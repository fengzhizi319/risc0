// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(test)]
mod tests;

use std::{array, cell::RefCell, collections::BTreeSet, io::Cursor, mem, rc::Rc};

use anyhow::{bail, ensure, Result};
use crypto_bigint::{CheckedMul as _, Encoding as _, NonZero, U256, U512};
use num_bigint::BigUint;
use risc0_binfmt::{ExitCode, MemoryImage, Program, SystemState};
use risc0_zkp::{
    core::{
        digest::{Digest, DIGEST_BYTES, DIGEST_WORDS},
        hash::sha::{BLOCK_BYTES, BLOCK_WORDS},
        log2_ceil,
    },
    MAX_CYCLES_PO2, MIN_CYCLES_PO2, ZK_CYCLES,
};
use risc0_zkvm_platform::{
    align_up,
    memory::{is_guest_memory, GUEST_MAX_MEM},
    syscall::{bigint, ecall, halt, reg_abi::*, IO_CHUNK_WORDS},
    PAGE_SIZE, WORD_SIZE,
};
use sha2::digest::generic_array::GenericArray;

use super::{
    addr::{ByteAddr, WordAddr},
    bibc,
    pager::PagedMemory,
    rv32im::{DecodedInstruction, EmuContext, Emulator, Instruction, TrapCause},
    BIGINT2_WIDTH_BYTES, BIGINT_CYCLES, SYSTEM_START,
};
use crate::{
    prove::{
        emu::sha_cycles,
        engine::loader::{FINI_CYCLES, INIT_CYCLES},
        segment::{Segment, SyscallRecord},
    },
    trace::{TraceCallback, TraceEvent},
};

pub const DEFAULT_SEGMENT_LIMIT_PO2: usize = 20;

/// A host-side implementation of a system call.
pub trait Syscall {
    /// Invokes the system call.
    fn syscall(
        &self,
        syscall: &str,
        ctx: &mut dyn SyscallContext,
        into_guest: &mut [u32],
    ) -> Result<(u32, u32)>;
}

/// Access to memory and machine state for syscalls.
pub trait SyscallContext {
    /// Loads the value of the given register, e.g. REG_A0.
    fn peek_register(&mut self, idx: usize) -> Result<u32>;

    /// Loads an individual word from memory.
    fn peek_u32(&mut self, addr: ByteAddr) -> Result<u32>;

    /// Loads an individual byte from memory.
    fn peek_u8(&mut self, addr: ByteAddr) -> Result<u8>;

    /// Loads bytes from the given region of memory.
    ///
    /// A region may span multiple pages.
    fn peek_region(&mut self, addr: ByteAddr, size: u32) -> Result<Vec<u8>> {
        let mut region = Vec::new();
        for i in 0..size {
            region.push(self.peek_u8(addr + i)?);
        }
        Ok(region)
    }

    /// Load a page from memory at the specified page index.
    ///
    /// This is used by sys_fork in order to build a copy-on-write page cache to
    /// inherit pages from the parent process.
    fn peek_page(&mut self, page_idx: u32) -> Result<Vec<u8>>;

    /// Returns the current cycle count.
    fn get_cycle(&self) -> u64;

    /// Returns the current program counter.
    fn get_pc(&self) -> u32;
}

pub struct ExecutorResult {
    pub segments: usize,
    pub exit_code: ExitCode,
    pub post_image: MemoryImage,
    pub user_cycles: u64,
    pub paging_cycles: u64,
    pub reserved_cycles: u64,
    pub total_cycles: u64,
    pub pre_state: SystemState,
    pub post_state: SystemState,
    pub output_digest: Option<Digest>,
}

#[derive(Default)]
struct SessionCycles {
    user: usize,
    paging: usize,
    reserved: usize,
    total: usize,
}

pub struct SimpleSession {
    pub segments: Vec<Segment>,
    pub result: ExecutorResult,
}

#[derive(Debug)]
/// 挂起状态结构体
/// Pending state struct
struct PendingState {
    /// 程序计数器
    /// Program counter
    pc: ByteAddr,
    /// 指令
    /// Instruction
    insn: u32,
    /// 周期计数
    /// Cycle count
    cycles: usize,
    /// 系统调用记录
    /// Syscall record
    syscall: Option<SyscallRecord>,
    /// 输出摘要
    /// Output digest
    output_digest: Option<Digest>,
    /// 退出代码
    /// Exit code
    exit_code: Option<ExitCode>,
    /// 事件集合
    /// Event set
    events: BTreeSet<TraceEvent>,
}
/*

 */
/// 执行器结构体
/// new ：创建一个新的 Executor 实例。
///run  ：运行执行器，执行指令并处理系统调用。
/// advance： 推进执行状态进执行状态，提交当前挂起状态并更新程序计数器。
/// reset  ：重置执行器状态到初始状态。
/// ecall_halt  ：处理 HALT 系统调用，终止或暂停执行。
/// ecall_input  ：处理 INPUT 系统调用，从输入摘要中加载一个字。
/// ecall_software  ：处理 SOFTWARE 系统调用，执行软件定义的系统调用。
/// ecall_sha  ：处理 SHA 系统调用，执行 SHA-256 哈希运算。
/// ecall_bigint  ：处理 BIGINT 系统调用，执行模乘运算。
/// ecall_bigint2：处理 BIGINT2 系统调用，执行大整数运算。
/// Executor struct
pub struct Executor<'a, 'b, S: Syscall> {
    /// 当前程序计数器
    /// Current program counter
    pc: ByteAddr,
    /// 指令周期计数
    /// Instruction cycle count
    insn_cycles: usize,
    /*
    寄存器的值保存在 PagedMemory 结构中。具体来说，寄存器的值通过 SYSTEM_START 偏移量存储在 PagedMemory 的内存中。
    load_register 和 store_register 方法用于从 PagedMemory 中加载和存储寄存器的值。
     */
    /// Paged memory manager
    pager: PagedMemory,
    /// 退出代码
    /// Exit code
    exit_code: Option<ExitCode>,
    /// 系统调用记录
    /// Syscall records
    syscalls: Vec<SyscallRecord>,
    /// 系统调用处理器
    /// Syscall handler
    syscall_handler: &'a S,
    /// 输入摘要
    /// Input digest
    input_digest: Digest,
    /// 输出摘要
    /// Output digest
    output_digest: Option<Digest>,
    /// 挂起状态
    /// Pending state
    pending: PendingState,
    /// 跟踪回调列表
    /// Trace callback list
    trace: Vec<Rc<RefCell<dyn TraceCallback + 'b>>>,
    /// 会话周期计数
    /// Session cycle count
    cycles: SessionCycles,
}

impl PendingState {
    fn reset(&mut self, pc: ByteAddr) {
        self.pc = pc;
        self.cycles = 0;
        self.syscall = None;
        self.output_digest = None;
        self.exit_code = None;
    }
}

impl<'a, 'b, S: Syscall> Executor<'a, 'b, S> {
    /// 创建一个新的执行器实例
    /// Creates a new executor instance
    pub fn new(
        image: MemoryImage, // 内存镜像
        syscall_handler: &'a S, // 系统调用处理器
        input_digest: Option<Digest>, // 输入摘要
        trace: Vec<Rc<RefCell<dyn TraceCallback + 'b>>>, // 跟踪回调列表
    ) -> Self {
        // 获取程序计数器
        // Get the program counter
        let pc = ByteAddr(image.pc);
        Self {
            pc, // 当前程序计数器
            insn_cycles: 0, // 指令周期计数
            pager: PagedMemory::new(image), // 分页内存管理器
            exit_code: None, // 退出代码
            syscalls: Vec::new(), // 系统调用记录
            syscall_handler, // 系统调用处理器
            input_digest: input_digest.unwrap_or_default(), // 输入摘要
            output_digest: None, // 输出摘要
            pending: PendingState { // 挂起状态
                pc, // 程序计数器
                insn: 0, // 指令
                cycles: 0, // 周期计数
                syscall: None, // 系统调用记录
                output_digest: None, // 输出摘要
                exit_code: None, // 退出代码
                events: BTreeSet::new(), // 事件集合
            },
            trace, // 跟踪回调列表
            cycles: SessionCycles::default(), // 会话周期计数
        }
    }

    pub fn run<F: FnMut(Segment) -> Result<()>>(
        &mut self,
        segment_po2: usize,
        max_cycles: Option<u64>,
        mut callback: F,
    ) -> Result<ExecutorResult> {
        // At least one HaltCycle needs to appear in the body
        // 在执行过程中至少需要一个 HaltCycle
        /*
        HaltCycle 是指在程序执行过程中，执行器（Executor）遇到 HALT 指令时所消耗的周期。
        HALT 指令通常用于终止或暂停程序的执行，因此 HaltCycle 代表了执行 HALT 指令所需的时间周期。
        在执行过程中，至少需要一个 HaltCycle 来确保程序能够正确处理 HALT 指令并完成相应的操作。
        MIN_HALT_CYCLES 的作用是在程序执行过程中，确保至少有一个 HaltCycle 被执行。
        HaltCycle 是指执行器（Executor）遇到 HALT 指令时所消耗的周期。HALT 指令通常用于终止
        或暂停程序的执行，因此 HaltCycle 代表了执行 HALT 指令所需的时间周期。通过设置 MIN_HALT_CYCLES，
        可以确保程序能够正确处理 HALT 指令并完成相应的操作。
         */
        const MIN_HALT_CYCLES: usize = 1;
        // A final "is_done" PageFault cycle is required when a split occurs
        // 当发生分段时，需要一个最终的 "is_done" PageFault 周期
        /*
        PAGE_FINI_CYCLES 的作用是在程序执行过程中，当发生分段时，确保至少有一个 "is_done" PageFault 周期被执行。
        这个周期用于处理分页操作的结束状态，确保分页操作能够正确完成并提交当前状态。
        通过设置 PAGE_FINI_CYCLES，可以确保在分段时正确处理分页操作的结束状态。
         */
        const PAGE_FINI_CYCLES: usize = 1;
        // Leave room for reserved cycles
        // 为保留周期留出空间
        /*
        RESERVED_CYCLES 的作用是在程序执行过程中，为特定的保留周期留出空间。这些保留周期包括初始化周期 (INIT_CYCLES)、
        最小 HALT 周期 (MIN_HALT_CYCLES)、分页结束周期 (PAGE_FINI_CYCLES)、结束周期 (FINI_CYCLES)
        和零知识证明周期 (ZK_CYCLES)。通过设置 RESERVED_CYCLES，可以确保在执行过程中为这些关键操作预留足够的周期，
        以保证程序的正确执行和状态提交。
         */
        const RESERVED_CYCLES: usize =
            INIT_CYCLES + MIN_HALT_CYCLES + PAGE_FINI_CYCLES + FINI_CYCLES + ZK_CYCLES;
        // Calculate the segment limit by subtracting reserved cycles from the total cycles
        // 通过从总周期中减去保留周期来计算段限制
        let segment_limit = (1 << segment_po2) - RESERVED_CYCLES;//1044982

        // Reset the executor state
        // 重置执行器状态
        self.reset();

        // Create a new emulator instance
        // 创建一个新的模拟器实例
        let mut emu = Emulator::new();
        // Initialize the segment counter
        // 初始化段计数器
        let mut segments = 0;
        // Get the initial system state from the memory image
        // 从内存镜像获取初始系统状态，它保存了程序计数器和 Merkle 根等关键信息。
        let initial_state = self.pager.image.get_system_state();

        // Main execution loop
        // 主执行循环
        loop {
            // Break the loop if an exit code is set
            // 如果设置了退出代码，则跳出循环
            if self.exit_code.is_some() {
                break;
            }

            // Check if the user cycle limit is exceeded
            // 检查用户周期限制是否超出
            if let Some(max_cycles) = max_cycles {
                if self.cycles.user >= max_cycles as usize {
                    bail!("Session limit exceeded");
                }
            }

            // Execute a single step in the emulator
            // 在模拟器中执行单步操作，会更新pc指针等内部状态到pending中，advance运算会从pending中取出状态更新到当前状态
            emu.step(self)?;

            // Calculate the total cycles used in the current segment
            // 计算当前段使用的总周期数
            let segment_cycles = self.insn_cycles + self.pager.cycles + self.pending.cycles;
            if segment_cycles < segment_limit {
                // Advance to the next instruction if within the segment limit
                // 如果在段限制内，则推进到下一条指令
                self.advance()?;
            } else if self.insn_cycles == 0 {
                /*
                self.insn_cycles == 0 表示当前指令周期计数为零。这意味着在当前段中还没有执行任何指令。
                如果在这种情况下段限制太小，程序会抛出错误，因为即使是执行一条指令所需的周期数也超过了段限制。
                 */
                // Bail if the segment limit is too small for the current instruction
                // 如果段限制对于当前指令来说太小，则抛出错误
                bail!(
                "segment limit ({segment_limit}) too small for instruction at pc: {:?}",
                self.pc
                );
            } else {
                // Undo the last pager operation and split the segment
                // 撤销最后的分页操作并分割段
                self.pager.undo();

                // Calculate the total cycles used in the current segment, including reserved cycles
                // 计算当前段使用的总周期数，包括保留周期
                let used_cycles = self.insn_cycles + self.pager.cycles + RESERVED_CYCLES;

                // Calculate the padding needed to reach the next power of two boundary for the segment
                // 计算达到段的下一个二次幂边界所需的填充
                let po2_padding = (1 << segment_po2) - used_cycles;

                // Log the split operation details for debugging purposes
                // 记录分割操作的详细信息以进行调试
                tracing::debug!(
                "split: {} + {} + {RESERVED_CYCLES} = {used_cycles}, padding: {po2_padding}, pending: {:?}",
                self.insn_cycles,
                self.pager.cycles,
                self.pending
                );

                // Commit the current state and create a new segment
                // 提交当前状态并创建新段
                let (pre_state, partial_image, post_state) = self.pager.commit(self.pc);

                // Create a new segment with the committed state and other relevant data
                // 使用提交的状态和其他相关数据创建一个新段
                callback(Segment {
                    partial_image, // The partial memory image of the segment 段的部分内存镜像
                    pre_state, // The system state before the segment execution 段执行前的系统状态
                    post_state, // The system state after the segment execution 段执行后的系统状态
                    syscalls: mem::take(&mut self.syscalls), // The list of syscalls made during the segment 段期间进行的系统调用列表
                    insn_cycles: self.insn_cycles, // The number of instruction cycles used in the segment 段中使用的指令周期数
                    po2: segment_po2, // The power of two for the segment size 段大小的二次幂
                    exit_code: ExitCode::SystemSplit, // The exit code indicating the segment was split 表示段被分割的退出代码
                    index: segments, // The index of the segment 段的索引
                    input_digest: self.input_digest, // The input digest for the segment 段的输入摘要
                    output_digest: self.output_digest, // The output digest for the segment 段的输出摘要
                })?;

                // Increment the segment counter
                // 增加段计数器
                segments += 1;

                // Update the total cycles used with the segment size
                // 使用段大小更新使用的总周期数
                self.cycles.total += 1 << segment_po2;

                // Update the paging cycles with the cycles used by the pager
                // 使用分页器使用的周期更新分页周期
                self.cycles.paging += self.pager.cycles;

                // Update the reserved cycles with the padding and reserved cycles
                // 使用填充和保留周期更新保留周期
                self.cycles.reserved += po2_padding + RESERVED_CYCLES;

                // Clear the pager state for the next segment
                // 清除下一个段的分页器状态
                self.pager.clear();

                // Reset the instruction cycles counter
                // 重置指令周期计数器
                self.insn_cycles = 0;

                // Replay the current instruction in a new segment
                // 在新段中重放当前指令
                self.pending.pc = self.pc; // Set the program counter to the current instruction 将程序计数器设置为当前指令
                self.pending.cycles = 0; // Reset the pending cycles counter 重置挂起的周期计数器
            }
        }

        // Commit the final state and create the last segment
        // 提交最终状态并创建最后一个段
        let (pre_state, partial_image, post_state) = self.pager.commit(self.pc);

        // Calculate the total cycles used in the current segment, including reserved cycles
        // 计算当前段使用的总周期数，包括保留周期
        let segment_cycles = self.insn_cycles + self.pager.cycles + RESERVED_CYCLES;

        // Determine the power of two that is greater than or equal to the segment cycles
        // 确定大于或等于段周期数的二次幂
        let po2 = log2_ceil(segment_cycles.next_power_of_two());

        // Calculate the padding needed to reach the next power of two boundary
        // 计算达到下一个二次幂边界所需的填充
        let po2_padding = (1 << po2) - segment_cycles;

        // Retrieve the exit code, which should be set at this point
        // 获取退出代码，此时应已设置
        let exit_code = self.exit_code.unwrap();

        // Create a new segment with the committed state and other relevant data
        // 使用提交的状态和其他相关数据创建一个新段
        callback(Segment {
            partial_image, // The partial memory image of the segment 段的部分内存镜像
            pre_state: pre_state.clone(), // The system state before the segment execution 段执行前的系统状态
            post_state: post_state.clone(), // The system state after the segment execution 段执行后的系统状态
            syscalls: mem::take(&mut self.syscalls), // The list of syscalls made during the segment 段期间进行的系统调用列表
            insn_cycles: self.insn_cycles, // The number of instruction cycles used in the segment 段中使用的指令周期数
            po2, // The power of two for the segment size 段大小的二次幂
            exit_code, // The exit code indicating the reason for segment termination 表示段终止原因的退出代码
            index: segments, // The index of the segment 段的索引
            input_digest: self.input_digest, // The input digest for the segment 段的输入摘要
            output_digest: self.output_digest, // The output digest for the segment 段的输出摘要
        })?;

        // Increment the segment counter
        // 增加段计数器
        segments += 1;

        // Update the total cycles used with the segment size
        // 使用段大小更新使用的总周期数
        self.cycles.total += 1 << po2;

        // Update the paging cycles with the cycles used by the pager
        // 使用分页器使用的周期更新分页周期
        self.cycles.paging += self.pager.cycles;

        // Update the reserved cycles with the padding and reserved cycles
        // 使用填充和保留周期更新保留周期
        self.cycles.reserved += po2_padding + RESERVED_CYCLES;

        // When a segment ends in a Halted(_) state, the post_state will be null
        // 当段以 Halted(_) 状态结束时，post_state 将为空
        let post_state = match exit_code {
            ExitCode::Halted(_) => SystemState {
                pc: 0, // Set the program counter to 0 将程序计数器设置为 0
                merkle_root: Digest::ZERO, // Set the Merkle root to zero 将 Merkle 根设置为零
            },
            _ => post_state, // Otherwise, use the existing post_state 否则，使用现有的 post_state
        };

        // Return the execution result
        // 返回执行结果
        Ok(ExecutorResult {
            segments, // The total number of segments 段的总数
            exit_code, // The exit code of the execution 执行的退出代码
            post_image: self.pager.image.clone(), // The final memory image after execution 执行后的最终内存镜像
            user_cycles: self.cycles.user.try_into()?, // The number of user cycles used 使用的用户周期数
            paging_cycles: self.cycles.paging.try_into()?, // The number of paging cycles used 使用的分页周期数
            reserved_cycles: self.cycles.reserved.try_into()?, // The number of reserved cycles used 使用的保留周期数
            total_cycles: self.cycles.total.try_into()?, // The total number of cycles used 使用的总周期数
            pre_state: initial_state, // The initial system state before execution 执行前的初始系统状态
            post_state, // The final system state after execution 执行后的最终系统状态
            output_digest: self.output_digest, // The output digest of the execution 执行的输出摘要
        })
    }


    /// 提交当前挂起状态并更新程序计数器，以推进执行状态。
    /// Advances the execution state by committing the current pending state and updating the program counter.
    fn advance(&mut self) -> Result<()> {
        // Iterate over all trace callbacks and notify them of the instruction start event.
        // 遍历所有跟踪回调，并通知它们指令开始事件。
        for trace in &self.trace {
            trace
                .borrow_mut()
                .trace_callback(TraceEvent::InstructionStart {
                    cycle: self.cycles.user.try_into()?, // Current user cycle count 当前用户周期计数
                    pc: self.pc.0, // Current program counter 当前程序计数器
                    insn: self.pending.insn, // Current instruction 当前指令
                })?;

            // Notify trace callbacks of all pending events.
            // 通知跟踪回调所有挂起的事件。
            for event in &self.pending.events {
                trace.borrow_mut().trace_callback(event.clone()).unwrap();
            }
        }

        // Update the program counter to the pending program counter.
        // 将程序计数器更新为挂起的程序计数器。
        self.pc = self.pending.pc;
        // Add the pending cycles to the instruction cycles.
        // 将挂起的周期添加到指令周期中。
        self.insn_cycles += self.pending.cycles;
        // Add the pending cycles to the user cycles.
        // 将挂起的周期添加到用户周期中。
        self.cycles.user += self.pending.cycles;
        // Reset the pending cycles to zero.
        // 将挂起的周期重置为零。
        self.pending.cycles = 0;
        // Clear all pending events.
        // 清除所有挂起的事件。
        self.pending.events.clear();
        // If there is a pending syscall, push it to the syscalls vector.
        // 如果有挂起的系统调用，将其推送到系统调用向量中。
        if let Some(syscall) = self.pending.syscall.take() {
            self.syscalls.push(syscall);
        }
        // Take the pending output digest and set it as the current output digest.
        // 获取挂起的输出摘要并将其设置为当前输出摘要。
        self.output_digest = self.pending.output_digest.take();
        // Take the pending exit code and set it as the current exit code.
        // 获取挂起的退出代码并将其设置为当前退出代码。
        self.exit_code = self.pending.exit_code.take();
        // Commit the current step in the pager.
        // 提交分页器中的当前步骤。
        self.pager.commit_step();

        Ok(())
    }

    // Resets the executor state to its initial state.
    fn reset(&mut self) {
        // Clear the pager state.
        self.pager.clear();
        // Reset the exit code to None.
        self.exit_code = None;
        // Clear the syscalls vector.
        self.syscalls.clear();
        // Reset the output digest to None.
        self.output_digest = None;
        // Reset the pending state with the current program counter.
        self.pending.reset(self.pc);
        // Reset the user cycles to zero.
        self.cycles.user = 0;
        // Reset the total cycles to zero.
        self.cycles.total = 0;
    }
}

impl<'a, 'b, S: Syscall> Executor<'a, 'b, S> {
    // Handle the HALT ecall, which terminates or pauses the execution.
    fn ecall_halt(&mut self) -> Result<bool> {
        // Load the value of register A0, which contains the halt type and user exit code.
        let a0 = self.load_register(REG_A0)?;
        // Load the address of the output digest from register A1.
        let output_ptr = self.load_guest_addr_from_register(REG_A1)?;
        // Load the output digest from the guest memory.
        let output: [u8; DIGEST_BYTES] = self.load_array_from_guest(output_ptr)?;

        // Extract the halt type and user exit code from the value of register A0.
        let halt_type = a0 & 0xff;
        let user_exit = (a0 >> 8) & 0xff;

        // Log the halt type and user exit code for debugging purposes.
        tracing::debug!("ecall_halt({halt_type}, {user_exit})");

        // Set the pending exit code based on the halt type.
        self.pending.exit_code = match halt_type {
            halt::TERMINATE => Some(ExitCode::Halted(user_exit)), // Terminate the execution.
            halt::PAUSE => Some(ExitCode::Paused(user_exit)), // Pause the execution.
            _ => bail!("Illegal halt type: {halt_type}"), // Invalid halt type.
        };
        // Set the pending output digest.
        self.pending.output_digest = Some(output.into());
        // Advance the program counter to the next instruction.
        self.pending.pc = self.pc + WORD_SIZE;

        Ok(true)
    }

    // Handle the INPUT ecall, which loads a word from the input digest.
    fn ecall_input(&mut self) -> Result<bool> {
        // Log the current instruction cycle for debugging purposes.
        tracing::debug!("[{}] ecall_input", self.insn_cycles);
        // Load the value of register A0, which contains the index of the word to load.
        let a0 = self.load_register(REG_A0)? as usize;
        // Ensure the index is within the valid range.
        ensure!(a0 < DIGEST_WORDS, "sys_input index out of range");
        // Load the word from the input digest at the specified index.
        let word = self.input_digest.as_words()[a0];
        // Store the loaded word into register A0.
        self.store_register(REG_A0, word)?;

        // Increment the pending cycles by 1.
        self.pending.cycles += 1;
        // Advance the program counter to the next instruction.
        self.pending.pc = self.pc + WORD_SIZE;

        Ok(true)
    }

    // Handle the SOFTWARE ecall, which performs a software-defined system call.
    fn ecall_software(&mut self) -> Result<bool> {
        // Log the current instruction cycle for debugging purposes.
        tracing::debug!("[{}] ecall_software", self.insn_cycles);
        // Load the address of the guest memory region to store the result from register A0.
        let into_guest_ptr = ByteAddr(self.load_register(REG_A0)?);
        // Load the length of the guest memory region from register A1.
        let into_guest_len = self.load_register(REG_A1)? as usize;
        // Ensure the guest memory address is valid if the length is greater than 0.
        if into_guest_len > 0 && !is_guest_memory(into_guest_ptr.0) {
            bail!("{into_guest_ptr:?} is an invalid guest address");
        }
        // Load the address of the syscall name string from register A2.
        let name_ptr = self.load_guest_addr_from_register(REG_A2)?;
        // Load the syscall name string from the guest memory.
        let syscall_name = self.peek_string(name_ptr)?;
        // Calculate the end address of the syscall name string.
        let name_end = name_ptr + syscall_name.len();
        // Ensure the end address of the syscall name string is valid.
        Self::check_guest_addr(name_end)?;
        // Log the syscall name and guest memory length for debugging purposes.
        tracing::trace!("ecall_software({syscall_name}, into_guest: {into_guest_len})");

        // Calculate the number of chunks needed to transfer the result to the guest memory.
        let chunks = align_up(into_guest_len, IO_CHUNK_WORDS) / IO_CHUNK_WORDS;

        // Check if the syscall has been previously recorded.
        let syscall = if let Some(syscall) = &self.pending.syscall {
            // Log the replayed syscall for debugging purposes.
            tracing::debug!("Replay syscall: {syscall:?}");
            syscall.clone()
        } else {
            // Create a buffer to store the result to be transferred to the guest memory.
            let mut to_guest = vec![0u32; into_guest_len];

            // Perform the syscall using the syscall handler.
            let (a0, a1) = self
                .syscall_handler
                .syscall(&syscall_name, self, &mut to_guest)?;

            // Record the syscall result.
            let syscall = SyscallRecord {
                to_guest,
                regs: (a0, a1),
            };
            // Store the recorded syscall in the pending state.
            self.pending.syscall = Some(syscall.clone());
            syscall
        };

        // Transfer the result to the guest memory if the length is greater than 0 and the address is not null.
        if into_guest_len > 0 && !into_guest_ptr.is_null() {
            Self::check_guest_addr(into_guest_ptr + into_guest_len)?;
            self.store_region(into_guest_ptr, bytemuck::cast_slice(&syscall.to_guest))?
        }

        // Store the syscall result registers into registers A0 and A1.
        let (a0, a1) = syscall.regs;
        self.store_register(REG_A0, a0)?;
        self.store_register(REG_A1, a1)?;

        // Log the syscall result for debugging purposes.
        tracing::trace!("{syscall:08x?}");

        // Increment the pending cycles by the number of chunks plus 1.
        self.pending.cycles += chunks + 1; // syscallBody + syscallFini
        // Advance the program counter to the next instruction.
        self.pending.pc = self.pc + WORD_SIZE;

        Ok(true)
    }

    // Handle the SHA ecall, which performs SHA-256 hashing.
    fn ecall_sha(&mut self) -> Result<bool> {
        // Log the current instruction cycle for debugging purposes.
        tracing::debug!("[{}] ecall_sha", self.insn_cycles);

        // Load the address of the output state from register A0.
        let state_out_ptr = self.load_guest_addr_from_register(REG_A0)?;
        // Load the address of the input state from register A1.
        let state_in_ptr = self.load_guest_addr_from_register(REG_A1)?;
        // Load the number of blocks to process from register A4.
        let count = self.load_register(REG_A4)?;

        // Load the input state from the guest memory.
        let state_in: [u8; DIGEST_BYTES] = self.load_array_from_guest(state_in_ptr)?;
        // Convert the input state to big-endian format.
        let mut state: [u32; DIGEST_WORDS] = bytemuck::cast_slice(&state_in).try_into().unwrap();
        for word in &mut state {
            *word = word.to_be();
        }

        // If there are blocks to process, load and hash them.
        if count > 0 {
            // Load the addresses of the first and second blocks from registers A2 and A3.
            let mut block1_ptr = self.load_guest_addr_from_register(REG_A2)?;
            let mut block2_ptr = self.load_guest_addr_from_register(REG_A3)?;

            // Initialize a buffer to store the blocks.
            let mut block = [0u32; BLOCK_WORDS];

            // Process each block.
            for _ in 0..count {
                // Split the buffer into two parts for the two blocks.
                let (digest1, digest2) = block.split_at_mut(DIGEST_WORDS);
                // Load the first block from the guest memory.
                for (i, word) in digest1.iter_mut().enumerate() {
                    *word = self.load_u32_from_guest(block1_ptr + (i * WORD_SIZE))?;
                }
                // Load the second block from the guest memory.
                for (i, word) in digest2.iter_mut().enumerate() {
                    *word = self.load_u32_from_guest(block2_ptr + (i * WORD_SIZE))?;
                }
                // Compress the blocks using SHA-256.
                sha2::compress256(
                    &mut state,
                    &[*GenericArray::from_slice(bytemuck::cast_slice(&block))],
                );

                // Advance the block pointers to the next blocks.
                block1_ptr += BLOCK_BYTES;
                block2_ptr += BLOCK_BYTES;
            }
        }

        // Convert the final state back to little-endian format.
        for word in &mut state {
            *word = u32::from_be(*word);
        }

        // Store the final state into the guest memory.
        self.store_region_into_guest(state_out_ptr, bytemuck::cast_slice(&state))?;

        // Increment the pending cycles by the number of SHA cycles.
        self.pending.cycles += sha_cycles(count as usize);
        // Advance the program counter to the next instruction.
        self.pending.pc = self.pc + WORD_SIZE;

        Ok(true)
    }

    // Handle the BIGINT ecall, which performs modular multiplication.
    fn ecall_bigint(&mut self) -> Result<bool> {
        // Load the operation code from register A1.
        let op = self.load_register(REG_A1)?;
        // Load the addresses of the result, operand X, operand Y, and modulus N from registers A0, A2, A3, and A4.
        let z_ptr = self.load_guest_addr_from_register(REG_A0)?;
        let x_ptr = self.load_guest_addr_from_register(REG_A2)?;
        let y_ptr = self.load_guest_addr_from_register(REG_A3)?;
        let n_ptr = self.load_guest_addr_from_register(REG_A4)?;

        // Helper function to load a bigint from the guest memory.
        let mut load_bigint_le_bytes = |ptr: ByteAddr| -> Result<[u8; bigint::WIDTH_BYTES]> {
            let mut arr = [0u32; bigint::WIDTH_WORDS];
            for (i, word) in arr.iter_mut().enumerate() {
                *word = self
                    .load_u32_from_guest(ptr + (i * WORD_SIZE) as u32)?
                    .to_le();
            }
            Ok(bytemuck::cast(arr))
        };

        // Ensure the operation code is 0.
        if op != 0 {
            bail!("ecall_bigint: op must be set to 0");
        }

        // Load the operands and modulus from the guest memory.
        let x = U256::from_le_bytes(load_bigint_le_bytes(x_ptr)?);
        let y = U256::from_le_bytes(load_bigint_le_bytes(y_ptr)?);
        let n = U256::from_le_bytes(load_bigint_le_bytes(n_ptr)?);

        // Compute the result of the modular multiplication.
        let z: U256 = if n == U256::ZERO {
            x.checked_mul(&y).unwrap()
        } else {
            let (w_lo, w_hi) = x.mul_wide(&y);
            let w = w_hi.concat(&w_lo);
            let z = w.rem(&NonZero::<U512>::from_uint(n.resize()));
            z.resize()
        };

        // Store the result into the guest memory.
        for (i, word) in bytemuck::cast::<_, [u32; bigint::WIDTH_WORDS]>(z.to_le_bytes())
            .into_iter()
            .enumerate()
        {
            self.store_u32_into_guest(z_ptr + (i * WORD_SIZE) as u32, word.to_le())?;
        }

        // Increment the pending cycles by the number of BIGINT cycles.
        self.pending.cycles += BIGINT_CYCLES;
        // Advance the program counter to the next instruction.
        self.pending.pc = self.pc + WORD_SIZE;

        Ok(true)
    }

    // Handle the BIGINT2 ecall, which performs operations on large integers.
    fn ecall_bigint2(&mut self) -> Result<bool> {
        // Load the addresses of the blob, nondeterministic program, verification program, and constants from registers A0, T1, T2, and T3.
        let blob_ptr = self.load_guest_addr_from_register(REG_A0)?.waddr();
        let nondet_program_ptr = self.load_guest_addr_from_register(REG_T1)?;
        let verify_program_ptr = self.load_guest_addr_from_register(REG_T2)?;
        let consts_ptr = self.load_guest_addr_from_register(REG_T3)?;

        // Load the sizes of the nondeterministic program, verification program, and constants from the blob.
        let nondet_program_size = self.load_u32_from_guest(blob_ptr.baddr())?;
        let verify_program_size = self.load_u32_from_guest((blob_ptr + 1u32).baddr())?;
        let consts_size = self.load_u32_from_guest((blob_ptr + 2u32).baddr())?;

        // Load the nondeterministic program from the guest memory.
        let program_bytes = self
            .load_region_from_guest(nondet_program_ptr, nondet_program_size * WORD_SIZE as u32)?;
        let mut cursor = Cursor::new(program_bytes);
        let program = bibc::Program::decode(&mut cursor)?;
        // Evaluate the nondeterministic program.
        program.eval(self)?;

        // Load the verification program and constants from the guest memory.
        self.load_region_from_guest(verify_program_ptr, verify_program_size * WORD_SIZE as u32)?;
        self.load_region_from_guest(consts_ptr, consts_size * WORD_SIZE as u32)?;

        // Calculate the number of cycles needed for the verification program.
        let cycles = verify_program_size as usize + 1;
        tracing::info!("bigint2: {cycles} cycles");

        // Increment the pending cycles by the number of cycles needed.
        self.pending.cycles += cycles;
        // Advance the program counter to the next instruction.
        self.pending.pc = self.pc + WORD_SIZE;

        Ok(true)
    }

    /// Check if the given address is a valid guest address.
    fn check_guest_addr(addr: ByteAddr) -> Result<ByteAddr> {
        if !is_guest_memory(addr.0) {
            bail!("{addr:?} is an invalid guest address");
        }
        Ok(addr)
    }

    /// Load a guest address from the specified register.
    fn load_guest_addr_from_register(&mut self, idx: usize) -> Result<ByteAddr> {
        // Load the value of the specified register and convert it to a ByteAddr.
        let addr = ByteAddr(self.load_register(idx)?);
        // Check if the loaded address is a valid guest address.
        Self::check_guest_addr(addr)
    }

    /// Load a 32-bit word from the guest memory.
    fn load_u32_from_guest(&mut self, addr: ByteAddr) -> Result<u32> {
        // Check if the address is a valid guest address.
        Self::check_guest_addr(addr)?;
        // Load the 32-bit word from the guest memory at the word-aligned address.
        self.load_memory(addr.waddr())
    }

    /// Load an array of bytes from the guest memory.
    fn load_array_from_guest<const N: usize>(&mut self, addr: ByteAddr) -> Result<[u8; N]> {
        // Check if the starting address is a valid guest address.
        Self::check_guest_addr(addr)?;
        // Check if the ending address is a valid guest address.
        Self::check_guest_addr(addr + N)?;
        // Load the array of bytes from the specified address.
        self.load_array(addr)
    }

    /// Load an array of bytes from the specified address.
    fn load_array<const N: usize>(&mut self, addr: ByteAddr) -> Result<[u8; N]> {
        // Initialize a vector to store the bytes.
        let mut bytes = Vec::new();
        // Iterate over the range and load each byte from the guest memory.
        for i in 0..N {
            bytes.push(self.load_u8(addr + i)?);
        }
        // Convert the vector to an array and return it.
        let ret = array::from_fn(|i| bytes[i]);
        Ok(ret)
    }

    /// Load a region of bytes from the guest memory.
    fn load_region_from_guest(&mut self, base: ByteAddr, size: u32) -> Result<Vec<u8>> {
        // Initialize a vector to store the bytes of the region.
        let mut region = Vec::new();
        // Iterate over the range and load each byte from the guest memory.
        for i in 0..size {
            let addr = base + i;
            // Check if the current address is a valid guest address.
            Self::check_guest_addr(addr)?;
            region.push(self.load_u8(addr)?);
        }
        // Return the loaded region as a vector of bytes.
        Ok(region)
    }

    /// Load a byte from the guest memory.
    fn load_u8(&mut self, addr: ByteAddr) -> Result<u8> {
        // Load the 32-bit word from the guest memory at the word-aligned address.
        let word = self.pager.load(addr.waddr());
        // Convert the 32-bit word to an array of bytes in little-endian format.
        let bytes = word.to_le_bytes();
        // Calculate the byte offset within the 32-bit word.
        let byte_offset = addr.0 as usize % WORD_SIZE;
        // Return the byte at the calculated offset.
        Ok(bytes[byte_offset])
    }

    /// Peek a null-terminated string from the guest memory starting at the given address.
    fn peek_string(&mut self, mut addr: ByteAddr) -> Result<String> {
        // Initialize a buffer to store the bytes of the string.
        let mut buf = Vec::new();
        loop {
            // Load a byte from the guest memory at the current address.
            let bytes = self.peek_u8(addr)?;
            // Break the loop if the byte is null (end of string).
            if bytes == 0 {
                break;
            }
            // Push the byte to the buffer.
            buf.push(bytes);
            // Increment the address to the next byte.
            addr += 1u32;
        }
        // Convert the buffer to a UTF-8 string and return it.
        Ok(String::from_utf8(buf)?)
    }

    /// Store a 32-bit word into the guest memory at the specified address.
    fn store_u32_into_guest(&mut self, addr: ByteAddr, data: u32) -> Result<()> {
        // Check if the address is a valid guest address.
        Self::check_guest_addr(addr)?;
        // Store the 32-bit word into the guest memory.
        self.store_memory(addr.waddr(), data)
    }

    /// Store a region of bytes into the guest memory starting at the specified address.
    fn store_region_into_guest(&mut self, addr: ByteAddr, slice: &[u8]) -> Result<()> {
        // Check if the starting address is a valid guest address.
        Self::check_guest_addr(addr)?;
        // Check if the ending address is a valid guest address.
        Self::check_guest_addr(addr + slice.len())?;
        // Store the region of bytes into the guest memory.
        self.store_region(addr, slice)
    }

    /// Store a single byte into the guest memory at the specified address.
    fn raw_store_u8(&mut self, addr: ByteAddr, byte: u8) -> Result<()> {
        // Calculate the byte offset within the 32-bit word.
        let byte_offset = addr.0 as usize % WORD_SIZE;
        // Load the 32-bit word from the guest memory at the address.
        let word = self.peek_u32(addr)?;
        // Convert the 32-bit word to an array of bytes.
        let mut bytes = word.to_le_bytes();
        // Set the byte at the calculated offset to the new byte value.
        bytes[byte_offset] = byte;
        // Convert the array of bytes back to a 32-bit word.
        let word = u32::from_le_bytes(bytes);
        // Store the modified 32-bit word back into the guest memory.
        self.raw_store_memory(addr.waddr(), word)
    }

    /// Store a region of bytes into the guest memory starting at the specified address.
    fn store_region(&mut self, addr: ByteAddr, slice: &[u8]) -> Result<()> {
        // If tracing is enabled, log the memory set event.
        if !self.trace.is_empty() {
            self.pending.events.insert(TraceEvent::MemorySet {
                addr: addr.0,
                region: slice.into(),
            });
        }

        // Iterate over the slice and store each byte into the guest memory.
        slice
            .iter()
            .enumerate()
            .try_for_each(|(i, x)| self.raw_store_u8(addr + i, *x))?;

        Ok(())
    }

    // /Store a 32-bit word into the guest memory at the specified word address.
    fn raw_store_memory(&mut self, addr: WordAddr, data: u32) -> Result<()> {
        // Store the 32-bit word into the guest memory.
        self.pager.store(addr, data)
    }
}

impl<'a, 'b, S: Syscall> bibc::BigIntIO for Executor<'a, 'b, S> {
    fn load(&mut self, arena: u32, offset: u32, count: u32) -> Result<BigUint> {
        tracing::debug!("load(arena: {arena}, offset: {offset}, count: {count})");
        let base = ByteAddr(self.load_register(arena as usize)?);
        let addr = base + offset * BIGINT2_WIDTH_BYTES as u32;
        let bytes = self.load_region_from_guest(addr, count)?;
        Ok(BigUint::from_bytes_le(&bytes))
    }

    fn store(&mut self, arena: u32, offset: u32, count: u32, value: &BigUint) -> Result<()> {
        tracing::debug!("store(arena: {arena}, offset: {offset}, count: {count}, value: {value})");
        let base = ByteAddr(self.load_register(arena as usize)?);
        let addr = base + offset * BIGINT2_WIDTH_BYTES as u32;
        let mut bytes = value.to_bytes_le();
        if bytes.len() < count as usize {
            bytes.resize(count as usize, 0);
        }
        ensure!(bytes.len() == count as usize);
        self.store_region_into_guest(addr, &bytes)
    }
}

impl<'a, 'b, S: Syscall> EmuContext for Executor<'a, 'b, S> {
    fn ecall(&mut self) -> Result<bool> {
        match self.load_register(REG_T0)? {
            ecall::HALT => self.ecall_halt(),
            ecall::INPUT => self.ecall_input(),
            ecall::SOFTWARE => self.ecall_software(),
            ecall::SHA => self.ecall_sha(),
            ecall::BIGINT => self.ecall_bigint(),
            ecall::BIGINT2 => self.ecall_bigint2(),
            ecall => bail!("Unknown ecall {ecall:?}"),
        }
    }

    fn mret(&self) -> Result<bool> {
        unimplemented!()
    }

    fn trap(&self, cause: TrapCause) -> Result<bool> {
        let msg = format!("Trap: {cause:08x?}, pc: {:?}", self.pc);
        tracing::info!("{msg}");
        bail!("{msg}");
    }

    fn check_data_load(&self, addr: ByteAddr) -> bool {
        is_guest_memory(addr.0)
    }

    fn check_data_store(&self, addr: ByteAddr) -> bool {
        is_guest_memory(addr.0)
    }

    fn check_insn_load(&self, addr: ByteAddr) -> bool {
        is_guest_memory(addr.0)
    }

    fn on_insn_decoded(&self, insn: &Instruction, _decoded: &DecodedInstruction) {
        tracing::trace!("{:?}> {:?}", self.pc, insn.kind);
    }

    fn on_normal_end(&mut self, insn: &Instruction, decoded: &DecodedInstruction) {
        self.pending.insn = decoded.insn;
        self.pending.cycles += insn.cycles;
    }

    fn get_pc(&self) -> ByteAddr {
        self.pending.pc
    }

    fn set_pc(&mut self, pc: ByteAddr) {
        self.pending.pc = pc;
    }

    fn load_register(&mut self, idx: usize) -> Result<u32> {
        // tracing::trace!("load_reg: x{idx}");
        Ok(self.pager.load(SYSTEM_START + idx))
    }

    fn store_register(&mut self, idx: usize, data: u32) -> Result<()> {
        if idx != 0 {
            // tracing::trace!("store_reg: x{idx} <= 0x{data:08x}");
            self.pager.store(SYSTEM_START + idx, data)?;
            if !self.trace.is_empty() {
                self.pending
                    .events
                    .insert(TraceEvent::RegisterSet { idx, value: data });
            }
        }
        Ok(())
    }

    fn load_memory(&mut self, addr: WordAddr) -> Result<u32> {
        let data = self.pager.load(addr);
        // tracing::trace!("load_mem({:?}) -> 0x{data:08x}", addr.baddr());
        Ok(data)
    }

    fn store_memory(&mut self, addr: WordAddr, data: u32) -> Result<()> {
        // tracing::trace!("store_mem({:?}, 0x{data:08x})", addr.baddr());
        if !self.trace.is_empty() {
            self.pending.events.insert(TraceEvent::MemorySet {
                addr: addr.baddr().0,
                region: data.to_le_bytes().to_vec(),
            });
        }
        self.raw_store_memory(addr, data)
    }
}

impl<'a, 'b, S: Syscall> SyscallContext for Executor<'a, 'b, S> {
    fn get_cycle(&self) -> u64 {
        self.cycles.user as u64
    }

    fn peek_register(&mut self, idx: usize) -> Result<u32> {
        if idx >= REG_MAX {
            bail!("invalid register: x{idx}");
        }
        self.pager.peek(SYSTEM_START + idx)
    }

    fn peek_u32(&mut self, addr: ByteAddr) -> Result<u32> {
        let addr = Self::check_guest_addr(addr)?;
        self.pager.peek(addr.waddr())
    }

    fn peek_u8(&mut self, addr: ByteAddr) -> Result<u8> {
        let addr = Self::check_guest_addr(addr)?;
        let word = self.pager.peek(addr.waddr())?;
        let bytes = word.to_le_bytes();
        let byte_offset = addr.0 as usize % WORD_SIZE;
        Ok(bytes[byte_offset])
    }

    fn peek_page(&mut self, page_idx: u32) -> Result<Vec<u8>> {
        let addr = self.pager.image.info.get_page_addr(page_idx);
        if !is_guest_memory(addr) {
            bail!("{page_idx} is an invalid guest page_idx");
        }
        Ok(self.pager.peek_page(page_idx))
    }

    fn get_pc(&self) -> u32 {
        EmuContext::get_pc(self).0
    }
}

pub fn execute<S: Syscall>(
    image: MemoryImage,
    segment_limit_po2: usize,
    max_cycles: Option<u64>,
    syscall_handler: &S,
    input_digest: Option<Digest>,
) -> Result<SimpleSession> {
    if !(MIN_CYCLES_PO2..=MAX_CYCLES_PO2).contains(&segment_limit_po2) {
        bail!("Invalid segment_limit_po2: {segment_limit_po2}");
    }

    let mut segments = Vec::new();
    let trace = Vec::new();
    let result = Executor::new(image, syscall_handler, input_digest, trace).run(
        segment_limit_po2,
        max_cycles,
        |segment| {
            segments.push(segment);
            Ok(())
        },
    )?;

    Ok(SimpleSession { segments, result })
}

pub fn execute_elf<S: Syscall>(
    elf: &[u8],
    segment_po2: usize,
    max_cycles: Option<u64>,
    syscall_handler: &S,
    input_digest: Option<Digest>,
) -> Result<SimpleSession> {
    let program = Program::load_elf(elf, GUEST_MAX_MEM as u32)?;
    let image = MemoryImage::new(&program, PAGE_SIZE as u32)?;
    execute(
        image,
        segment_po2,
        max_cycles,
        syscall_handler,
        input_digest,
    )
}
