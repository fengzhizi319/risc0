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

use anyhow::Result;
use risc0_zkvm_platform::WORD_SIZE;

use super::addr::{ByteAddr, WordAddr};

pub trait EmuContext {
    /// 处理环境调用
    /// Handle environment call
    fn ecall(&mut self) -> Result<bool>;

    /// 处理机器返回
    /// Handle a machine return
    fn mret(&self) -> Result<bool>;

    /// 处理异常
    /// Handle a trap
    fn trap(&self, cause: TrapCause) -> Result<bool>;

    /// 指令解码后的回调
    /// Callback when instructions are decoded
    fn on_insn_decoded(&self, kind: &Instruction, decoded: &DecodedInstruction);

    /// 指令正常结束后的回调
    /// Callback when instructions end normally
    fn on_normal_end(&mut self, insn: &Instruction, decoded: &DecodedInstruction);

    /// 获取程序计数器
    /// Get the program counter
    fn get_pc(&self) -> ByteAddr;

    /// 设置程序计数器
    /// Set the program counter
    fn set_pc(&mut self, addr: ByteAddr);

    /// 从寄存器加载数据
    /// Load from a register
    fn load_register(&mut self, idx: usize) -> Result<u32>;

    /// 存储数据到寄存器
    /// Store to a register
    fn store_register(&mut self, idx: usize, data: u32) -> Result<()>;

    /// 从内存加载数据
    /// Load from memory
    fn load_memory(&mut self, addr: WordAddr) -> Result<u32>;

    /// 存储数据到内存
    /// Store to memory
    fn store_memory(&mut self, addr: WordAddr, data: u32) -> Result<()>;

    /// 检查指令加载的访问权限
    /// Check access for instruction load
    fn check_insn_load(&self, _addr: ByteAddr) -> bool {
        true
    }

    /// 检查数据加载的访问权限
    /// Check access for data load
    fn check_data_load(&self, _addr: ByteAddr) -> bool {
        true
    }

    /// 检查数据存储的访问权限
    /// Check access for data store
    fn check_data_store(&self, _addr: ByteAddr) -> bool {
        true
    }
}

#[derive(Default)]
pub struct Emulator {
    table: FastDecodeTable,
}

#[derive(Debug)]
/// 表示陷阱的原因
/// Represents the cause of a trap
pub enum TrapCause {
    /// 指令地址未对齐
    /// Instruction address misaligned
    InstructionAddressMisaligned,

    /// 指令访问错误
    /// Instruction access fault
    InstructionAccessFault,

    /// 非法指令
    /// Illegal instruction
    IllegalInstruction(u32),

    /// 断点
    /// Breakpoint
    Breakpoint,

    /// 加载地址未对齐
    /// Load address misaligned
    LoadAddressMisaligned,

    /// 加载访问错误
    /// Load access fault
    LoadAccessFault(ByteAddr),

    /// 存储地址未对齐
    /// Store address misaligned
    StoreAddressMisaligned(ByteAddr),

    /// 存储访问错误
    /// Store access fault
    StoreAccessFault,

    /// 用户模式的环境调用
    /// Environment call from user mode
    EnvironmentCallFromUserMode,
}

#[derive(Clone, Debug, Default)]
pub struct DecodedInstruction {
    pub insn: u32,
    top_bit: u32,
    func7: u32,
    rs2: u32,
    rs1: u32,
    func3: u32,
    rd: u32,
    opcode: u32,
}

#[derive(Clone, Copy, Debug)]
enum InsnCategory {
    Compute,
    Load,
    Store,
    System,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq)]
/// 表示指令的种类
/// Represents the kind of instruction
pub enum InsnKind {
    /// 无效指令
    /// Invalid instruction
    INVALID,

    /// 加法指令
    /// Addition instruction
    ADD,

    /// 减法指令
    /// Subtraction instruction
    SUB,

    /// 异或指令
    /// XOR instruction
    XOR,

    /// 或指令
    /// OR instruction
    OR,

    /// 与指令
    /// AND instruction
    AND,

    /// 逻辑左移���令
    /// Logical left shift instruction
    SLL,

    /// 逻辑右移指令
    /// Logical right shift instruction
    SRL,

    /// 算术右移指令
    /// Arithmetic right shift instruction
    SRA,

    /// 小于比较指令（有符号）
    /// Set less than instruction (signed)
    SLT,

    /// 小于比较指令（无符号）
    /// Set less than instruction (unsigned)
    SLTU,

    /// 加法立即数指令
    /// Addition immediate instruction
    ADDI,

    /// 异或立即数指令
    /// XOR immediate instruction
    XORI,

    /// 或立即数指令
    /// OR immediate instruction
    ORI,

    /// 与立即数指令
    /// AND immediate instruction
    ANDI,

    /// 逻辑左移立即数指令
    /// Logical left shift immediate instruction
    SLLI,

    /// 逻辑右移立即数指令
    /// Logical right shift immediate instruction
    SRLI,

    /// 算术右移立即数指令
    /// Arithmetic right shift immediate instruction
    SRAI,

    /// 小于比较立即数指令（有符号）
    /// Set less than immediate instruction (signed)
    SLTI,

    /// 小于比较立即数指令（无符号）
    /// Set less than immediate instruction (unsigned)
    SLTIU,

    /// 相等分支指令
    /// Branch if equal instruction
    BEQ,

    /// 不相等分支指令
    /// Branch if not equal instruction
    BNE,

    /// 小于分支指令（有符号）
    /// Branch if less than instruction (signed)
    BLT,

    /// 大于等于分支指令（有符号）
    /// Branch if greater than or equal instruction (signed)
    BGE,

    /// 小于分支指令（无符号）
    /// Branch if less than instruction (unsigned)
    BLTU,

    /// 大于等于分支指令（无符号）
    /// Branch if greater than or equal instruction (unsigned)
    BGEU,

    /// 无条件跳转指令
    /// Jump and link instruction
    JAL,

    /// 寄存器无条件跳转指令
    /// Jump and link register instruction
    JALR,

    /// 加载上半部分立即数指令
    /// Load upper immediate instruction
    LUI,

    /// 加载上半部分立即数并加上程序计数器指令
    /// Add upper immediate to PC instruction
    AUIPC,

    /// 乘法指令
    /// Multiplication instruction
    MUL,

    /// 高位乘法指令（有符号）
    /// High multiplication instruction (signed)
    MULH,

    /// 高位乘法指令（有符号和无符号）
    /// High multiplication instruction (signed and unsigned)
    MULHSU,

    /// 高位乘法指令（无符号）
    /// High multiplication instruction (unsigned)
    MULHU,

    /// 除法指令（有符号）
    /// Division instruction (signed)
    DIV,

    /// 除法指令（无符号）
    /// Division instruction (unsigned)
    DIVU,

    /// 取余指令（有符号）
    /// Remainder instruction (signed)
    REM,

    /// 取余指令（无符号）
    /// Remainder instruction (unsigned)
    REMU,

    /// 加载字节指令
    /// Load byte instruction
    LB,

    /// 加载半字指令
    /// Load halfword instruction
    LH,

    /// 加载字指令
    /// Load word instruction
    LW,

    /// 加载无符号字节指令
    /// Load byte unsigned instruction
    LBU,

    /// 加载无符号半字指令
    /// Load halfword unsigned instruction
    LHU,

    /// 存储字节指令
    /// Store byte instruction
    SB,

    /// 存储半字指令
    /// Store halfword instruction
    SH,

    /// 存储字指令
    /// Store word instruction
    SW,

    /// 任意环境调用指令
    /// Any environment call instruction
    EANY,

    /// 机器返回指令
    /// Machine return instruction
    MRET,
}
/*
在 RISC-V 指令集中，opcode、func3 和 func7 是指令编码中的字段，用于确定要执行的具体操作。
opcode：这是一个 7 位的字段，用于指定指令的一般类型（例如，加载、存储、算术等）。它用于识别指令的广泛类别。
func3：这是一个 3 位的字段，用于在 opcode 指定的类别内进一步细化操作。它有助于区分共享相同 opcode 的不同指令。
func7：这是一个 7 位的字段，用于进一步区分某些指令，特别是在算术和逻辑操作中。它通常与 opcode 和 func3 一起使用，以确定具体的指令操作。
例如，在 RISC-V 指令集中：
算术操作的 opcode 是 0x33。
func3 字段区分具体的算术操作，如加法（0x0）、减法（0x0，但 func7 为 0x20）等。
func7 字段用于进一步区分某些操作，如加法和减法。
 */
#[derive(Clone, Copy, Debug)]
pub struct Instruction {
    //kind：表示指令的具体种类。例如，加法指令（ADD）、减法指令（SUB）、逻辑与指令（AND）等。它详细描述了指令的操作类型。
    pub kind: InsnKind,
    //category：表示指令的类别。例如，计算指令（Compute）、加载指令（Load）、存储指令（Store）、系统指令（System）等。它用于对指令进行更高层次的分类。
    category: InsnCategory,
    pub opcode: u32,
    pub func3: u32,
    pub func7: u32,
    pub cycles: usize,
}

impl DecodedInstruction {
    /// 创建一个新的解码指令
/// Create a new decoded instruction
fn new(insn: u32) -> Self {
    Self {
        insn,
        top_bit: (insn & 0x80000000) >> 31,
        func7: (insn & 0xfe000000) >> 25,
        rs2: (insn & 0x01f00000) >> 20,
        rs1: (insn & 0x000f8000) >> 15,
        func3: (insn & 0x00007000) >> 12,
        rd: (insn & 0x00000f80) >> 7,
        opcode: insn & 0x0000007f,
    }
}

/// 计算 B 型立即数
/// Calculate the B-type immediate value
fn imm_b(&self) -> u32 {
    (self.top_bit * 0xfffff000)
        | ((self.rd & 1) << 11)
        | ((self.func7 & 0x3f) << 5)
        | (self.rd & 0x1e)
}

/// 计算 I 型立即数
/// Calculate the I-type immediate value
//imm_i 是一个方法，用于计算 RISC-V 指令中的 I 型立即数（immediate value）。
// I 型立即数通常用于立即数算术指令（如 ADDI、ORI 等），它们需要一个立即数来进行操作。
// 这个方法通过从指令编码中提取特定的位并组合它们来生成这个立即数。
fn imm_i(&self) -> u32 {
    (self.top_bit * 0xfffff000) | (self.func7 << 5) | self.rs2
}

/// 计算 S 型立即数
/// Calculate the S-type immediate value
//imm_s 是一个方法，用于计算 RISC-V 指令中的 S 型立即数（immediate value）。
// S 型立即数通常用于存储指令（如 SB、SH、SW 等），它们需要一个立即数来指定存储地址的偏移量。
// 这个方法通过从指令编码中提取特定的位并组合它们来生成这个立即数。
fn imm_s(&self) -> u32 {
    (self.top_bit * 0xfffff000) | (self.func7 << 5) | self.rd
}

/// 计算 J 型立即数
/// Calculate the J-type immediate value
//imm_j 是一个方法，用于计算 RISC-V 指令中的 J 型立即数（immediate value）。
// J 型立即数通常用于跳转指令（如 JAL），它们需要一个立即数来指定跳转的目标地址。
fn imm_j(&self) -> u32 {
    (self.top_bit * 0xfff00000)
        | (self.rs1 << 15)
        | (self.func3 << 12)
        | ((self.rs2 & 1) << 11)
        | ((self.func7 & 0x3f) << 5)
        | (self.rs2 & 0x1e)
}

/// 计算 U 型立即数
/// Calculate the U-type immediate value
//imm_u 是一个方法，用于计算 RISC-V 指令中的 U 型立即数（immediate value）。
// U 型立即数通常用于加载上半部分立即数指令（如 LUI）和加载上半部分立即数并加上程序计数器指令（如 AUIPC）
fn imm_u(&self) -> u32 {
    self.insn & 0xfffff000
}
}

const fn insn(
    kind: InsnKind,
    category: InsnCategory,
    opcode: u32,
    func3: i32,
    func7: i32,
    cycles: usize,
) -> Instruction {
    Instruction {
        kind,
        category,
        opcode,
        func3: func3 as u32,
        func7: func7 as u32,
        cycles,
    }
}

type InstructionTable = [Instruction; 48];
type FastInstructionTable = [u8; 1 << 10];

const RV32IM_ISA: InstructionTable = [
    insn(InsnKind::INVALID, InsnCategory::Invalid, 0x00, 0x0, 0x00, 0),
    insn(InsnKind::ADD, InsnCategory::Compute, 0x33, 0x0, 0x00, 1),
    insn(InsnKind::SUB, InsnCategory::Compute, 0x33, 0x0, 0x20, 1),
    insn(InsnKind::XOR, InsnCategory::Compute, 0x33, 0x4, 0x00, 2),
    insn(InsnKind::OR, InsnCategory::Compute, 0x33, 0x6, 0x00, 2),
    insn(InsnKind::AND, InsnCategory::Compute, 0x33, 0x7, 0x00, 2),
    insn(InsnKind::SLL, InsnCategory::Compute, 0x33, 0x1, 0x00, 1),
    insn(InsnKind::SRL, InsnCategory::Compute, 0x33, 0x5, 0x00, 2),
    insn(InsnKind::SRA, InsnCategory::Compute, 0x33, 0x5, 0x20, 2),
    insn(InsnKind::SLT, InsnCategory::Compute, 0x33, 0x2, 0x00, 1),
    insn(InsnKind::SLTU, InsnCategory::Compute, 0x33, 0x3, 0x00, 1),
    insn(InsnKind::ADDI, InsnCategory::Compute, 0x13, 0x0, -1, 1),
    insn(InsnKind::XORI, InsnCategory::Compute, 0x13, 0x4, -1, 2),
    insn(InsnKind::ORI, InsnCategory::Compute, 0x13, 0x6, -1, 2),
    insn(InsnKind::ANDI, InsnCategory::Compute, 0x13, 0x7, -1, 2),
    insn(InsnKind::SLLI, InsnCategory::Compute, 0x13, 0x1, 0x00, 1),
    insn(InsnKind::SRLI, InsnCategory::Compute, 0x13, 0x5, 0x00, 2),
    insn(InsnKind::SRAI, InsnCategory::Compute, 0x13, 0x5, 0x20, 2),
    insn(InsnKind::SLTI, InsnCategory::Compute, 0x13, 0x2, -1, 1),
    insn(InsnKind::SLTIU, InsnCategory::Compute, 0x13, 0x3, -1, 1),
    insn(InsnKind::BEQ, InsnCategory::Compute, 0x63, 0x0, -1, 1),
    insn(InsnKind::BNE, InsnCategory::Compute, 0x63, 0x1, -1, 1),
    insn(InsnKind::BLT, InsnCategory::Compute, 0x63, 0x4, -1, 1),
    insn(InsnKind::BGE, InsnCategory::Compute, 0x63, 0x5, -1, 1),
    insn(InsnKind::BLTU, InsnCategory::Compute, 0x63, 0x6, -1, 1),
    insn(InsnKind::BGEU, InsnCategory::Compute, 0x63, 0x7, -1, 1),
    insn(InsnKind::JAL, InsnCategory::Compute, 0x6f, -1, -1, 1),
    insn(InsnKind::JALR, InsnCategory::Compute, 0x67, 0x0, -1, 1),
    insn(InsnKind::LUI, InsnCategory::Compute, 0x37, -1, -1, 1),
    insn(InsnKind::AUIPC, InsnCategory::Compute, 0x17, -1, -1, 1),
    insn(InsnKind::MUL, InsnCategory::Compute, 0x33, 0x0, 0x01, 1),
    insn(InsnKind::MULH, InsnCategory::Compute, 0x33, 0x1, 0x01, 1),
    insn(InsnKind::MULHSU, InsnCategory::Compute, 0x33, 0x2, 0x01, 1),
    insn(InsnKind::MULHU, InsnCategory::Compute, 0x33, 0x3, 0x01, 1),
    insn(InsnKind::DIV, InsnCategory::Compute, 0x33, 0x4, 0x01, 2),
    insn(InsnKind::DIVU, InsnCategory::Compute, 0x33, 0x5, 0x01, 2),
    insn(InsnKind::REM, InsnCategory::Compute, 0x33, 0x6, 0x01, 2),
    insn(InsnKind::REMU, InsnCategory::Compute, 0x33, 0x7, 0x01, 2),
    insn(InsnKind::LB, InsnCategory::Load, 0x03, 0x0, -1, 1),
    insn(InsnKind::LH, InsnCategory::Load, 0x03, 0x1, -1, 1),
    insn(InsnKind::LW, InsnCategory::Load, 0x03, 0x2, -1, 1),
    insn(InsnKind::LBU, InsnCategory::Load, 0x03, 0x4, -1, 1),
    insn(InsnKind::LHU, InsnCategory::Load, 0x03, 0x5, -1, 1),
    insn(InsnKind::SB, InsnCategory::Store, 0x23, 0x0, -1, 1),
    insn(InsnKind::SH, InsnCategory::Store, 0x23, 0x1, -1, 1),
    insn(InsnKind::SW, InsnCategory::Store, 0x23, 0x2, -1, 1),
    insn(InsnKind::EANY, InsnCategory::System, 0x73, 0x0, 0x00, 1),
    insn(InsnKind::MRET, InsnCategory::System, 0x73, 0x0, 0x18, 1),
];

// RISC-V instruction are determined by 3 parts:
// - Opcode: 7 bits
// - Func3: 3 bits
// - Func7: 7 bits
// In many cases, func7 and/or func3 is ignored.  A standard trick is to decode
// via a table, but a 17 bit lookup table destroys L1 cache.  Luckily for us,
// in practice the low 2 bits of opcode are always 11, so we can drop them, and
// also func7 is always either 0, 1, 0x20 or don't care, so we can reduce func7
// to 2 bits, which gets us to 10 bits, which is only 1k.
struct FastDecodeTable {
    table: FastInstructionTable,
}

impl Default for FastDecodeTable {
    fn default() -> Self {
        Self::new()
    }
}

/// FastDecodeTable 的主要功能是通过一个快速查找表来解码 RISC-V 指令。
/// 它将指令的 opcode、func3 和 func7 字段映射到一个 10 位的索引，以便快速查找指令的具体类型。
/// 这种方法通过减少查找表的大小来提高解码速度，从而优化指令解码的性能。  主要函数解释如下：
/// 。new：创建并初始化一个新的 FastDecodeTable 实例。它会遍历 RV32IM_ISA 指令集，并将每条指令添加到查找表中。
/// 。map10：将 opcode、func3 和 func7 字段映射到一个 10 位的索引。这个索引用于在查找表中快速定位指令。
/// 。add_insn：将一条指令添加到查找表中。它根据指令的 opcode、func3 和 func7 字段计算出索引，并将指令的索引值存储在查找表中。
/// 。lookup：根据解码后的指令字段在查找表中查找对应的指令。它使用 map10 函数计算索引，���后从查找表中获取指令。

impl FastDecodeTable {
    fn new() -> Self {
        let mut table: FastInstructionTable = [0; 1 << 10];
        for (isa_idx, insn) in RV32IM_ISA.iter().enumerate() {
            Self::add_insn(&mut table, insn, isa_idx);
        }
        Self { table }
    }

    // Map to 10 bit format
    fn map10(opcode: u32, func3: u32, func7: u32) -> usize {
        let op_high = opcode >> 2;
        // Map 0 -> 0, 1 -> 1, 0x20 -> 2, everything else to 3
        let func72bits = if func7 <= 1 {
            func7
        } else if func7 == 0x20 {
            2
        } else {
            3
        };
        ((op_high << 5) | (func72bits << 3) | func3) as usize
    }

    fn add_insn(table: &mut FastInstructionTable, insn: &Instruction, isa_idx: usize) {
        let op_high = insn.opcode >> 2;
        if (insn.func3 as i32) < 0 {
            for f3 in 0..8 {
                for f7b in 0..4 {
                    let idx = (op_high << 5) | (f7b << 3) | f3;
                    table[idx as usize] = isa_idx as u8;
                }
            }
        } else if (insn.func7 as i32) < 0 {
            for f7b in 0..4 {
                let idx = (op_high << 5) | (f7b << 3) | insn.func3;
                table[idx as usize] = isa_idx as u8;
            }
        } else {
            table[Self::map10(insn.opcode, insn.func3, insn.func7)] = isa_idx as u8;
        }
    }

    fn lookup(&self, decoded: &DecodedInstruction) -> Instruction {
        let isa_idx = self.table[Self::map10(decoded.opcode, decoded.func3, decoded.func7)];
        RV32IM_ISA[isa_idx as usize]
    }
}
/// Emulator 的主要功能是模拟 RISC-V 指令的执行。它通过解码和执行指令来模拟处理器的行为。以下是 Emulator 的主要函数及其功能：
/// .new：创建并初始化一个新的 Emulator 实例。它会初始化一个 FastDecodeTable 用于快速指令解码。
/// .step：执行一个指令周期。它首先获取当前的程序计数器（PC），然后加载并解码指令，根据指令的类别调用相应的处理函数（如 step_compute、step_load、step_store、step_system），最后更新程序计数器。
/// .step_compute：处理计算类指令（如加法、减法等）。它根据指令的种类执行相应的计算操作，并将结果存储到目标寄存器中。
/// .step_load：处理加载类指令（如加载字节、加载半字等）。它从内存中加载数据并存储到目标寄存器中。
/// .step_store：处理存储类指令（如存储字节、存储半字等）。它将寄存器中的数据存储到内存中。
/// .step_system：
impl Emulator {
    pub fn new() -> Self {
        Self {
            table: FastDecodeTable::new(),
        }
    }
    /// step 函数在模拟器中执行单步操作。具体来说，它会执行当前指令并更新模拟器的状态。主要步骤如下：
    /// 1.获取当前的程序计数器（PC）。
    /// 2.检查指令加载的访问权限，如果访问失败则触发异常。
    /// 3.从内存中加载指令，并检查指令的合法性，如果非法则触发异常。
    /// 4.解码指令，获取指令的详细信息。
    /// 5.根据指令的类别（计算、加载、存储、系统、无效）调用相应的处理函数：
    /// step_compute：处理计算类指令。
    /// step_load：处理加载类指令。
    /// step_store：处理存储类指令。
    /// step_system：处理系统类指令。
    /// Invalid：处理无效指令，触发异常。
    /// 6.如果指令正常结束，调用 on_normal_end 函数。
    /// 7.返回执行结果。
    pub fn step<C: EmuContext>(&mut self, ctx: &mut C) -> Result<()> {
        let pc = ctx.get_pc();

        if !ctx.check_insn_load(pc) {
            ctx.trap(TrapCause::InstructionAccessFault)?;
            return Ok(());
        }

        /*
        word 主要用于从内存中加载当前程序计数器（PC）指向的指令。具体来说，它通过调用
        ctx.load_memory(pc.waddr()) 方法获取指令数据，并检查指令的合法性。
        如果指令的低两位不等于 0x03，则触发非法指令异常。这是因为在 RISC-V 指令集中，
        合法指令的低两位通常为 0x03。
         */
        let word = ctx.load_memory(pc.waddr())?;
        if word & 0x03 != 0x03 {
            ctx.trap(TrapCause::IllegalInstruction(word))?;
            return Ok(());
        }

        let decoded = DecodedInstruction::new(word);
        let insn = self.table.lookup(&decoded);
        ctx.on_insn_decoded(&insn, &decoded);

        if match insn.category {
            InsnCategory::Compute => self.step_compute(ctx, insn.kind, &decoded)?,
            InsnCategory::Load => self.step_load(ctx, insn.kind, &decoded)?,
            InsnCategory::Store => self.step_store(ctx, insn.kind, &decoded)?,
            InsnCategory::System => self.step_system(ctx, insn.kind, &decoded)?,
            InsnCategory::Invalid => ctx.trap(TrapCause::IllegalInstruction(word))?,
        } {
            ctx.on_normal_end(&insn, &decoded);
        };

        Ok(())
    }

    ///step_compute 函数的主要作用是处理计算类指令。它根据指令的种类执行相应的计算操作，并将结果存储到目标寄存器中
    /// 1.获取当前的程序计数器（PC）和目标寄存器（rd）。
    /// 2.从寄存器中加载源操作数（rs1 和 rs2）。
    /// 3.根据指令类型（如加法、减法、逻辑运算等）执行相应的计算操作。
    /// 4.将计算结果存储到目标寄存器（rd）。
    /// 5.更新程序计数器（PC）。
    /// 6.如果指令正常结束，返回 true，否则触发相应的异常。
    fn step_compute<M: EmuContext>(
        &mut self,
        ctx: &mut M,
        kind: InsnKind,
        decoded: &DecodedInstruction,
    ) -> Result<bool> {
        let pc = ctx.get_pc();
        let mut new_pc = pc + WORD_SIZE;
        let mut rd = decoded.rd;
        let rs1 = ctx.load_register(decoded.rs1 as usize)?;
        let rs2 = ctx.load_register(decoded.rs2 as usize)?;
        let imm_i = decoded.imm_i();
        let mut br_cond = |cond| -> u32 {
            rd = 0;
            if cond {
                new_pc = pc.wrapping_add(decoded.imm_b());
            }
            0
        };
        let out = match kind {
            InsnKind::ADD => rs1.wrapping_add(rs2),
            InsnKind::SUB => rs1.wrapping_sub(rs2),
            InsnKind::XOR => rs1 ^ rs2,
            InsnKind::OR => rs1 | rs2,
            InsnKind::AND => rs1 & rs2,
            InsnKind::SLL => rs1 << (rs2 & 0x1f),
            InsnKind::SRL => rs1 >> (rs2 & 0x1f),
            InsnKind::SRA => ((rs1 as i32) >> (rs2 & 0x1f)) as u32,
            InsnKind::SLT => {
                if (rs1 as i32) < (rs2 as i32) {
                    1
                } else {
                    0
                }
            }
            InsnKind::SLTU => {
                if rs1 < rs2 {
                    1
                } else {
                    0
                }
            }
            InsnKind::ADDI => rs1.wrapping_add(imm_i),
            InsnKind::XORI => rs1 ^ imm_i,
            InsnKind::ORI => rs1 | imm_i,
            InsnKind::ANDI => rs1 & imm_i,
            InsnKind::SLLI => rs1 << (imm_i & 0x1f),
            InsnKind::SRLI => rs1 >> (imm_i & 0x1f),
            InsnKind::SRAI => ((rs1 as i32) >> (imm_i & 0x1f)) as u32,
            InsnKind::SLTI => {
                if (rs1 as i32) < (imm_i as i32) {
                    1
                } else {
                    0
                }
            }
            InsnKind::SLTIU => {
                if rs1 < imm_i {
                    1
                } else {
                    0
                }
            }
            InsnKind::BEQ => br_cond(rs1 == rs2),
            InsnKind::BNE => br_cond(rs1 != rs2),
            InsnKind::BLT => br_cond((rs1 as i32) < (rs2 as i32)),
            InsnKind::BGE => br_cond((rs1 as i32) >= (rs2 as i32)),
            InsnKind::BLTU => br_cond(rs1 < rs2),
            InsnKind::BGEU => br_cond(rs1 >= rs2),
            InsnKind::JAL => {
                new_pc = pc.wrapping_add(decoded.imm_j());
                (pc + WORD_SIZE).0
            }
            InsnKind::JALR => {
                new_pc = ByteAddr(rs1.wrapping_add(imm_i) & 0xfffffffe);
                (pc + WORD_SIZE).0
            }
            InsnKind::LUI => decoded.imm_u(),
            InsnKind::AUIPC => (pc.wrapping_add(decoded.imm_u())).0,
            InsnKind::MUL => rs1.wrapping_mul(rs2),
            InsnKind::MULH => {
                (sign_extend_u32(rs1).wrapping_mul(sign_extend_u32(rs2)) >> 32) as u32
            }
            InsnKind::MULHSU => (sign_extend_u32(rs1).wrapping_mul(rs2 as i64) >> 32) as u32,
            InsnKind::MULHU => (((rs1 as u64).wrapping_mul(rs2 as u64)) >> 32) as u32,
            InsnKind::DIV => {
                if rs2 == 0 {
                    u32::MAX
                } else {
                    ((rs1 as i32).wrapping_div(rs2 as i32)) as u32
                }
            }
            InsnKind::DIVU => {
                if rs2 == 0 {
                    u32::MAX
                } else {
                    rs1 / rs2
                }
            }
            InsnKind::REM => {
                if rs2 == 0 {
                    rs1
                } else {
                    ((rs1 as i32).wrapping_rem(rs2 as i32)) as u32
                }
            }
            InsnKind::REMU => {
                if rs2 == 0 {
                    rs1
                } else {
                    rs1 % rs2
                }
            }
            _ => unreachable!(),
        };
        if !new_pc.is_aligned() {
            return ctx.trap(TrapCause::InstructionAddressMisaligned);
        }
        ctx.store_register(rd as usize, out)?;
        ctx.set_pc(new_pc);
        Ok(true)
    }

    fn step_load<M: EmuContext>(
        &mut self,
        ctx: &mut M,
        kind: InsnKind,
        decoded: &DecodedInstruction,
    ) -> Result<bool> {
        let rs1 = ctx.load_register(decoded.rs1 as usize)?;
        let _rs2 = ctx.load_register(decoded.rs2 as usize)?;
        let addr = ByteAddr(rs1.wrapping_add(decoded.imm_i()));
        if !ctx.check_data_load(addr) {
            return ctx.trap(TrapCause::LoadAccessFault(addr));
        }
        let data = ctx.load_memory(addr.waddr())?;
        let shift = 8 * (addr.0 & 3);
        let out = match kind {
            InsnKind::LB => {
                let mut out = (data >> shift) & 0xff;
                if out & 0x80 != 0 {
                    out |= 0xffffff00;
                }
                out
            }
            InsnKind::LH => {
                if addr.0 & 0x01 != 0 {
                    return ctx.trap(TrapCause::LoadAddressMisaligned);
                }
                let mut out = (data >> shift) & 0xffff;
                if out & 0x8000 != 0 {
                    out |= 0xffff0000;
                }
                out
            }
            InsnKind::LW => {
                if addr.0 & 0x03 != 0 {
                    return ctx.trap(TrapCause::LoadAddressMisaligned);
                }
                data
            }
            InsnKind::LBU => (data >> shift) & 0xff,
            InsnKind::LHU => {
                if addr.0 & 0x01 != 0 {
                    return ctx.trap(TrapCause::LoadAddressMisaligned);
                }
                (data >> shift) & 0xffff
            }
            _ => unreachable!(),
        };
        ctx.store_register(decoded.rd as usize, out)?;
        ctx.set_pc(ctx.get_pc() + WORD_SIZE);
        Ok(true)
    }

    fn step_store<M: EmuContext>(
        &mut self,
        ctx: &mut M,
        kind: InsnKind,
        decoded: &DecodedInstruction,
    ) -> Result<bool> {
        let rs1 = ctx.load_register(decoded.rs1 as usize)?;
        let rs2 = ctx.load_register(decoded.rs2 as usize)?;
        let addr = ByteAddr(rs1.wrapping_add(decoded.imm_s()));
        let shift = 8 * (addr.0 & 3);
        if !ctx.check_data_store(addr) {
            return ctx.trap(TrapCause::StoreAccessFault);
        }
        let mut data = ctx.load_memory(addr.waddr())?;
        match kind {
            InsnKind::SB => {
                data ^= data & (0xff << shift);
                data |= (rs2 & 0xff) << shift;
            }
            InsnKind::SH => {
                if addr.0 & 0x01 != 0 {
                    tracing::debug!("Misaligned SH");
                    return ctx.trap(TrapCause::StoreAddressMisaligned(addr));
                }
                data ^= data & (0xffff << shift);
                data |= (rs2 & 0xffff) << shift;
            }
            InsnKind::SW => {
                if addr.0 & 0x03 != 0 {
                    tracing::debug!("Misaligned SW");
                    return ctx.trap(TrapCause::StoreAddressMisaligned(addr));
                }
                data = rs2;
            }
            _ => unreachable!(),
        }
        ctx.store_memory(addr.waddr(), data)?;
        ctx.set_pc(ctx.get_pc() + WORD_SIZE);
        Ok(true)
    }

    fn step_system<M: EmuContext>(
        &mut self,
        ctx: &mut M,
        kind: InsnKind,
        decoded: &DecodedInstruction,
    ) -> Result<bool> {
        match kind {
            InsnKind::EANY => match decoded.rs2 {
                0 => ctx.ecall(),
                1 => ctx.trap(TrapCause::Breakpoint),
                _ => ctx.trap(TrapCause::IllegalInstruction(decoded.insn)),
            },
            InsnKind::MRET => ctx.mret(),
            _ => unreachable!(),
        }
    }
}

fn sign_extend_u32(x: u32) -> i64 {
    (x as i32) as i64
}
