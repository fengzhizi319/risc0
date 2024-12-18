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

use derive_more::Debug;
use risc0_binfmt::{ExitCode, MemoryImage, SystemState};
use risc0_core::scope;
use risc0_zkp::{
    adapter::CircuitInfo as _,
    core::digest::{Digest, DIGEST_WORDS},
    field::{baby_bear::Elem, Elem as _},
};
use risc0_zkvm_platform::WORD_SIZE;
use serde::{Deserialize, Serialize};

use crate::CircuitImpl;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyscallRecord {
    pub to_guest: Vec<u32>,
    pub regs: (u32, u32),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Segment {
    #[debug(skip)]
    pub partial_image: MemoryImage, // 部分内存映像，表示程序执行过程中某个时刻的内存状态
    pub pre_state: SystemState, // 执行前的系统状态，包括寄存器和内存等信息
    pub post_state: SystemState, // 执行后的系统状态，包括寄存器和内存等信息
    #[debug(skip)]
    pub syscalls: Vec<SyscallRecord>, // 系统调用记录，包含所有在执行过程中发生的系统调用
    pub insn_cycles: usize, // 指令周期数，表示执行指令所花费的周期数
    pub po2: usize, // 证明最大长度的幂次，表示证明的复杂度
    pub exit_code: ExitCode, // 退出码，表示程序执行的结果状态
    pub index: usize, // 段索引，表示当前段在整个程序中的位置
    pub input_digest: Digest, // 输入摘要，表示输入数据的哈希值
    pub output_digest: Option<Digest>, // 输出摘要，表示输出数据的哈希值（可选）
}

impl Segment {
    ///input_digest||pre_state.pc||merkle_root
    pub fn prepare_globals(&self) -> Vec<Elem> {
        scope!("prepare_globals");

        let mut io = vec![Elem::INVALID; CircuitImpl::OUTPUT_SIZE];

        // initialize Input
        let mut offset = 0;
        for i in 0..DIGEST_WORDS {
            let bytes = self.input_digest.as_words()[i].to_le_bytes();
            for j in 0..WORD_SIZE {
                io[offset + i * WORD_SIZE + j] = (bytes[j] as u32).into();
            }
        }
        offset += DIGEST_WORDS * WORD_SIZE;

        // initialize PC
        let pc_bytes = self.pre_state.pc.to_le_bytes();
        for i in 0..WORD_SIZE {
            io[offset + i] = (pc_bytes[i] as u32).into();
        }
        offset += WORD_SIZE;

        // initialize ImageID
        let merkle_root = self.pre_state.merkle_root.as_words();
        for i in 0..DIGEST_WORDS {
            let bytes = merkle_root[i].to_le_bytes();
            for j in 0..WORD_SIZE {
                io[offset + i * WORD_SIZE + j] = (bytes[j] as u32).into();
            }
        }

        io
    }
}
