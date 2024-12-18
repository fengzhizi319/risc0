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

// Manages system calls for accelerators and other proof composition

use anyhow::Result;
use risc0_circuit_rv32im::prove::emu::addr::ByteAddr;
use risc0_zkvm_platform::{
    syscall::reg_abi::{REG_A3, REG_A4, REG_A5, REG_A6},
    WORD_SIZE,
};

use crate::{
    host::client::env::ProveKeccakRequest, recursion::prove::get_registered_zkr, Assumption,
    AssumptionReceipt,
};

use super::{Syscall, SyscallContext};

#[derive(Clone)]
pub(crate) struct SysProveKeccak;

impl Syscall for SysProveKeccak {
    /// 实现一个系统调用，用于处理 Keccak 证明请求。
    fn syscall(
        &mut self,
        _syscall: &str,
        ctx: &mut dyn SyscallContext,
        _to_guest: &mut [u32],
    ) -> Result<(u32, u32)> {
        // 从寄存器 REG_A3 加载 po2 值
        let po2 = ctx.load_register(REG_A3) as usize;
        // 从寄存器 REG_A4 加载输入指针
        let input_ptr = ByteAddr(ctx.load_register(REG_A4));
        // 从寄存器 REG_A5 加载输入长度
        let input_len = ctx.load_register(REG_A5);
        // 从内存区域加载输入数据
        let input: Vec<u8> = ctx.load_region(input_ptr, input_len * WORD_SIZE as u32)?;
        // 从寄存器 REG_A6 加载控制根
        let control_root = ctx.load_digest_from_register(REG_A6)?;

        // 构建 Keccak 证明请求
        let proof_request = ProveKeccakRequest { po2, input };

        // 获取 Keccak 协处理器
        let Some(keccak_coprocessor) = &ctx.syscall_table().keccak_coprocessor else {
            // 目前只支持使用 Keccak 协处理器
            unimplemented!()
        };

        // 调用 Keccak 协处理器生成证明
        let keccak_response = keccak_coprocessor
            .borrow_mut()
            .prove_keccak(proof_request)?;
        // 请求将 ZKR 提升到递归电路中
        let zkr_proof_request = keccak_response.zkr_lift;
        let claim = zkr_proof_request.claim_digest;
        eprintln!("claim: {claim:?}");

        // 如果存在协处理器，则调用其 prove_zkr 方法
        if let Some(coprocessor) = &ctx.syscall_table().coprocessor {
            coprocessor.borrow_mut().prove_zkr(zkr_proof_request)?;
        } else {
            // 否则，注册 ZKR 并将其添加到待处理的 ZKR 列表中
            get_registered_zkr(&zkr_proof_request.control_id)?;
            ctx.syscall_table()
                .pending_zkrs
                .borrow_mut()
                .push(zkr_proof_request);
        }

        // 记录假设
        let assumption = Assumption {
            claim,
            control_root,
        };
        ctx.syscall_table()
            .assumptions
            .borrow_mut()
            .0
            .push(AssumptionReceipt::Unresolved(assumption));

        // 返回结果
        Ok((0, 0))
    }
}
