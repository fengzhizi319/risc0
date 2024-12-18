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
    syscall::reg_abi::{REG_A3, REG_A4, REG_A5, REG_A6, REG_A7},
    WORD_SIZE,
};

use crate::{
    host::client::env::ProveZkrRequest, recursion::prove::get_registered_zkr, Assumption,
    AssumptionReceipt,
};

use super::{Syscall, SyscallContext};

#[derive(Clone)]
pub(crate) struct SysProveZkr;

impl Syscall for SysProveZkr {
    fn syscall(
        &mut self,
        _syscall: &str,
        ctx: &mut dyn SyscallContext,
        _to_guest: &mut [u32],
    ) -> Result<(u32, u32)> {
        // 从寄存器 REG_A3 加载 claim_digest
        let claim_digest = ctx.load_digest_from_register(REG_A3)?;
        // 从寄存器 REG_A4 加载 control_id
        let control_id = ctx.load_digest_from_register(REG_A4)?;
        // 从寄存器 REG_A5 加载 control_root
        let control_root = ctx.load_digest_from_register(REG_A5)?;
        // 从寄存器 REG_A6 加载输入指针
        let input_ptr = ByteAddr(ctx.load_register(REG_A6));
        // 从寄存器 REG_A7 加载输入长度
        let input_len = ctx.load_register(REG_A7);
        // 从内存区域加载输入数据
        let input: Vec<u8> = ctx.load_region(input_ptr, input_len * WORD_SIZE as u32)?;

        // 查找假设
        let assumption = ctx
            .syscall_table()
            .assumptions
            .borrow()
            .find_assumption(&claim_digest, &control_root)?;
        if assumption.is_some() {
            // 假设已存在，不需要创建新的证明
            return Ok((0, 0));
        }

        // 构建 ZKR 证明请求
        let proof_request = ProveZkrRequest {
            claim_digest,
            control_id,
            input,
        };

        // 如果存在协处理器，则调用其 prove_zkr 方法
        if let Some(coprocessor) = &ctx.syscall_table().coprocessor {
            coprocessor.borrow_mut().prove_zkr(proof_request)?;
        } else {
            // 否则，注册 ZKR 并将其添加到待处理的 ZKR 列表中
            get_registered_zkr(&control_id)?;
            ctx.syscall_table()
                .pending_zkrs
                .borrow_mut()
                .push(proof_request);
        }

        // 记录假设
        let assumption = Assumption {
            claim: claim_digest,
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
