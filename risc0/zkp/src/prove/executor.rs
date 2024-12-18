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

use core::cmp::max;

use anyhow::Result;
use rand::thread_rng;
use rayon::prelude::*;
use risc0_core::{
    field::{Elem, Field},
    scope,
};
use tracing::debug;

use crate::{
    adapter::{
        CircuitProveDef, CircuitStepContext, CircuitStepHandler, REGISTER_GROUP_CODE,
        REGISTER_GROUP_DATA,
    },
    hal::cpu::{CpuBuffer, SyncSlice},
    MIN_PO2, ZK_CYCLES,
};

pub struct Executor<F, C, S>
where
    F: Field,
    C: 'static + CircuitProveDef<F>,
    S: CircuitStepHandler<F::Elem>,
{
    pub circuit: &'static C,
    // Circuit Step Handler
    pub handler: S,
    // Control Instructions
    pub code: CpuBuffer<F::Elem>,
    // Number of columns used for control instructions
    code_size: usize,
    // Execution Trace Data
    pub data: CpuBuffer<F::Elem>,
    // Number of columns used for execution trace data
    data_size: usize,
    // Circuit inputs/outputs
    pub io: CpuBuffer<F::Elem>,
    // Power of 2
    pub po2: usize,
    // steps = 2^po2 is the total number of cycles in the zkVM execution
    pub steps: usize,
    // Indicates whether the guest program has already halted
    pub halted: bool,
    // Counter for zkVM execution
    pub cycle: usize,
}

impl<F, C, S> Executor<F, C, S>
where
    F: Field,
    C: 'static + CircuitProveDef<F>,
    S: CircuitStepHandler<F::Elem>,
{
    pub fn new(circuit: &'static C, handler: S, min_po2: usize, io: &[F::Elem]) -> Self {
        // 计算 po2，取 min_po2 和 MIN_PO2 中的较大值
        let po2 = max(min_po2, MIN_PO2);
        // 获取电路的 taps
        let taps = circuit.get_taps();
        // 获取控制指令的列数
        let code_size = taps.group_size(REGISTER_GROUP_CODE);
        // 获取执行跟踪数据的列数
        let data_size = taps.group_size(REGISTER_GROUP_DATA);
        // 计算总的周期数 steps = 2^po2
        let steps = 1 << po2;
        debug!("po2: {po2}, steps: {steps}, code_size: {code_size}");
        Executor {
            circuit,
            handler,
            // 初始化 trace 为 min_po2 大小
            code: CpuBuffer::from_fn("code", steps * code_size, |_| F::Elem::ZERO),
            code_size,
            data: CpuBuffer::from_fn("data", steps * data_size, |_| F::Elem::INVALID),
            data_size,
            io: CpuBuffer::from(Vec::from(io)),
            po2,
            steps,
            halted: false,
            cycle: 0,
        }
    }

    pub fn step(&mut self, code: &[F::Elem], needed_fini: usize) -> Result<bool> {
        // 计算下一个周期数
        let next_cycles = self.cycle + needed_fini + ZK_CYCLES;
        // 如果下一个周期数超过总的周期数
        if next_cycles >= self.steps {
            debug!(
            "cycle:{} + needed_fini:{} + ZK_CYCLES:{} = {} >= steps: {}",
            self.cycle, needed_fini, ZK_CYCLES, next_cycles, self.steps
        );
            // 如果已经停止，返回 false
            if self.halted {
                debug!("halted");
                return Ok(false);
            }
            // 否则抛出异常
            panic!("expand must not be called.");
        }
        // 获取同步的代码缓冲区
        let code_buf = self.code.as_slice_sync();
        // 将代码写入缓冲区
        for (i, code) in code.iter().enumerate().take(self.code_size) {
            code_buf.set(self.steps * i + self.cycle, *code);
        }
        // 创建步骤上下文
        let ctx = CircuitStepContext {
            size: self.steps,
            cycle: self.cycle,
        };
        // 创建参数数组
        let args: &[SyncSlice<F::Elem>] =
            &[code_buf, self.io.as_slice_sync(), self.data.as_slice_sync()];
        // 执行电路步骤
        let result = self.circuit.step_exec(&ctx, &mut self.handler, args)?;
        // 如果结果为零，表示已经停止
        self.halted = self.halted || result == F::Elem::ZERO;
        // 增加周期计数
        self.cycle += 1;
        Ok(true)
    }

    fn compute_verify(&mut self) {
        let mut rng = thread_rng();
        let code_buf = self.code.as_slice_sync();
        let io_buf = self.io.as_slice_sync();
        let data_buf = self.data.as_slice_sync();

        // 将代码缓冲区的 zk 周期部分置零，数据缓冲区置为随机值
        for i in self.cycle..self.steps {
            for j in 0..self.code_size {
                code_buf.set(j * self.steps + i, F::Elem::ZERO);
            }
            for j in 0..self.data_size {
                data_buf.set(j * self.steps + i, F::Elem::random(&mut rng));
            }
        }
        // 执行验证周期
        let args: &[SyncSlice<F::Elem>] = &[code_buf, io_buf, data_buf];

        // 对 RAM 进行排序
        self.handler.sort("ram");
        scope!("step_verify_mem", {
        for i in 0..self.cycle {
            let ctx = CircuitStepContext {
                cycle: i,
                size: self.steps,
            };
            self.circuit
                .step_verify_mem(&ctx, &mut self.handler, args)
                .unwrap();
        }
    });

        // 对字节进行排序
        self.handler.sort("bytes");
        scope!("step_verify_bytes", {
        for i in 0..self.cycle {
            let ctx = CircuitStepContext {
                cycle: i,
                size: self.steps,
            };
            self.circuit
                .step_verify_bytes(&ctx, &mut self.handler, args)
                .unwrap();
        }
    });
    }

    pub fn finalize(&mut self) {
        scope!("finalize");

        // 确保已经停止
        assert!(self.halted);
        // 确保周期数等于总周期数减去 zk 周期数
        assert_eq!(self.cycle, self.steps - ZK_CYCLES);

        // 计算验证
        self.compute_verify();

        // 将数据和输出中的无效条目置零
        self.data
            .as_slice_mut()
            .par_iter_mut()
            .chain(self.io.as_slice_mut().par_iter_mut())
            .for_each(|value| *value = value.valid_or_zero());
    }
}
