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

use rand::thread_rng;
use risc0_core::scope;
use risc0_zkp::{
    adapter::TapsProvider,
    field::{
        baby_bear::{BabyBear, BabyBearElem, BabyBearExtElem},
        Elem as _,
    },
    hal::Hal,
    ZK_CYCLES,
};

use super::machine::MachineContext;
use crate::{
    prove::{
        emu::preflight::PreflightTrace,
        engine::loader::Loader,
        hal::{CircuitWitnessGenerator, StepMode},
    },
    CIRCUIT,
};

pub(crate) struct WitnessGenerator<H>
where
    H: Hal<Field = BabyBear, Elem = BabyBearElem, ExtElem = BabyBearExtElem>,
{
    // 表示步骤数，即电路执行的总周期数
    pub steps: usize,
    // 控制缓冲区，用于存储控制寄存器的数据
    pub ctrl: H::Buffer<H::Elem>,
    // 数据缓冲区，用于存储数据寄存器的数据
    pub data: H::Buffer<H::Elem>,
    // 输入输出缓冲区，用于存储输入输出寄存器的数据
    pub io: H::Buffer<H::Elem>,
}

impl<H> WitnessGenerator<H>
where
    H: Hal<Field = BabyBear, Elem = BabyBearElem, ExtElem = BabyBearExtElem>,
{
    pub fn new<C: CircuitWitnessGenerator<H>>(
        hal: &H,
        circuit_hal: &C,
        po2: usize,
        io: &[BabyBearElem],
        trace: &PreflightTrace,
        mode: StepMode,
    ) -> Self {
        // 创建一个范围（scope）以记录见证生成的过程
        scope!("witgen");

        // 计算步骤数，2 的 po2 次方
        let steps = 1 << po2;

        // 加载控制数据，获取最后一个周期
        let (loader, last_cycle) = scope!("load", {
        let mut loader = Loader::new(steps, CIRCUIT.ctrl_size());
        let last_cycle = loader.load();
        (loader, last_cycle)
        });
        tracing::debug!("last_cycle: {last_cycle}");

        // 分配数据缓冲区，初始化为无效值
        let data = scope!(
        "alloc(data)",
        hal.alloc_elem_init("data", steps * CIRCUIT.data_size(), BabyBearElem::INVALID)
        );

        // 创建机器上下文
        let machine = MachineContext::new(trace);
        if mode != StepMode::SeqForward {
            // 注入执行回退数据到 data 中
            scope!("inject_exec_backs", {
            let mut offsets = vec![];
            let mut values = vec![];
            let mut index = Vec::with_capacity(last_cycle + 1);
            for cycle in 0..last_cycle {
                index.push(offsets.len() as u32);
                machine.inject_exec_backs(steps, cycle, &mut offsets, &mut values);
            }
            index.push(offsets.len() as u32);

            hal.scatter(&data, &index, &offsets, &values);//将values散列到data中
            });
        }

        if mode == StepMode::Parallel {
            // 向 data 中添加随机噪声
            scope!("noise(data)", {
            let mut rng = thread_rng();
            let noise = vec![BabyBearElem::random(&mut rng); ZK_CYCLES * CIRCUIT.data_size()];
            hal.eltwise_copy_elem_slice(
                &data,
                &noise,
                CIRCUIT.data_size(), // from_rows
                ZK_CYCLES,           // from_cols
                0,                   // from_offset
                ZK_CYCLES,           // from_stride
                steps - ZK_CYCLES,   // into_offset
                steps,               // into_stride
            );//随机噪声noise拷贝到data的末尾
           });
        }

        // 复制控制数据到 ctrl 缓冲区
        let ctrl = scope!("copy(ctrl)", hal.copy_from_elem("ctrl", &loader.ctrl));
        // 复制输入输出数据到 io 缓冲区
        let io = scope!("copy(io)", hal.copy_from_elem("io", io));

        // 生成见证数据
        circuit_hal.generate_witness(
            mode,
            &machine.raw_trace,
            steps,
            last_cycle,
            &ctrl,
            &io,
            &data,
        );

        // 清零 data 和 io 缓冲区中的无效条目
        scope!("zeroize", {
        hal.eltwise_zeroize_elem(&data);
        hal.eltwise_zeroize_elem(&io);
    });

        // 返回 WitnessGenerator 实例
        Self {
            steps,
            ctrl,
            data,
            io,
        }
    }
}
