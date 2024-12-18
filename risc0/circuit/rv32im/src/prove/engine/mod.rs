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

pub mod loader;
pub mod machine;
#[cfg(test)]
mod tests;
pub mod witgen;

use std::rc::Rc;

use anyhow::Result;
use rand::thread_rng;
use risc0_core::scope;
use risc0_zkp::{
    adapter::{CircuitInfo, TapsProvider, PROOF_SYSTEM_INFO},
    field::{
        baby_bear::{BabyBear, BabyBearElem, BabyBearExtElem},
        Elem as _,
    },
    hal::{Buffer as _, CircuitHal, Hal},
    prove::Prover,
    ZK_CYCLES,
};

use self::witgen::WitnessGenerator;
use super::{hal::CircuitWitnessGenerator, segment::Segment, Seal, SegmentProver};
use crate::{
    prove::hal::StepMode, CircuitImpl, CIRCUIT, REGISTER_GROUP_ACCUM, REGISTER_GROUP_CTRL,
    REGISTER_GROUP_DATA,
};

pub(crate) struct SegmentProverImpl<H, C>
where
    H: Hal<Field = BabyBear, Elem = BabyBearElem, ExtElem = BabyBearExtElem>,
    C: CircuitHal<H> + CircuitWitnessGenerator<H>,
{
    hal: Rc<H>,
    circuit_hal: Rc<C>,
}

impl<H, C> SegmentProverImpl<H, C>
where
    H: Hal<Field = BabyBear, Elem = BabyBearElem, ExtElem = BabyBearExtElem>,
    C: CircuitHal<H> + CircuitWitnessGenerator<H>,
{
    pub fn new(hal: Rc<H>, circuit_hal: Rc<C>) -> Self {
        Self { hal, circuit_hal }
    }
}

impl<H, C> SegmentProver for SegmentProverImpl<H, C>
where
    H: Hal<Field = BabyBear, Elem = BabyBearElem, ExtElem = BabyBearExtElem>,
    C: CircuitHal<H> + CircuitWitnessGenerator<H>,
{
    /*
    1. 初始化：创建一个范围（scope）以记录证明段的过程。
    2. 预处理：调用 segment.preflight() 函数进行预处理，获取跟踪信息。调用 segment.prepare_globals() 函数准备全局变量。
    3. 生成见证：创建一个 WitnessGenerator 实例，用于生成见证数据。
    4. 初始化证明者：创建一个 Prover 实例，并初始化哈希函数。
    5. 主证明过程：
      - 提交初始信息：将证明系统和电路的信息提交到 Fiat-Shamir 转录中。
      - 处理全局变量和 po2：将全局变量和 po2 连接成一个向量，并计算其哈希值。
      - 提交全局变量和 po2：将哈希值和向量提交到证明者中，并设置 po2。
      - 提交控制和数据寄存器组：将控制和数据寄存器组提交到证明者中。
      - 生成混合值：生成混合值并提交到证明者中。
      - 分配累加器：分配累加器并添加随机噪声。
      - 累加：调用 circuit_hal.accumulate 函数进行累加操作。
      - 提交累加器：将累加器提交到证明者中。
    6. 完成证明：调用 prover.finalize 函数完成证明过程，并返回结果
     */
    fn prove_segment(&self, segment: &Segment) -> Result<Seal> {
        // 创建一个范围（scope）以记录证明段的过程
        scope!("prove_segment");

        // 调用 segment.preflight() 函数进行预处理，获取trace信息
        let trace = segment.preflight()?;
        // 调用 segment.prepare_globals() 函数准备全局变量
        let io = segment.prepare_globals();
        println!("io: {:?}", io);

        // 创建一个 WitnessGenerator 实例，用于生成见证数据
        let witgen = WitnessGenerator::new(
            self.hal.as_ref(),
            self.circuit_hal.as_ref(),
            segment.po2,
            &io,
            &trace,
            StepMode::Parallel,
        );
        // println!("witgen.io: {:?}", witgen.io.clone().to_vec());
        // println!("io: {:?}", io);
        let steps = witgen.steps;

        // 返回证明结果
        Ok(scope!("prove", {
        // 创建一个 Prover 实例，并初始化哈希函数
        let mut prover = Prover::new(self.hal.as_ref(), CIRCUIT.get_taps());
        let hashfn = &self.hal.get_hash_suite().hashfn;

        // 主证明过程
        let mix = scope!("main", {
            // 将证明系统和电路的信息提交到 Fiat-Shamir 转录（transcript）中
            prover
                .iop()
                .commit(&hashfn.hash_elem_slice(&PROOF_SYSTEM_INFO.encode()));
            prover
                .iop()
                .commit(&hashfn.hash_elem_slice(&CircuitImpl::CIRCUIT_INFO.encode()));

            // 将io复制给io_po2，并将io_po2的最后一个元素设置为segment.po2
            let mut io_po2 = vec![BabyBearElem::ZERO; io.len() + 1];
            witgen.io.view_mut(|view| {
                for (i, elem) in view.iter_mut().enumerate() {
                    *elem = elem.valid_or_zero();
                    io_po2[i] = *elem;
                }
                io_po2[io.len()] = BabyBearElem::new_raw(segment.po2 as u32);
            });
            //println!("io_po2: {:?}", io_po2);

            // 将哈希值和向量提交到证明者中，并设置 po2
            let io_po2_digest = hashfn.hash_elem_slice(&io_po2);
            prover.iop().commit(&io_po2_digest);
            prover.iop().write_field_elem_slice(io_po2.as_slice());
            prover.set_po2(segment.po2);

            // 将控制和数据寄存器组提交到证明者中
            prover.commit_group(REGISTER_GROUP_CTRL, &witgen.ctrl);
            prover.commit_group(REGISTER_GROUP_DATA, &witgen.data);

            // 生成混合值并提交到证明者中
            let mix: Vec<_> = scope!(
                "mix",
                (0..CircuitImpl::MIX_SIZE)
                    .map(|_| prover.iop().random_elem())
                    .collect()
            );

            let mix = scope!("copy(mix)", self.hal.copy_from_elem("mix", mix.as_slice()));

            // 分配累加器并添加随机噪声
            let accum = scope!(
                "alloc(accum)",
                self.hal.alloc_elem_init(
                    "accum",
                    steps * CIRCUIT.accum_size(),
                    BabyBearElem::INVALID,
                )
            );

            // 添加随机噪声到累加器末尾
            scope!("noise(accum)", {
                let mut rng = thread_rng();
                let noise =
                    vec![BabyBearElem::random(&mut rng); ZK_CYCLES * CIRCUIT.accum_size()];
                self.hal.eltwise_copy_elem_slice(
                    &accum,
                    &noise,
                    CIRCUIT.accum_size(), // from_rows
                    ZK_CYCLES,            // from_cols
                    0,                    // from_offset
                    ZK_CYCLES,            // from_stride
                    steps - ZK_CYCLES,    // into_offset
                    steps,                // into_stride
                );
            });

            // 调用 circuit_hal.accumulate 函数进行累加操作
            self.circuit_hal.accumulate(
                &trace.accum,
                &witgen.ctrl,
                &witgen.io,
                &witgen.data,
                &mix,
                &accum,
                steps,
            );

            // 将累加器提交到证明者中
            prover.commit_group(REGISTER_GROUP_ACCUM, &accum);

            mix
        });

        // 调用 prover.finalize 函数完成证明过程，并返回结果
        prover.finalize(&[&mix, &witgen.io], self.circuit_hal.as_ref())
    }))
    }
}
