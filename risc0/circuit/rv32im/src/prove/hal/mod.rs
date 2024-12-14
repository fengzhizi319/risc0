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

pub(crate) mod cpp;
pub mod cpu;
#[cfg(feature = "cuda")]
pub mod cuda;
#[cfg(any(all(target_os = "macos", target_arch = "aarch64"), target_os = "ios"))]
pub mod metal;
pub mod testutil;

use risc0_circuit_rv32im_sys::ffi::RawPreflightTrace;
use risc0_zkp::hal::Hal;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum StepMode {
    ///并行模式，表示步骤可以并行执行，通常用于提高性能
    Parallel,
    ///顺序前进模式，表示步骤按顺序从头到尾执行
    SeqForward,
    #[allow(dead_code)]
    ///顺序反向模式，表示步骤按顺序从尾到头执行（此字段在当前代码中未使用
    SeqReverse,
}

pub(crate) trait CircuitWitnessGenerator<H: Hal> {
    #[allow(clippy::too_many_arguments)]
    fn generate_witness(
        &self,
        mode: StepMode,
        trace: &RawPreflightTrace,
        steps: usize,
        count: usize,
        ctrl: &H::Buffer<H::Elem>,
        io: &H::Buffer<H::Elem>,
        data: &H::Buffer<H::Elem>,
    );
}
