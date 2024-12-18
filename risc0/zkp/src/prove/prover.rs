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

use risc0_core::{
    field::{Elem, ExtElem, RootsOfUnity},
    scope, scope_with,
};

use crate::{
    core::poly::poly_interpolate,
    hal::{Buffer, CircuitHal, Hal},
    prove::{fri::fri_prove, poly_group::PolyGroup, write_iop::WriteIOP},
    taps::TapSet,
    INV_RATE,
};

/// Object to generate a zero-knowledge proof of the execution of some circuit.
pub struct Prover<'a, H: Hal> {
    hal: &'a H,
    taps: &'a TapSet<'a>,
    ///iop 的主要功能是用于在零知识证明过程中提交或读取随机数据
    iop: WriteIOP<H::Field>,
    ///groups 的主要功能是存储多项式组（PolyGroup）的可选值。这些多项式组在零知识证明过程中用于
    /// 评估和验证多项式的系数和根。每个 PolyGroup 包含一个多项式的系数和一个 Merkle 树，用于确保数据的完整性和安全性。
    groups: Vec<Option<PolyGroup<H>>>,
    cycles: usize,
    po2: usize,
}

fn make_coeffs<H: Hal>(hal: &H, witness: &H::Buffer<H::Elem>, count: usize) -> H::Buffer<H::Elem> {
    scope!("make_coeffs");
    let coeffs = hal.alloc_elem("coeffs", witness.size());
    hal.eltwise_copy_elem(&coeffs, witness);
    // Do interpolate
    hal.batch_interpolate_ntt(&coeffs, count);
    // Convert f(x) -> f(3x), which effective multiplies coefficients c_i by 3^i.
    #[cfg(not(feature = "circuit_debug"))]
    hal.zk_shift(&coeffs, count);
    coeffs
}

impl<'a, H: Hal> Prover<'a, H> {
    /// Creates a new prover.
    pub fn new(hal: &'a H, taps: &'a TapSet) -> Self {
        Self {
            hal,
            taps,
            iop: WriteIOP::new(hal.get_hash_suite().rng.as_ref()),
            //生成了一个包含 taps.num_groups() 个 None 值的向量
            groups: std::iter::repeat_with(|| None)
                .take(taps.num_groups())
                .collect(),
            cycles: 0,
            po2: usize::MAX,
        }
    }

    /// Accesses the prover's IOP to commit or read random data.
    pub fn iop(&mut self) -> &mut WriteIOP<H::Field> {
        &mut self.iop
    }

    /// Sets the number of cycles to 2^po2.  This must be called
    /// once after new() before any commit_group() calls.
    pub fn set_po2(&mut self, po2: usize) {
        assert_eq!(self.po2, usize::MAX);
        assert_eq!(self.cycles, 0);
        self.po2 = po2;
        self.cycles = 1 << po2;
    }

    /// Commits a given buffer to the IOP; the values must not subsequently
    /// change.
    pub fn commit_group(&mut self, tap_group_index: usize, witness: &H::Buffer<H::Elem>) {
        // 创建一个范围（scope）以记录提交组的过程
        scope_with!("commit_group({})", witness.name());

        // 获取组的大小
        let group_size = self.taps.group_size(tap_group_index);

        // 确保 witness 的大小是 group_size 的整数倍
        assert_eq!(witness.size() % group_size, 0);

        // 确保 witness 的大小除以 group_size 等于 cycles
        assert_eq!(witness.size() / group_size, self.cycles);

        // 确保该组尚未提交
        assert!(
            self.groups[tap_group_index].is_none(),
            "Attempted to commit group {} more than once",
            self.taps.group_name(tap_group_index)
        );

        // 生成多项式系数
        let coeffs = make_coeffs(self.hal, witness, group_size);

        // 创建一个新的 PolyGroup 并插入到 groups 中
        let group_ref = self.groups[tap_group_index].insert(PolyGroup::new(
            self.hal,
            coeffs,
            group_size,
            self.cycles,
            witness.name(),
        ));

        // 提交 Merkle 树的根到 IOP
        group_ref.merkle.commit(&mut self.iop);

        // 记录调试信息
        tracing::debug!(
        "{} group root: {}",
        self.taps.group_name(tap_group_index),
        group_ref.merkle.root()
    );
    }

    /// Generates the proof and returns the seal.
    /// 生成证明并返回封装（seal）。
    pub fn finalize<C>(mut self, globals: &[&H::Buffer<H::Elem>], circuit_hal: &C) -> Vec<u32>
    where
        C: CircuitHal<H>,
    {
        scope!("finalize");

        // Set the poly mix value, which is used for constraint compression in the
        // DEEP-ALI protocol.
        // 设置多项式混合值，用于 DEEP-ALI 协议中的约束压缩。
        let poly_mix = self.iop.random_ext_elem();
        let domain = self.cycles * INV_RATE;
        let ext_size = H::ExtElem::EXT_SIZE;

        // Now generate the check polynomial.
        // The check polynomial is the core of the STARK: if the constraints are
        // satisfied, the check polynomial will be a low-degree polynomial. See
        // DEEP-ALI paper for details on the construction of the check_poly.
        // 生成检查多项式。
        // 检查多项式是 STARK 的核心：如果约束满足，检查多项式将是低阶多项式。详见 DEEP-ALI 论文。
        let check_poly = self.hal.alloc_elem("check_poly", ext_size * domain);

        let groups: Vec<&_> = self
            .groups
            .iter()
            .map(|pg| &pg.as_ref().unwrap().evaluated)
            .collect();
        circuit_hal.eval_check(
            &check_poly,
            groups.as_slice(),
            globals,
            poly_mix,
            self.po2,
            self.cycles,
        );

        #[cfg(feature = "circuit_debug")]
        check_poly.view(|check_out| {
            for i in (0..domain).step_by(4) {
                if check_out[i] != H::Elem::ZERO {
                    tracing::debug!("check[{}] =  {:?}", i, check_out[i]);
                }
            }
        });

        // Convert to coefficients.  Some tricky business here with the fact that
        // checkPoly is really an FpExt polynomial.  Nicely for us, since all the
        // roots of unity (which are the only thing that and values get multiplied
        // by) are in Fp, FpExt values act like simple vectors of Fp for the
        // purposes of interpolate/evaluate.
        // 转换为系数。这里有一些复杂的操作，因为 checkPoly 实际上是一个 FpExt 多项式。
        // 对我们来说很方便，因为所有的单位根（以及所有被乘以的值）都在 Fp 中，
        // 对于插值/评估来说，FpExt 值就像 Fp 的简单向量。
        self.hal.batch_interpolate_ntt(&check_poly, ext_size);

        // The next step is to convert the degree 4*n check polynomial into 4 degree n
        // polynomials so that f(x) = g0(x^4) + g1(x^4) x + g2(x^4) x^2 + g3(x^4)
        // x^3.  To do this, we normally would grab all the coefficients of f(x) =
        // sum_i c_i x^i where i % 4 == 0 and put them into a new polynomial g0(x) =
        // sum_i d0_i*x^i, where d0_i = c_(i*4).
        //
        // Amazingly, since the coefficients are bit reversed, the coefficients of g0
        // are all already next to each other and in bit-reversed for g0, as are
        // the coefficients of g1, etc. So really, we can just reinterpret 4 polys of
        // invRate*size to 16 polys of size, without actually doing anything.
        // 下一步是将 4*n 次的检查多项式转换为 4 个 n 次多项式，使得 f(x) = g0(x^4) + g1(x^4) x + g2(x^4) x^2 + g3(x^4) x^3。
        // 为此，我们通常会抓�� f(x) = sum_i c_i x^i 的所有系数，其中 i % 4 == 0，并将它们放入一个新的多项式 g0(x) = sum_i d0_i*x^i，
        // 其中 d0_i = c_(i*4)。
        //
        // 令人惊讶的是，由于系数是位反转的，g0 的系数都已经在一起并且是 g0 的位反转，g1 的系数也是如此。
        // 所以实际上，我们可以将 invRate*size 的 4 个多项式重新解释为 size 的 16 个多项式，而无需实际做任何事情。

        // Make the PolyGroup + add it to the IOP;
        // 创建 PolyGroup 并将其添加到 IOP 中；
        let check_group = PolyGroup::new(self.hal, check_poly, H::CHECK_SIZE, self.cycles, "check");
        check_group.merkle.commit(&mut self.iop);
        tracing::debug!("checkGroup: {}", check_group.merkle.root());

        // Now pick a value for Z, which is used as the DEEP-ALI query point.
        // 现在选择一个 Z 值，作为 DEEP-ALI 查询点。
        let z = self.iop.random_ext_elem();
        // #ifdef CIRCUIT_DEBUG
        //   if (badZ != FpExt(0)) {
        //     Z = badZ;
        //   }
        //   iop.write(&Z, 1);
        // #endif
        //   LOG(1, "Z = " << Z);

        // Get rev rou for size
        // 获取 size 的 rev rou
        let back_one = H::ExtElem::from_subfield(&H::Elem::ROU_REV[self.po2]);
        let mut all_xs = Vec::new();

        // Now, we evaluate each group at the appropriate points (relative to Z).
        // From here on out, we always process groups in accum, code, data order,
        // since this is the order used by the codegen system (alphabetical).
        // Sometimes it's a requirement for matching generated code, but even when
        // it's not we keep the order for consistency.
        // 现在，我们在适当的点（相对于 Z）评估每个组。
        // 从现在开始，我们总是按 accum、code、data 的顺序处理组，
        // 因为这是代码生成系统使用的顺序（按字母顺序）。
        // 有时这是匹配生成代码的要求，但即使不是，我们也保持顺序一致。
        let mut eval_u: Vec<H::ExtElem> = Vec::new();
        scope!("eval_u", {
        for (id, pg) in self.groups.iter().enumerate() {
            let pg = pg.as_ref().unwrap();

            let mut which = Vec::new();
            let mut xs = Vec::new();
            for tap in self.taps.group_taps(id) {
                which.push(tap.offset() as u32);
                let x = back_one.pow(tap.back()) * z;
                xs.push(x);
                all_xs.push(x);
            }
            let which = self.hal.copy_from_u32("which", which.as_slice());
            let xs = self.hal.copy_from_extelem("xs", xs.as_slice());
            let out = self.hal.alloc_extelem("out", which.size());
            self.hal
                .batch_evaluate_any(&pg.coeffs, pg.count, &which, &xs, &out);
            out.view(|view| {
                eval_u.extend(view);
            });
        }
    });

        // Now, convert the values to coefficients via interpolation
        // 现在，通过插值将值转换为系数
        let mut coeff_u = vec![H::ExtElem::ZERO; eval_u.len()];
        scope!("poly_interpolate", {
        let mut pos = 0;
        for reg in self.taps.regs() {
            poly_interpolate(
                &mut coeff_u[pos..],
                &all_xs[pos..],
                &eval_u[pos..],
                reg.size(),
            );
            pos += reg.size();
        }
    });

        // Add in the coeffs of the check polynomials.
        // 添加检查多项式的系数。
        let z_pow = z.pow(ext_size);
        scope!("misc", {
        let which = Vec::from_iter(0u32..H::CHECK_SIZE as u32);
        let xs = vec![z_pow; H::CHECK_SIZE];
        let out = self.hal.alloc_extelem("out", H::CHECK_SIZE);
        let which = self.hal.copy_from_u32("which", which.as_slice());
        let xs = self.hal.copy_from_extelem("xs", xs.as_slice());
        self.hal
            .batch_evaluate_any(&check_group.coeffs, H::CHECK_SIZE, &which, &xs, &out);
        out.view(|view| {
            coeff_u.extend(view);
        });

        tracing::debug!("Size of U = {}", coeff_u.len());
        self.iop.write_field_elem_slice(&coeff_u);
        let hash_u = self
            .hal
            .get_hash_suite()
            .hashfn
            .hash_ext_elem_slice(coeff_u.as_slice());
        self.iop.commit(&hash_u);

        // Set the mix value, which is used for FRI batching.
        // 设置混合值，用于 FRI 批处理。
    });

        let mix = self.iop.random_ext_elem();
        tracing::debug!("Mix = {mix:?}");

        // Do the coefficient mixing
        // 进行系数混合
        // Begin by making a zeroed output buffer
        // 首先创建一个清零的输出缓冲区
        let combo_count = self.taps.combos_size();
        let combos = scope!(
        "alloc(combos)",
        self.hal
            .alloc_extelem_zeroed("combos", self.cycles * (combo_count + 1))
    );

        scope!("mix_poly_coeffs", {
        let mut cur_mix = H::ExtElem::ONE;

        for (id, pg) in self.groups.iter().enumerate() {
            let pg = pg.as_ref().unwrap();

            let group_size = self.taps.group_size(id);
            let mut which = Vec::with_capacity(group_size);
            for reg in self.taps.group_regs(id) {
                which.push(reg.combo_id() as u32);
            }
            let which = self.hal.copy_from_u32("which", which.as_slice());
            self.hal.mix_poly_coeffs(
                &combos,
                &cur_mix,
                &mix,
                &pg.coeffs,
                &which,
                group_size,
                self.cycles,
            );
            cur_mix *= mix.pow(group_size);
        }

        let which = vec![combo_count as u32; H::CHECK_SIZE];
        let which_buf = self.hal.copy_from_u32("which", which.as_slice());
        self.hal.mix_poly_coeffs(
            &combos,
            &cur_mix,
            &mix,
            &check_group.coeffs,
            &which_buf,
            H::CHECK_SIZE,
            self.cycles,
        );
    });

        scope!("load_combos", {
        let reg_sizes: Vec<_> = self.taps.regs().map(|x| x.size() as u32).collect();
        let reg_combo_ids: Vec<_> = self.taps.regs().map(|x| x.combo_id() as u32).collect();

        scope!("prepare", {
            self.hal.combos_prepare(
                &combos,
                &coeff_u,
                combo_count,
                self.cycles,
                &reg_sizes,
                &reg_combo_ids,
                &mix,
            );
        });

        scope!("divide", {
            let mut chunks = vec![];

            // Divide each element by (x - Z * back1^back) for each back
            // 将每个元素除以 (x - Z * back1^back)
            for i in 0..combo_count {
                let mut pows = vec![];
                for &back in self.taps.get_combo(i).slice() {
                    pows.push(z * back_one.pow(back.into()));
                }
                chunks.push((i, pows));
            }

            // Divide check polys by z^EXT_SIZE
            // 将检查多项式除以 z^EXT_SIZE
            chunks.push((combo_count, vec![z_pow]));

            self.hal.combos_divide(&combos, chunks, self.cycles);
        });
    });

        // Sum the combos up into one final polynomial + make it into 4 Fp polys.
        // Additionally, it needs to be bit reversed to make everyone happy
        // 将组合求和为一个最终多项式 + 将其转换为 4 个 Fp 多项式。
        // 此外，还需要进行位反转以使所有人满意
        let final_poly_coeffs = scope!("sum", {
        let final_poly_coeffs = self
            .hal
            .alloc_elem("final_poly_coeffs", self.cycles * ext_size);
        self.hal.eltwise_sum_extelem(&final_poly_coeffs, &combos);
        final_poly_coeffs
    });

        // Finally do the FRI protocol to prove the degree of the polynomial
        // 最后执行 FRI 协议以证明多项式的度数
        scope!(
        "bit_rev",
        self.hal.batch_bit_reverse(&final_poly_coeffs, ext_size)
    );
        tracing::debug!("FRI-proof, size = {}", final_poly_coeffs.size() / ext_size);

        fri_prove(self.hal, &mut self.iop, &final_poly_coeffs, |iop, idx| {
            for pg in self.groups.iter() {
                let pg = pg.as_ref().unwrap();
                pg.merkle.prove(self.hal, iop, idx);
            }
            check_group.merkle.prove(self.hal, iop, idx);
        });

        let proven_soundness_error =
            super::soundness::proven::<H>(self.taps, final_poly_coeffs.size());
        tracing::debug!("proven_soundness_error: {proven_soundness_error:?}");

        let conjectured_security =
            super::soundness::toy_model_security::<H>(self.taps, final_poly_coeffs.size());
        tracing::debug!("conjectured_security: {conjectured_security:?}");

        // Return final proof
        // 返回最终证明
        let proof = self.iop.proof;
        tracing::debug!("Proof size = {}", proof.len());
        proof
    }
}
