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

//! Run the zkVM guest and prove its results.

mod dev_mode;
mod prover_impl;
#[cfg(test)]
mod tests;

use std::rc::Rc;

use anyhow::{anyhow, bail, ensure, Result};
use risc0_circuit_rv32im::prove::segment_prover;
use risc0_core::field::baby_bear::{BabyBear, Elem, ExtElem};
use risc0_zkp::hal::{CircuitHal, Hal};

use self::{dev_mode::DevModeProver, prover_impl::ProverImpl};
use crate::{
    host::prove_info::ProveInfo,
    is_dev_mode,
    receipt::{
        CompositeReceipt, Groth16Receipt, Groth16ReceiptVerifierParameters, InnerAssumptionReceipt,
        InnerReceipt, SegmentReceipt, SuccinctReceipt,
    },
    receipt_claim::Unknown,
    sha::Digestible,
    stark_to_snark, ExecutorEnv, ExecutorImpl, ProverOpts, Receipt, ReceiptClaim, ReceiptKind,
    Segment, Session, VerifierContext,
};

/// A ProverServer can execute a given ELF binary and produce a [ProveInfo] which contains a
/// [Receipt][crate::Receipt] that can be used to verify correct computation.
pub trait ProverServer {
    /// Prove the specified ELF binary.
    fn prove(&self, env: ExecutorEnv<'_>, elf: &[u8]) -> Result<ProveInfo> {
        self.prove_with_ctx(env, &VerifierContext::default(), elf)
    }

    /// Prove the specified ELF binary using the specified [VerifierContext].
    fn prove_with_ctx(
        &self,
        env: ExecutorEnv<'_>,
        ctx: &VerifierContext,
        elf: &[u8],
    ) -> Result<ProveInfo> {
        // 从 ELF 文件和执行环境构造一个新的 ExecutorImpl 实例
        let mut exec = ExecutorImpl::from_elf(env, elf)?;

        // 运行执行器以获取包含执行结果的 Session
        let session = exec.run()?;

        // 使用提供的验证上下文对 Session 进行证明，并返回 ProveInfo
        self.prove_session(ctx, &session)
    }
    /// Prove the specified [Session].
    fn prove_session(&self, ctx: &VerifierContext, session: &Session) -> Result<ProveInfo>;

    /// Prove the specified [Segment].
    fn prove_segment(&self, ctx: &VerifierContext, segment: &Segment) -> Result<SegmentReceipt>;

    /// Lift a [SegmentReceipt] into a [SuccinctReceipt]
    fn lift(&self, receipt: &SegmentReceipt) -> Result<SuccinctReceipt<ReceiptClaim>>;

    /// Join two [SuccinctReceipt] into a [SuccinctReceipt]
    fn join(
        &self,
        a: &SuccinctReceipt<ReceiptClaim>,
        b: &SuccinctReceipt<ReceiptClaim>,
    ) -> Result<SuccinctReceipt<ReceiptClaim>>;

    /// Resolve an assumption from a conditional [SuccinctReceipt] by providing a [SuccinctReceipt]
    /// proving the validity of the assumption.
    fn resolve(
        &self,
        conditional: &SuccinctReceipt<ReceiptClaim>,
        assumption: &SuccinctReceipt<Unknown>,
    ) -> Result<SuccinctReceipt<ReceiptClaim>>;

    /// Convert a [SuccinctReceipt] with a Poseidon hash function that uses a 254-bit field
    fn identity_p254(
        &self,
        a: &SuccinctReceipt<ReceiptClaim>,
    ) -> Result<SuccinctReceipt<ReceiptClaim>>;

    /// Compress a [CompositeReceipt] into a single [SuccinctReceipt].
    ///
    /// A [CompositeReceipt] may contain an arbitrary number of receipts assembled into
    /// segments and assumptions. Together, these receipts collectively prove a top-level
    /// [ReceiptClaim](crate::ReceiptClaim). This function compresses all of the constituent receipts of a
    /// [CompositeReceipt] into a single [SuccinctReceipt] that proves the same top-level claim. It
    /// accomplishes this by iterative application of the recursion programs including lift, join,
    /// and resolve.
    fn composite_to_succinct(
        &self,
        receipt: &CompositeReceipt,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        // 将顶层会话中的所有收据压缩成一个简洁的收据
        let continuation_receipt = receipt
            .segments
            .iter()
            .try_fold(
                None,
                |left: Option<SuccinctReceipt<ReceiptClaim>>,
                 right: &SegmentReceipt|
                 -> Result<_> {
                    Ok(Some(match left {
                        // 如果左侧已经有收据，则将其与右侧的收据合并
                        Some(left) => self.join(&left, &self.lift(right)?)?,
                        // 否则，将右侧的收据提升为简洁收据
                        None => self.lift(right)?,
                    }))
                },
            )?
            .ok_or(anyhow!(
            "malformed composite receipt has no continuation segment receipts"
        ))?;

        // 压缩假设并解析它们以获得最终的简洁收据
        receipt.assumption_receipts.iter().try_fold(
            continuation_receipt,
            |conditional: SuccinctReceipt<ReceiptClaim>, assumption: &InnerAssumptionReceipt| match assumption {
                // 如果假设是简洁收据，则直接解析
                InnerAssumptionReceipt::Succinct(assumption) => self.resolve(&conditional, assumption),
                // 如果假设是复合收据，则递归压缩并解析
                InnerAssumptionReceipt::Composite(assumption) => {
                    self.resolve(&conditional, &self.composite_to_succinct(assumption)?.into_unknown())
                }
                // 不支持假收据的压缩
                InnerAssumptionReceipt::Fake(_) => bail!(
                "compressing composite receipts with fake receipt assumptions is not supported"
            ),
                // 不支持 Groth16 收据的压缩
                InnerAssumptionReceipt::Groth16(_) => bail!(
                "compressing composite receipts with Groth16 receipt assumptions is not supported"
            )
            },
        )
    }

    /// 将 [SuccinctReceipt] 压缩成 [Groth16Receipt]。
    fn succinct_to_groth16(
        &self,
        receipt: &SuccinctReceipt<ReceiptClaim>,
    ) -> Result<Groth16Receipt<ReceiptClaim>> {
        // 使用 P254 哈希函数将收据转换为身份收据
        let ident_receipt = self.identity_p254(receipt).unwrap();

        // 获取身份收据的密封字节
        let seal_bytes = ident_receipt.get_seal_bytes();

        // 使用 STARK 到 SNARK 的转换函数将密封字节转换为密封
        let seal = stark_to_snark(&seal_bytes)?.to_vec();

        // 返回 Groth16 收据，其中包含密封、声明和验证参数
        Ok(Groth16Receipt {
            seal,
            claim: receipt.claim.clone(),
            verifier_parameters: Groth16ReceiptVerifierParameters::default().digest(),
        })
    }

    /// 将收据压缩成更小的表示形式。
    ///
    /// 请求的目标表示形式由提供的 [ProverOpts] 中指定的 [ReceiptKind] 决定。
    /// 如果收据已经至少压缩到请求的类型，则此操作无效。
    fn compress(&self, opts: &ProverOpts, receipt: &Receipt) -> Result<Receipt> {
        match &receipt.inner {
            // 如果收据是 Composite 类型
            InnerReceipt::Composite(inner) => match opts.receipt_kind {
                // 如果请求的类型是 Composite，则直接返回原始收据
                ReceiptKind::Composite => Ok(receipt.clone()),
                // 如果请求的类型是 Succinct，则将 Composite 收据压缩成 Succinct 收据
                ReceiptKind::Succinct => {
                    let succinct_receipt = self.composite_to_succinct(inner)?;
                    Ok(Receipt::new(
                        InnerReceipt::Succinct(succinct_receipt),
                        receipt.journal.bytes.clone(),
                    ))
                }
                // 如果请求的类型是 Groth16，则先将 Composite 收据压缩成 Succinct 收据，再压缩成 Groth16 收据
                ReceiptKind::Groth16 => {
                    let succinct_receipt = self.composite_to_succinct(inner)?;
                    let groth16_receipt = self.succinct_to_groth16(&succinct_receipt)?;
                    Ok(Receipt::new(
                        InnerReceipt::Groth16(groth16_receipt),
                        receipt.journal.bytes.clone(),
                    ))
                }
            },
            // 如果收据是 Succinct 类型
            InnerReceipt::Succinct(inner) => match opts.receipt_kind {
                // 如果请求的类型是 Composite 或 Succinct，则直接返回原始收据
                ReceiptKind::Composite | ReceiptKind::Succinct => Ok(receipt.clone()),
                // 如果请求的类型是 Groth16，则将 Succinct 收据压缩成 Groth16 收据
                ReceiptKind::Groth16 => {
                    let groth16_receipt = self.succinct_to_groth16(inner)?;
                    Ok(Receipt::new(
                        InnerReceipt::Groth16(groth16_receipt),
                        receipt.journal.bytes.clone(),
                    ))
                }
            },
            // 如果收据是 Groth16 类型
            InnerReceipt::Groth16(_) => match opts.receipt_kind {
                // 如果请求的类型是 Composite、Succinct 或 Groth16，则直接返回原始收据
                ReceiptKind::Composite | ReceiptKind::Succinct | ReceiptKind::Groth16 => {
                    Ok(receipt.clone())
                }
            },
            // 如果收据是 Fake 类型
            InnerReceipt::Fake(_) => {
                // 确保开发模式已启用，否则返回错误
                ensure!(
                is_dev_mode(),
                "dev mode must be enabled to compress fake receipts"
            );
                Ok(receipt.clone())
            }
        }
    }
}

/// A pair of [Hal] and [CircuitHal].
#[derive(Clone)]
pub struct HalPair<H, C>
where
    H: Hal<Field = BabyBear, Elem = Elem, ExtElem = ExtElem>,
    C: CircuitHal<H>,
{
    /// A [Hal] implementation.
    pub hal: Rc<H>,

    /// An [CircuitHal] implementation.
    pub circuit_hal: Rc<C>,
}

impl Session {
    /// For each segment, call [ProverServer::prove_session] and collect the
    /// receipts.
    pub fn prove(&self) -> Result<ProveInfo> {
        let prover = get_prover_server(&ProverOpts::default())?;
        prover.prove_session(&VerifierContext::default(), self)
    }
}

/// get a local prover server.
pub fn get_local_prover() -> Result<Rc<dyn ProverServer>> {
    get_prover_server(&ProverOpts::default())
}

/// Select a [ProverServer] based on the specified [ProverOpts] and currently
/// compiled features.
pub fn get_prover_server(opts: &ProverOpts) -> Result<Rc<dyn ProverServer>> {
    if is_dev_mode() {
        eprintln!("WARNING: proving in dev mode. This will not generate valid, secure proofs.");
        return Ok(Rc::new(DevModeProver));
    }

    let prover = segment_prover(&opts.hashfn)?;
    Ok(Rc::new(ProverImpl::new(opts.clone(), prover)))
}
