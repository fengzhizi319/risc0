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

use std::collections::HashMap;

use anyhow::{anyhow, bail, ensure, Context, Result};
use risc0_circuit_rv32im::prove::SegmentProver;

use super::ProverServer;
use crate::{
    host::{
        client::prove::ReceiptKind,
        prove_info::ProveInfo,
        recursion::{identity_p254, join, lift, resolve},
    },
    prove_zkr,
    receipt::{
        segment::decode_receipt_claim_from_seal, InnerReceipt, SegmentReceipt, SuccinctReceipt,
    },
    receipt_claim::{MaybePruned, Merge, Unknown},
    sha::Digestible,
    Assumption, AssumptionReceipt, CompositeReceipt, InnerAssumptionReceipt, Output, ProverOpts,
    Receipt, ReceiptClaim, Segment, Session, VerifierContext,
};

/// An implementation of a Prover that runs locally.
pub struct ProverImpl {
    opts: ProverOpts,
    segment_prover: Box<dyn SegmentProver>,
}

impl ProverImpl {
    /// Construct a [ProverImpl].
    pub fn new(opts: ProverOpts, segment_prover: Box<dyn SegmentProver>) -> Self {
        Self {
            opts,
            segment_prover,
        }
    }
}

impl ProverServer for ProverImpl {
    /*
    1记录调试信息：使用 tracing::debug! 记录会话的退出代码、日志和段的数量。
    2处理每个段：遍历会话中的每个段，调用 prove_segment 方法进行证明，并在证明前后调用钩子函数。
    3处理假设：将会话中的假设和假设收据分离，并将输出合并到最后一个段中。
    4获取验证参数：从验证上下文中获取复合验证参数。
    5处理 ZKR 收据：遍历会话中的待处理 ZKR 请求，生成收据并存储在哈希映射中。
    6处理假设收据：将假设收据转换为内部假设收据。
    7创建复合收据：使用段、假设收据和验证参数创建复合收据。
    8验证收据完整性：验证复合收据的完整性，并检查声明是否匹配。
    9压缩收据：根据选项中的收据类型，将复合收据压缩为所需类型。
    10返回证明信息：返回包含收据和统计信息的 ProveInfo。
     */
    fn prove_session(&self, ctx: &VerifierContext, session: &Session) -> Result<ProveInfo> {
        // 记录调试信息
        tracing::debug!(
        "prove_session: exit_code = {:?}, journal = {:?}, segments: {}",
        session.exit_code,
        session.journal.as_ref().map(hex::encode),
        session.segments.len()
        );

        // 处理每个段
        let mut segments = Vec::new();
        for segment_ref in session.segments.iter() {
            let segment = segment_ref.resolve()?;
            for hook in &session.hooks {
                hook.on_pre_prove_segment(&segment);
            }
            let  prove_segment0=self.prove_segment(ctx, &segment)?;
            segments.push(prove_segment0);
            //segments.push(self.prove_segment(ctx, &segment)?);
            for hook in &session.hooks {
                hook.on_post_prove_segment(&segment);
            }
        }

        // 处理假设
        let (assumptions, session_assumption_receipts): (Vec<_>, Vec<_>) =
            session.assumptions.iter().cloned().unzip();

        // 将输出合并到最后一个段中
        segments
            .last_mut()
            .ok_or(anyhow!("session is empty"))?
            .claim
            .output
            .merge_with(
                &session
                    .journal
                    .as_ref()
                    .map(|journal| Output {
                        journal: MaybePruned::Pruned(journal.digest()),
                        assumptions: assumptions.into(),
                    })
                    .into(),
            )
            .context("failed to merge output into final segment claim")?;

        // 获取验证参数
        let verifier_parameters = ctx
            .composite_verifier_parameters()
            .ok_or(anyhow!(
            "composite receipt verifier parameters missing from context"
        ))?
            .digest();

        // 处理 ZKR 收据
        let mut zkr_receipts = HashMap::new();
        for proof_request in session.pending_zkrs.iter() {
            let receipt = prove_zkr(&proof_request.control_id, &proof_request.input)?;
            let assumption = Assumption {
                claim: receipt.claim.digest(),
                control_root: receipt.control_root()?,
            };
            zkr_receipts.insert(assumption, receipt);
        }

        // 处理假设收据
        let inner_assumption_receipts: Vec<_> = session_assumption_receipts
            .into_iter()
            .map(|assumption_receipt| match assumption_receipt {
                AssumptionReceipt::Proven(receipt) => Ok(receipt),
                AssumptionReceipt::Unresolved(assumption) => {
                    let receipt = zkr_receipts
                        .get(&assumption)
                        .ok_or(anyhow!("no receipt available for unresolved assumption"))?;
                    Ok(InnerAssumptionReceipt::Succinct(receipt.clone()))
                }
            })
            .collect::<Result<_>>()?;

        let assumption_receipts: Vec<_> = inner_assumption_receipts
            .iter()
            .map(|inner| AssumptionReceipt::Proven(inner.clone()))
            .collect();

        // 创建复合收据
        let composite_receipt = CompositeReceipt {
            segments,
            assumption_receipts: inner_assumption_receipts,
            verifier_parameters,
        };

        let session_claim = session.claim_with_assumptions(assumption_receipts.iter())?;

        // 验证收据完整性
        composite_receipt.verify_integrity_with_context(ctx)?;
        check_claims(
            &session_claim,
            "composite",
            MaybePruned::Value(composite_receipt.claim()?),
        )?;

        // 压缩收据
        let receipt = match self.opts.receipt_kind {
            ReceiptKind::Composite => Receipt::new(
                InnerReceipt::Composite(composite_receipt),
                session.journal.clone().unwrap_or_default().bytes,
            ),
            ReceiptKind::Succinct => {
                let succinct_receipt = self.composite_to_succinct(&composite_receipt)?;
                Receipt::new(
                    InnerReceipt::Succinct(succinct_receipt),
                    session.journal.clone().unwrap_or_default().bytes,
                )
            }
            ReceiptKind::Groth16 => {
                let succinct_receipt = self.composite_to_succinct(&composite_receipt)?;
                let groth16_receipt = self.succinct_to_groth16(&succinct_receipt)?;
                Receipt::new(
                    InnerReceipt::Groth16(groth16_receipt),
                    session.journal.clone().unwrap_or_default().bytes,
                )
            }
        };

        // 验证收据完整性
        receipt.verify_integrity_with_context(ctx)?;
        check_claims(&session_claim, "receipt", receipt.claim()?)?;

        // 返回证明信息
        Ok(ProveInfo {
            receipt,
            stats: session.stats(),
        })
    }
    /*
    1. 检查段的 po2：确保段的 po2 不超过最大允许值。
    2. 生成段的密封：调用 segment_prover.prove_segment 方法生成段的密封。
    3. 解码收据声明：从密封中解码收据声明，并设置段的输出。
    4. 获取验证参数：从验证上下文中获取段的验证参数。
    5. 创建段收据：使用密封、索引、哈希函数、声明和验证参数创建段收据。
    6. 验证收据完整性：验证段收据的完整性。
    7. 返回段收据：返回段收据
     */

    fn prove_segment(&self, ctx: &VerifierContext, segment: &Segment) -> Result<SegmentReceipt> {
        // 确保段的 po2 不超过最大允许值
        ensure!(
        segment.po2() <= self.opts.max_segment_po2,
        "segment po2 exceeds max on ProverOpts: {} > {}",
        segment.po2(),
        self.opts.max_segment_po2
        );

        // 调用 segment_prover.prove_segment 方法生成段的密封
        let seal = self.segment_prover.prove_segment(&segment.inner)?;

        // 从密封中解码收据声明，并设置段的输出
        let mut claim = decode_receipt_claim_from_seal(&seal)?;
        claim.output = segment.output.clone().into();

        // 从验证上下文中获取段的验证参数
        let verifier_parameters = ctx
            .segment_verifier_parameters
            .as_ref()
            .ok_or(anyhow!(
            "segment receipt verifier parameters missing from context"
        ))?
            .digest();

        // 使用密封、索引、哈希函数、声明和验证参数创建段收据
        let receipt = SegmentReceipt {
            seal,
            index: segment.index,
            hashfn: self.opts.hashfn.clone(),
            claim,
            verifier_parameters,
        };

        // 验证段收据的完整性
        receipt.verify_integrity_with_context(ctx)?;

        // 返回段收据
        Ok(receipt)
    }

    fn lift(&self, receipt: &SegmentReceipt) -> Result<SuccinctReceipt<ReceiptClaim>> {
        lift(receipt)
    }

    fn join(
        &self,
        a: &SuccinctReceipt<ReceiptClaim>,
        b: &SuccinctReceipt<ReceiptClaim>,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        join(a, b)
    }

    fn resolve(
        &self,
        conditional: &SuccinctReceipt<ReceiptClaim>,
        assumption: &SuccinctReceipt<Unknown>,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        resolve(conditional, assumption)
    }

    fn identity_p254(
        &self,
        a: &SuccinctReceipt<ReceiptClaim>,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        identity_p254(a)
    }
}

fn check_claims(
    session_claim: &ReceiptClaim,
    other_name: &str,
    other_claim: MaybePruned<ReceiptClaim>,
) -> Result<()> {
    let session_claim_digest = session_claim.digest();
    let other_claim_digest = other_claim.digest();
    if session_claim_digest != other_claim_digest {
        tracing::debug!("session claim and {other_name} do not match");
        tracing::debug!("session claim: {session_claim:#?}");
        tracing::debug!("{other_name} claim: {other_claim:#?}");
        bail!(
            "session claim: {} != {other_name} claim: {}",
            hex::encode(session_claim_digest),
            hex::encode(other_claim_digest)
        );
    }
    Ok(())
}
