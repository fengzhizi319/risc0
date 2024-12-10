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

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use prost::Message;
use risc0_zkp::core::digest::Digest;

use super::{
    malformed_err, pb, Asset, AssetRequest, ConnectionWrapper, Connector, ParentProcessConnector,
    SessionInfo,
};
use crate::{
    get_version,
    host::{api::SegmentInfo, client::prove::get_r0vm_path},
    receipt::{AssumptionReceipt, SegmentReceipt, SuccinctReceipt},
    ExecutorEnv, Journal, ProveInfo, ProverOpts, Receipt, ReceiptClaim,
};

/// A client implementation for interacting with a zkVM server.
pub struct Client {
    connector: Box<dyn Connector>,
    compat: bool,
}

impl Default for Client {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

impl Client {
    /// Construct a [Client] that connects to `r0vm` in a child process.
    pub fn new() -> Result<Self> {
        Self::new_sub_process("r0vm")
    }

    /// Construct a [Client] that connects to a sub-process which implements
    /// the server by calling the specified `server_path`.
    pub fn new_sub_process<P: AsRef<Path>>(server_path: P) -> Result<Self> {
        let connector = ParentProcessConnector::new(server_path)?;
        Ok(Self::with_connector(Box::new(connector)))
    }

    /// Construct a [Client] that connects to a sub-process which implements
    /// the server by calling the specified `server_path`.
    ///
    /// Additionally allows for wider version mismatches, only rejecting major differences
    pub fn new_sub_process_compat<P: AsRef<Path>>(server_path: P) -> Result<Self> {
        let connector = ParentProcessConnector::new_wide_version(server_path)?;
        Ok(Self {
            connector: Box::new(connector),
            compat: true,
        })
    }

    /// Construct a [Client] based on environment variables.
    pub fn from_env() -> Result<Self> {
        Client::new_sub_process(get_r0vm_path()?)
    }

    /// Construct a [Client] using the specified [Connector] to establish a
    /// connection with the server.
    pub fn with_connector(connector: Box<dyn Connector>) -> Self {
        Self {
            connector,
            compat: false,
        }
    }

    /// 证明指定的 ELF 二进制文件。
    pub fn prove(
        &self,
        env: &ExecutorEnv<'_>,
        opts: &ProverOpts,
        binary: Asset,
    ) -> Result<ProveInfo> {
        // 使用连接器创建一个新的连接
        let mut conn = self.connect()?;
        // 创建一个 ProveRequest 消息，包含执行环境、选项和接收输出的请求
        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Prove(
                pb::api::ProveRequest {
                    // 将执行环境转换为 Protobuf 格式
                    env: Some(self.make_execute_env(env, binary.try_into()?)?),
                    // 将选项转换为 Protobuf 格式
                    opts: Some(opts.clone().into()),
                    // 创建一个内联的 AssetRequest 用于接收输出
                    receipt_out: Some(pb::api::AssetRequest {
                        kind: Some(pb::api::asset_request::Kind::Inline(())),
                    }),
                },
            )),
        };
        // 发送 ProveRequest 消息给服务器
        conn.send(request)?;

        // 处理证明过程的响应
        let asset = self.prove_handler(&mut conn, env)?;

        // 关闭连接并检查返回的代码
        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        // 将资产转换为字节数组
        let prove_info_bytes = asset.as_bytes()?;
        // 解码字节数组为 ProveInfo Protobuf 对象
        let prove_info_pb = pb::core::ProveInfo::decode(prove_info_bytes)?;
        // 将 Protobuf 对象转换为 ProveInfo 并返回
        prove_info_pb.try_into()
    }

    /// 执行指定的 ELF 二进制文件。
    pub fn execute<F>(
        &self,
        env: &ExecutorEnv<'_>,
        binary: Asset,
        segments_out: AssetRequest,
        segment_callback: F,
    ) -> Result<SessionInfo>
    where
        F: FnMut(SegmentInfo, Asset) -> Result<()>,
    {
        // 使用连接器创建一个新的连接
        let mut conn = self.connect()?;

        // 创建一个 ExecuteRequest 消息，包含执行环境和输出段的请求
        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Execute(
                pb::api::ExecuteRequest {
                    // 将执行环境转换为 Protobuf 格式
                    env: Some(self.make_execute_env(env, binary.try_into()?)?),
                    // 将输出段请求转换为 Protobuf 格式
                    segments_out: Some(segments_out.try_into()?),
                },
            )),
        };
        // 发送 ExecuteRequest 消息给服务器
        conn.send(request)?;

        // 处理执行过程的响应
        let result = self.execute_handler(segment_callback, &mut conn, env);

        // 关闭连接并检查返回的代码
        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    /// 证明指定的段。
    pub fn prove_segment(
        &self,
        opts: &ProverOpts,
        segment: Asset,
        receipt_out: AssetRequest,
    ) -> Result<SegmentReceipt> {
        // 使用连接器创建一个新的连接
        let mut conn = self.connect()?;

        // 创建一个 ProveSegmentRequest 消息，包含选项、段和接收输出的请求
        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::ProveSegment(
                pb::api::ProveSegmentRequest {
                    // 将选项转换为 Protobuf 格式
                    opts: Some(opts.clone().into()),
                    // 将段转换为 Protobuf 格式
                    segment: Some(segment.try_into()?),
                    // 将接收输出请求转换为 Protobuf 格式
                    receipt_out: Some(receipt_out.try_into()?),
                },
            )),
        };
        // 发送 ProveSegmentRequest 消息给服务器
        conn.send(request)?;

        // 接收 ProveSegmentReply 消息
        let reply: pb::api::ProveSegmentReply = conn.recv()?;

        // 处理 ProveSegmentReply 消息
        let result = match reply.kind.ok_or(malformed_err())? {
            pb::api::prove_segment_reply::Kind::Ok(result) => {
                // 将接收的字节数组解码为 SegmentReceipt Protobuf 对象
                let receipt_bytes = result.receipt.ok_or(malformed_err())?.as_bytes()?;
                let receipt_pb = pb::core::SegmentReceipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::prove_segment_reply::Kind::Error(err) => Err(err.into()),
        };

        // 关闭连接并检查返回的代码
        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    /// 运行 lift 程序，将 [SegmentReceipt] 转换为 [SuccinctReceipt]。
    pub fn lift(
        &self,
        opts: &ProverOpts,
        receipt: Asset,
        receipt_out: AssetRequest,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        // 使用连接器创建一个新的连接
        let mut conn = self.connect()?;

        // 创建一个 LiftRequest 消息，包含选项、接收和接收输出的请求
        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Lift(pb::api::LiftRequest {
                // 将选项转换为 Protobuf 格式
                opts: Some(opts.clone().into()),
                // 将接收转换为 Protobuf 格式
                receipt: Some(receipt.try_into()?),
                // 将接收输出请求转换为 Protobuf 格式
                receipt_out: Some(receipt_out.try_into()?),
            })),
        };
        // 发送 LiftRequest 消息给服务器
        conn.send(request)?;

        // 接收 LiftReply 消息
        let reply: pb::api::LiftReply = conn.recv()?;

        // 处理 LiftReply 消息
        let result = match reply.kind.ok_or(malformed_err())? {
            pb::api::lift_reply::Kind::Ok(result) => {
                // 将接收的字节数组解码为 SuccinctReceipt Protobuf 对象
                let receipt_bytes = result.receipt.ok_or(malformed_err())?.as_bytes()?;
                let receipt_pb = pb::core::SuccinctReceipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::lift_reply::Kind::Error(err) => Err(err.into()),
        };

        // 关闭连接并检查返回的代码
        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    /// 运行 join 程序，将两个 [SuccinctReceipt] 合并为一个。
    pub fn join(
        &self,
        opts: &ProverOpts,
        left_receipt: Asset,
        right_receipt: Asset,
        receipt_out: AssetRequest,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        // 使用连接器创建一个新的连接
        let mut conn = self.connect()?;

        // 创建一个 JoinRequest 消息，包含选项、左接收、右接收和接收输出的请求
        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Join(pb::api::JoinRequest {
                // 将选项转换为 Protobuf 格式
                opts: Some(opts.clone().into()),
                // 将左接收转换为 Protobuf 格式
                left_receipt: Some(left_receipt.try_into()?),
                // 将右接收转换为 Protobuf 格式
                right_receipt: Some(right_receipt.try_into()?),
                // 将接收输出请求转换为 Protobuf 格式
                receipt_out: Some(receipt_out.try_into()?),
            })),
        };
        // 发送 JoinRequest 消息给服务器
        conn.send(request)?;

        // 接收 JoinReply 消息
        let reply: pb::api::JoinReply = conn.recv()?;

        // 处理 JoinReply 消息
        let result = match reply.kind.ok_or(malformed_err())? {
            pb::api::join_reply::Kind::Ok(result) => {
                // 将接收的字节数组解码为 SuccinctReceipt Protobuf 对象
                let receipt_bytes = result.receipt.ok_or(malformed_err())?.as_bytes()?;
                let receipt_pb = pb::core::SuccinctReceipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::join_reply::Kind::Error(err) => Err(err.into()),
        };

        // 关闭连接并检查返回的代码
        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    /// 运行 resolve 程序，移除条件 [SuccinctReceipt] 中的假设。
    pub fn resolve(
        &self,
        opts: &ProverOpts,
        conditional_receipt: Asset,
        assumption_receipt: Asset,
        receipt_out: AssetRequest,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        // 使用连接器创建一个新的连接
        let mut conn = self.connect()?;

        // 创建一个 ResolveRequest 消息，包含选项、条件接收、假设接收和接收输出的请求
        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Resolve(
                pb::api::ResolveRequest {
                    // 将选项转换为 Protobuf 格式
                    opts: Some(opts.clone().into()),
                    // 将条件接收转换为 Protobuf ���式
                    conditional_receipt: Some(conditional_receipt.try_into()?),
                    // 将假设接收转换为 Protobuf 格式
                    assumption_receipt: Some(assumption_receipt.try_into()?),
                    // 将接收输出请求转换为 Protobuf 格式
                    receipt_out: Some(receipt_out.try_into()?),
                },
            )),
        };
        // 发送 ResolveRequest 消息给服务器
        conn.send(request)?;

        // 接收 ResolveReply 消息
        let reply: pb::api::ResolveReply = conn.recv()?;

        // 处理 ResolveReply 消息
        let result = match reply.kind.ok_or(malformed_err())? {
            pb::api::resolve_reply::Kind::Ok(result) => {
                // 将接收的字节数组解码为 SuccinctReceipt Protobuf 对象
                let receipt_bytes = result.receipt.ok_or(malformed_err())?.as_bytes()?;
                let receipt_pb = pb::core::SuccinctReceipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::resolve_reply::Kind::Error(err) => Err(err.into()),
        };

        // 关闭连接并检查返回的代码
        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    /// 证明递归接收的验证，使用 Poseidon254 哈希函数进行 FRI。
    pub fn identity_p254(
        &self,
        opts: &ProverOpts,
        receipt: Asset,
        receipt_out: AssetRequest,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        // 使用连接器创建一个新的连接
        let mut conn = self.connect()?;

        // 创建一个 IdentityP254Request 消息，包含选项、接收和接收输出的请求
        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::IdentityP254(
                pb::api::IdentityP254Request {
                    // 将选项转换为 Protobuf 格式
                    opts: Some(opts.clone().into()),
                    // 将接收转换为 Protobuf 格式
                    receipt: Some(receipt.try_into()?),
                    // 将接收输出请求转换为 Protobuf 格式
                    receipt_out: Some(receipt_out.try_into()?),
                },
            )),
        };
        // 发送 IdentityP254Request 消息给服务器
        conn.send(request)?;

        // 接收 IdentityP254Reply 消息
        let reply: pb::api::IdentityP254Reply = conn.recv()?;

        // 处理 IdentityP254Reply 消息
        let result = match reply.kind.ok_or(malformed_err())? {
            pb::api::identity_p254_reply::Kind::Ok(result) => {
                // 将接收的字节数组解码为 SuccinctReceipt Protobuf 对象
                let receipt_bytes = result.receipt.ok_or(malformed_err())?.as_bytes()?;
                let receipt_pb = pb::core::SuccinctReceipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::identity_p254_reply::Kind::Error(err) => Err(err.into()),
        };

        // 关闭连接并检查返回的代码
        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    /// 压缩 [Receipt]，使用更小的表示证明相同的计算。
    pub fn compress(
        &self,
        opts: &ProverOpts,
        receipt: Asset,
        receipt_out: AssetRequest,
    ) -> Result<Receipt> {
        // 使用连接器创建一个新的连接
        let mut conn = self.connect()?;

        // 创建一个 CompressRequest 消息，包含选项、接收和接收输出的请求
        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Compress(
                pb::api::CompressRequest {
                    // 将选项转换为 Protobuf 格式
                    opts: Some(opts.clone().into()),
                    // 将接收转换为 Protobuf 格式
                    receipt: Some(receipt.try_into()?),
                    // 将接收输出请求转换为 Protobuf 格式
                    receipt_out: Some(receipt_out.try_into()?),
                },
            )),
        };
        // 发送 CompressRequest 消息给服务器
        conn.send(request)?;

        // 接收 CompressReply 消息
        let reply: pb::api::CompressReply = conn.recv()?;

        // 处理 CompressReply 消息
        let result = match reply.kind.ok_or(malformed_err())? {
            pb::api::compress_reply::Kind::Ok(result) => {
                // 将接收的字节数组解码为 Receipt Protobuf 对象
                let receipt_bytes = result.receipt.ok_or(malformed_err())?.as_bytes()?;
                let receipt_pb = pb::core::Receipt::decode(receipt_bytes)?;
                receipt_pb.try_into()
            }
            pb::api::compress_reply::Kind::Error(err) => Err(err.into()),
        };

        // 关闭连接并检查返回的代码
        let code = conn.close()?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }

    /// 验证 [Receipt]。
    pub fn verify(&self, receipt: Asset, image_id: impl Into<Digest>) -> Result<()> {
        // 使用连接器创建一个新的连接
        let mut conn = self.connect().context("connect")?;
        let image_id = image_id.into();

        // 创建一个 VerifyRequest 消息，包含接收和图像 ID
        let request = pb::api::ServerRequest {
            kind: Some(pb::api::server_request::Kind::Verify(
                pb::api::VerifyRequest {
                    // 将接收转换为 Protobuf 格式
                    receipt: Some(receipt.try_into().context("convert receipt asset")?),
                    // 将图像 ID 转换为 Protobuf 格式
                    image_id: Some(image_id.into()),
                },
            )),
        };
        // 发送 VerifyRequest 消息给服务器
        conn.send(request).context("send")?;

        // 接收 GenericReply 消息
        let reply: pb::api::GenericReply = conn.recv().context("error from server")?;
        let result = match reply.kind.ok_or(malformed_err())? {
            pb::api::generic_reply::Kind::Ok(ok) => Ok(ok),
            pb::api::generic_reply::Kind::Error(err) => Err(err.into()),
        };

        // 关闭连接并检查返回的代码
        let code = conn.close().context("close")?;
        if code != 0 {
            bail!("Child finished with: {code}");
        }

        result
    }
    /*
    connect 函数的主要功能是建立与 zkVM 服务器的连接。具体步骤如下：
    创建连接：使用 self.connector.connect() 方法创建一个新的连接。
    发送客户端版本信息：获取客户端版本信息，并将其封装在 HelloRequest 消息中发送给服务器。
    接收服务器响应：接收服务器的响应消息 HelloReply，并检查服务器版本是否兼容。
    版本检查：根据客户端和服务器的版本信息，检查版本兼容性。如果不兼容，则返回错误。
    返回连接：如果一切正常，返回建立的连接对象。
    通过这些步骤，connect 函数确保客户端与服务器之间的通信可以顺利进行，并且版本兼容。
     */
    fn connect(&self) -> Result<ConnectionWrapper> {
        // 使用连接器创建一个新的连接
        let mut conn = self.connector.connect()?;

        // 获取客户端版本信息，如果获取失败则返回错误
        let client_version = get_version().map_err(|err| anyhow!(err))?;
        // 创建一个 HelloRequest 消息，包含客户端版本信息
        let request = pb::api::HelloRequest {
            version: Some(client_version.clone().into()),
        };
        // 发送 HelloRequest 消息给服务器
        conn.send(request)?;

        // 接收服务器的 HelloReply 消息
        let reply: pb::api::HelloReply = conn.recv()?;

        // 处理服务器的 HelloReply 消息
        match reply.kind.ok_or(malformed_err())? {
            // 如果���务器返回 Ok，则检查服务器版本
            pb::api::hello_reply::Kind::Ok(reply) => {
                // 获取服务器版本信息，如果获取失败则返回错误
                let server_version: semver::Version = reply
                    .version
                    .ok_or(malformed_err())?
                    .try_into()
                    .map_err(|err: semver::Error| anyhow!(err))?;

                // 根据是否兼容模式选择版本检查函数
                let version_check = if self.compat {
                    check_server_version_wide
                } else {
                    check_server_version
                };
                // 检查客户端和服务器版本是否兼容，如果不兼容��返回错误
                if !version_check(&client_version, &server_version) {
                    let msg = format!("incompatible server version: {server_version}");
                    tracing::warn!("{msg}");
                    bail!(msg);
                }
            }
            // 如果服务器返回 Error，则关闭连接并返回错误
            pb::api::hello_reply::Kind::Error(err) => {
                let code = conn.close()?;
                tracing::debug!("Child finished with: {code}");
                bail!(err);
            }
        }

        // 返回建立的连接对象
        Ok(conn)
    }

    fn make_execute_env(
        &self,
        env: &ExecutorEnv<'_>,
        binary: pb::api::Asset,
    ) -> Result<pb::api::ExecutorEnv> {
        Ok(pb::api::ExecutorEnv {
            binary: Some(binary),
            env_vars: env.env_vars.clone(),
            args: env.args.clone(),
            slice_ios: env.slice_io.borrow().inner.keys().cloned().collect(),
            read_fds: env.posix_io.borrow().read_fds(),
            write_fds: env.posix_io.borrow().write_fds(),
            segment_limit_po2: env.segment_limit_po2,
            session_limit: env.session_limit,
            trace_events: (!env.trace.is_empty()).then_some(()),
            pprof_out: env
                .pprof_out
                .as_ref()
                .map(|x| x.to_string_lossy().into())
                .unwrap_or_default(),
            assumptions: env
                .assumptions
                .borrow()
                .cached
                .iter()
                .map(|a| {
                    Ok(match a {
                        AssumptionReceipt::Proven(inner) => pb::api::AssumptionReceipt {
                            kind: Some(pb::api::assumption_receipt::Kind::Proven(
                                Asset::Inline(
                                    pb::core::InnerReceipt::from(inner.clone())
                                        .encode_to_vec()
                                        .into(),
                                )
                                    .try_into()?,
                            )),
                        },
                        AssumptionReceipt::Unresolved(assumption) => pb::api::AssumptionReceipt {
                            kind: Some(pb::api::assumption_receipt::Kind::Unresolved(
                                Asset::Inline(
                                    pb::core::Assumption::from(assumption.clone())
                                        .encode_to_vec()
                                        .into(),
                                )
                                    .try_into()?,
                            )),
                        },
                    })
                })
                .collect::<Result<_>>()?,
            segment_path: env
                .segment_path
                .as_ref()
                .map(|x| x.path().to_string_lossy().into())
                .unwrap_or_default(),
        })
    }

    fn execute_handler<F>(
        &self,
        segment_callback: F,
        conn: &mut ConnectionWrapper,
        env: &ExecutorEnv<'_>,
    ) -> Result<SessionInfo>
    where
        F: FnMut(SegmentInfo, Asset) -> Result<()>,
    {
        let mut segment_callback = segment_callback;
        let mut segments = Vec::new();
        loop {
            let reply: pb::api::ServerReply = conn.recv()?;
            // tracing::trace!("rx: {reply:?}");

            match reply.kind.ok_or(malformed_err())? {
                pb::api::server_reply::Kind::Ok(request) => {
                    match request.kind.ok_or(malformed_err())? {
                        pb::api::client_callback::Kind::Io(io) => {
                            let msg: pb::api::OnIoReply = self.on_io(env, io).into();
                            // tracing::trace!("tx: {msg:?}");
                            conn.send(msg)?;
                        }
                        pb::api::client_callback::Kind::SegmentDone(segment) => {
                            let reply: pb::api::GenericReply = segment
                                .segment
                                .map_or_else(
                                    || Err(malformed_err()),
                                    |segment| {
                                        let asset =
                                            segment.segment.ok_or(malformed_err())?.try_into()?;
                                        let info = SegmentInfo {
                                            po2: segment.po2,
                                            cycles: segment.cycles,
                                        };
                                        segments.push(info.clone());
                                        segment_callback(info, asset)
                                    },
                                )
                                .into();
                            // tracing::trace!("tx: {reply:?}");
                            conn.send(reply)?;
                        }
                        pb::api::client_callback::Kind::SessionDone(session) => {
                            return match session.session {
                                Some(session) => Ok(SessionInfo {
                                    segments,
                                    journal: Journal::new(session.journal),
                                    exit_code: session
                                        .exit_code
                                        .ok_or(malformed_err())?
                                        .try_into()?,
                                }),
                                None => Err(malformed_err()),
                            }
                        }
                        pb::api::client_callback::Kind::ProveDone(_) => {
                            return Err(anyhow!("Illegal client callback"))
                        }
                    }
                }
                pb::api::server_reply::Kind::Error(err) => return Err(err.into()),
            }
        }
    }

    fn prove_handler(
        &self,
        conn: &mut ConnectionWrapper,
        env: &ExecutorEnv<'_>,
    ) -> Result<pb::api::Asset> {
        loop {
            // 从连接中接收服务器的回复消息
            let reply: pb::api::ServerReply = conn.recv()?;
            // tracing::trace!("rx: {reply:?}");

            // 处理服务器的回复消息
            match reply.kind.ok_or(malformed_err())? {
                // 如果服务器返回 Ok，则处理客户端回调
                pb::api::server_reply::Kind::Ok(request) => {
                    match request.kind.ok_or(malformed_err())? {
                        // 处理 I/O 请求
                        pb::api::client_callback::Kind::Io(io) => {
                            // 调用 on_io 方法处理 I/O 请求，并将结果转换为 OnIoReply 消息
                            let msg: pb::api::OnIoReply = self.on_io(env, io).into();
                            // tracing::trace!("tx: {msg:?}");
                            // 将 OnIoReply 消息发送回服务器
                            conn.send(msg)?;
                        }
                        // 处理 SegmentDone 回调，返回错误，因为这是非法的客户端回调
                        pb::api::client_callback::Kind::SegmentDone(_) => {
                            return Err(anyhow!("Illegal client callback"))
                        }
                        // 处理 SessionDone 回调，返回错误，因为这是非法的客户端回调
                        pb::api::client_callback::Kind::SessionDone(_) => {
                            return Err(anyhow!("Illegal client callback"))
                        }
                        // 处理 ProveDone 回调，返回证明信息
                        pb::api::client_callback::Kind::ProveDone(done) => {
                            return done.prove_info.ok_or(malformed_err())
                        }
                    }
                }
                // 如果服务器返回 Error，则返回错误
                pb::api::server_reply::Kind::Error(err) => return Err(err.into()),
            }
        }
    }

    fn on_io(&self, env: &ExecutorEnv<'_>, request: pb::api::OnIoRequest) -> Result<Bytes> {
        // 处理 I/O 请求，根据请求的类型调用相应的方法
        match request.kind.ok_or(malformed_err())? {
            // 处理 POSIX I/O 请求
            pb::api::on_io_request::Kind::Posix(posix) => {
                let cmd = posix.cmd.ok_or(malformed_err())?;
                match cmd.kind.ok_or(malformed_err())? {
                    // 处理 POSIX 读请求
                    pb::api::posix_cmd::Kind::Read(nread) => {
                        self.on_posix_read(env, posix.fd, nread as usize)
                    }
                    // 处理 POSIX 写请求
                    pb::api::posix_cmd::Kind::Write(from_guest) => {
                        self.on_posix_write(env, posix.fd, from_guest.into())?;
                        Ok(Bytes::new())
                    }
                }
            }
            // 处理 Slice I/O 请求
            pb::api::on_io_request::Kind::Slice(slice_io) => {
                self.on_slice(env, &slice_io.name, slice_io.from_guest.into())
            }
            // 处理 Trace 事件
            pb::api::on_io_request::Kind::Trace(event) => {
                self.on_trace(env, event)?;
                Ok(Bytes::new())
            }
        }
    }

    fn on_posix_read(&self, env: &ExecutorEnv<'_>, fd: u32, nread: usize) -> Result<Bytes> {
        tracing::debug!("on_posix_read: {fd}, {nread}");
        // 创建一个缓冲区，用于存储从主机读取的数据
        let mut from_host = vec![0; nread];
        let posix_io = env.posix_io.borrow();
        // 获取文件描述符对应的读取器
        let reader = posix_io.get_reader(fd)?;
        // 从读取器中读取数据到缓冲区
        let nread = reader.borrow_mut().read(&mut from_host)?;
        // 将读取的数据转换为字节数组并返回
        let slice = from_host[..nread].to_vec();
        Ok(slice.into())
    }

    fn on_posix_write(&self, env: &ExecutorEnv<'_>, fd: u32, from_guest: Bytes) -> Result<()> {
        tracing::debug!("on_posix_write: {fd}");
        let posix_io = env.posix_io.borrow();
        // 获取文件描述符对应的写入器
        let writer = posix_io.get_writer(fd)?;
        // 将来自客户端的数据写入到写入器中
        writer.borrow_mut().write_all(&from_guest)?;
        Ok(())
    }

    fn on_slice(&self, env: &ExecutorEnv<'_>, name: &str, from_guest: Bytes) -> Result<Bytes> {
        let table = env.slice_io.borrow();
        // 获取指定名称的 Slice I/O 处理器
        let slice_io = table
            .inner
            .get(name)
            .ok_or(anyhow!("Unknown I/O channel name: {name}"))?;
        // 调用 Slice I/O 处理器处理 I/O 请求，并返回结果
        let result = slice_io.borrow_mut().handle_io(name, from_guest)?;
        Ok(result)
    }

    fn on_trace(&self, env: &ExecutorEnv<'_>, event: pb::api::TraceEvent) -> Result<()> {
        // 遍历所有的 Trace 回调函数，并调用它们处理 Trace 事件
        for trace_callback in env.trace.iter() {
            trace_callback
                .borrow_mut()
                .trace_callback(event.clone().try_into()?)?;
        }
        Ok(())
    }
}

impl From<Result<Bytes, anyhow::Error>> for pb::api::OnIoReply {
    fn from(result: Result<Bytes, anyhow::Error>) -> Self {
        Self {
            kind: Some(match result {
                Ok(bytes) => pb::api::on_io_reply::Kind::Ok(bytes.into()),
                Err(err) => pb::api::on_io_reply::Kind::Error(err.into()),
            }),
        }
    }
}

pub(crate) fn check_server_version(requested: &semver::Version, server: &semver::Version) -> bool {
    if requested.pre.is_empty() {
        requested.major == server.major && requested.minor == server.minor
    } else {
        requested == server
    }
}

pub(crate) fn check_server_version_wide(
    requested: &semver::Version,
    server: &semver::Version,
) -> bool {
    requested.major == server.major
}

#[cfg(test)]
mod tests {
    use semver::Version;

    use super::{check_server_version, check_server_version_wide};

    #[test]
    fn check_version() {
        fn test(requested: &str, server: &str) -> bool {
            check_server_version(
                &Version::parse(requested).unwrap(),
                &Version::parse(server).unwrap(),
            )
        }

        assert!(test("0.18.0", "0.18.0"));
        assert!(test("0.18.0", "0.18.1"));
        assert!(test("0.18.1", "0.18.1"));
        assert!(test("0.18.1", "0.18.2"));
        assert!(test("0.18.1", "0.18.0"));
        assert!(!test("0.18.0", "0.19.0"));

        assert!(test("1.0.0", "1.0.0"));
        assert!(test("1.0.0", "1.0.1"));
        assert!(test("1.1.0", "1.1.0"));
        assert!(test("1.1.0", "1.1.1"));
        assert!(!test("1.0.0", "0.18.0"));
        assert!(!test("1.0.0", "2.0.0"));
        assert!(!test("1.1.0", "1.0.0"));
        assert!(test("1.0.3", "1.0.1"));

        assert!(test("0.19.0-alpha.1", "0.19.0-alpha.1"));
        assert!(!test("0.19.0-alpha.1", "0.19.0-alpha.2"));
    }

    #[test]
    fn check_wide_version() {
        fn test(requested: &str, server: &str) -> bool {
            check_server_version_wide(
                &Version::parse(requested).unwrap(),
                &Version::parse(server).unwrap(),
            )
        }

        assert!(test("0.1.0", "0.1.0"));
        assert!(test("0.1.0", "0.1.1"));
        assert!(test("0.1.0", "0.2.0"));
        assert!(test("0.1.0-rc.1", "0.2.0"));
        assert!(test("1.1.0", "1.0.0"));
        assert!(!test("1.0.0", "2.0.0"));
    }
}
