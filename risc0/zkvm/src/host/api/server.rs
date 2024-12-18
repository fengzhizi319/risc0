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

use std::{
    error::Error as StdError,
    io::{BufReader, Error as IoError, ErrorKind as IoErrorKind, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use prost::Message;
use risc0_zkp::core::digest::Digest;

use super::{malformed_err, path_to_string, pb, ConnectionWrapper, Connector, TcpConnector};
use crate::{
    get_prover_server, get_version,
    host::{
        client::{
            env::{CoprocessorCallback, ProveZkrRequest},
            slice_io::SliceIo,
        },
        server::session::NullSegmentRef,
    },
    prove_zkr,
    recursion::identity_p254,
    AssetRequest, Assumption, ExecutorEnv, ExecutorImpl, InnerAssumptionReceipt, ProverOpts,
    Receipt, ReceiptClaim, Segment, SegmentReceipt, Session, SuccinctReceipt, TraceCallback,
    TraceEvent, VerifierContext,
};

/// A server implementation for handling requests by clients of the zkVM.
pub struct Server {
    connector: Box<dyn Connector>,
}
struct PosixIoProxy {
    fd: u32,
    conn: ConnectionWrapper,
}

impl PosixIoProxy {
    fn new(fd: u32, conn: ConnectionWrapper) -> Self {
        PosixIoProxy { fd, conn }
    }
}

impl Read for PosixIoProxy {
    fn read(&mut self, to_guest: &mut [u8]) -> std::io::Result<usize> {
        let nread = to_guest.len().try_into().map_io_err()?;
        let request = pb::api::ServerReply {
            kind: Some(pb::api::server_reply::Kind::Ok(pb::api::ClientCallback {
                kind: Some(pb::api::client_callback::Kind::Io(pb::api::OnIoRequest {
                    kind: Some(pb::api::on_io_request::Kind::Posix(pb::api::PosixIo {
                        fd: self.fd,
                        cmd: Some(pb::api::PosixCmd {
                            kind: Some(pb::api::posix_cmd::Kind::Read(nread)),
                        }),
                    })),
                })),
            })),
        };

        tracing::trace!("tx: {request:?}");
        let reply: pb::api::OnIoReply = self.conn.send_recv(request).map_io_err()?;
        tracing::trace!("rx: {reply:?}");

        let kind = reply.kind.ok_or("Malformed message").map_io_err()?;
        match kind {
            pb::api::on_io_reply::Kind::Ok(bytes) => {
                let (head, _) = to_guest.split_at_mut(bytes.len());
                head.copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            pb::api::on_io_reply::Kind::Error(err) => Err(err.into()),
        }
    }
}

impl Write for PosixIoProxy {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let request = pb::api::ServerReply {
            kind: Some(pb::api::server_reply::Kind::Ok(pb::api::ClientCallback {
                kind: Some(pb::api::client_callback::Kind::Io(pb::api::OnIoRequest {
                    kind: Some(pb::api::on_io_request::Kind::Posix(pb::api::PosixIo {
                        fd: self.fd,
                        cmd: Some(pb::api::PosixCmd {
                            kind: Some(pb::api::posix_cmd::Kind::Write(buf.into())),
                        }),
                    })),
                })),
            })),
        };

        tracing::trace!("tx: {request:?}");
        let reply: pb::api::OnIoReply = self.conn.send_recv(request).map_io_err()?;
        tracing::trace!("rx: {reply:?}");

        let kind = reply.kind.ok_or("Malformed message").map_io_err()?;
        match kind {
            pb::api::on_io_reply::Kind::Ok(_) => Ok(buf.len()),
            pb::api::on_io_reply::Kind::Error(err) => Err(err.into()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct SliceIoProxy {
    conn: ConnectionWrapper,
}

impl SliceIoProxy {
    fn new(conn: ConnectionWrapper) -> Self {
        Self { conn }
    }
}

impl SliceIo for SliceIoProxy {
    fn handle_io(&mut self, syscall: &str, from_guest: Bytes) -> Result<Bytes> {
        let request = pb::api::ServerReply {
            kind: Some(pb::api::server_reply::Kind::Ok(pb::api::ClientCallback {
                kind: Some(pb::api::client_callback::Kind::Io(pb::api::OnIoRequest {
                    kind: Some(pb::api::on_io_request::Kind::Slice(pb::api::SliceIo {
                        name: syscall.to_string(),
                        from_guest: from_guest.into(),
                    })),
                })),
            })),
        };
        tracing::trace!("tx: {request:?}");
        let reply: pb::api::OnIoReply = self.conn.send_recv(request).map_io_err()?;
        tracing::trace!("rx: {reply:?}");

        let kind = reply.kind.ok_or("Malformed message").map_io_err()?;
        match kind {
            pb::api::on_io_reply::Kind::Ok(buf) => Ok(buf.into()),
            pb::api::on_io_reply::Kind::Error(err) => Err(err.into()),
        }
    }
}

struct TraceProxy {
    conn: ConnectionWrapper,
}

impl TraceProxy {
    fn new(conn: ConnectionWrapper) -> Self {
        Self { conn }
    }
}

impl TraceCallback for TraceProxy {
    fn trace_callback(&mut self, event: TraceEvent) -> Result<()> {
        let request = pb::api::ServerReply {
            kind: Some(pb::api::server_reply::Kind::Ok(pb::api::ClientCallback {
                kind: Some(pb::api::client_callback::Kind::Io(pb::api::OnIoRequest {
                    kind: Some(pb::api::on_io_request::Kind::Trace(event.into())),
                })),
            })),
        };
        tracing::trace!("tx: {request:?}");
        let reply: pb::api::OnIoReply = self.conn.send_recv(request).map_io_err()?;
        tracing::trace!("rx: {reply:?}");

        let kind = reply.kind.ok_or("Malformed message").map_io_err()?;
        match kind {
            pb::api::on_io_reply::Kind::Ok(_) => Ok(()),
            pb::api::on_io_reply::Kind::Error(err) => Err(err.into()),
        }
    }
}

struct CoprocessorProxy {
    conn: ConnectionWrapper,
}

impl CoprocessorProxy {
    fn new(conn: ConnectionWrapper) -> Self {
        Self { conn }
    }
}

impl CoprocessorCallback for CoprocessorProxy {
    /// 处理 ZKR 证明请求的系统调用函数。这个函数实现了一个系统调用，
    /// 用于处理 ZKR（零知识证明）请求。它将请求发送到连接，并处理响应
    fn prove_zkr(&mut self, proof_request: ProveZkrRequest) -> Result<()> {
        // 构建服务器回复消息
        let request = pb::api::ServerReply {
            kind: Some(pb::api::server_reply::Kind::Ok(pb::api::ClientCallback {
                kind: Some(pb::api::client_callback::Kind::Io(pb::api::OnIoRequest {
                    kind: Some(pb::api::on_io_request::Kind::Coprocessor(
                        pb::api::CoprocessorRequest {
                            kind: Some(pb::api::coprocessor_request::Kind::ProveZkr({
                                pb::api::ProveZkrRequest {
                                    claim_digest: Some(proof_request.claim_digest.into()),
                                    control_id: Some(proof_request.control_id.into()),
                                    input: proof_request.input,
                                    receipt_out: None,
                                }
                            })),
                        },
                    )),
                })),
            })),
        };

        // 记录发送的消息
        tracing::trace!("tx: {request:?}");

        // 发送请求并接收回复
        let reply: pb::api::OnIoReply = self.conn.send_recv(request).map_io_err()?;

        // 记录接收的消息
        tracing::trace!("rx: {reply:?}");

        // 检查回复的类型
        let kind = reply.kind.ok_or("Malformed message").map_io_err()?;
        match kind {
            // 如果回复是 Ok，则返回成功
            pb::api::on_io_reply::Kind::Ok(_) => Ok(()),
            // 如果回复是错误，则返回错误
            pb::api::on_io_reply::Kind::Error(err) => Err(err.into()),
        }
    }
}

impl Server {
    /// Construct a new [Server] with the specified [Connector].
    pub fn new(connector: Box<dyn Connector>) -> Self {
        Self { connector }
    }

    /// Construct a new [Server] which will connect to the specified TCP/IP
    /// address.
    pub fn new_tcp<A: AsRef<str>>(addr: A) -> Self {
        let connector = TcpConnector::new(addr.as_ref());
        Self::new(Box::new(connector))
    }

    /// Start the [Server] and run until all requests are complete.
    pub fn run(&self) -> Result<()> {
        tracing::debug!("connect");
        let mut conn = self.connector.connect()?;

        let server_version = get_version().map_err(|err| anyhow!(err))?;

        let request: pb::api::HelloRequest = conn.recv()?;
        tracing::trace!("rx: {request:?}");

        let client_version: semver::Version = request
            .version
            .ok_or(malformed_err())?
            .try_into()
            .map_err(|err: semver::Error| anyhow!(err))?;

        #[cfg(not(feature = "r0vm-ver-compat"))]
        let check_client_func = check_client_version;
        #[cfg(feature = "r0vm-ver-compat")]
        let check_client_func = check_client_version_compat;

        if !check_client_func(&client_version, &server_version) {
            let msg = format!(
                "incompatible client version: {client_version}, server version: {server_version}"
            );
            tracing::debug!("{msg}");
            bail!(msg);
        }

        let reply = pb::api::HelloReply {
            kind: Some(pb::api::hello_reply::Kind::Ok(pb::api::HelloResult {
                version: Some(server_version.into()),
            })),
        };
        tracing::trace!("tx: {reply:?}");
        let request: pb::api::ServerRequest = conn.send_recv(reply)?;
        tracing::trace!("rx: {request:?}");

        match request.kind.ok_or(malformed_err())? {
            pb::api::server_request::Kind::Prove(request) => self.on_prove(conn, request),
            pb::api::server_request::Kind::Execute(request) => self.on_execute(conn, request),
            pb::api::server_request::Kind::ProveSegment(request) => {
                self.on_prove_segment(conn, request)
            }
            pb::api::server_request::Kind::Lift(request) => self.on_lift(conn, request),
            pb::api::server_request::Kind::Join(request) => self.on_join(conn, request),
            pb::api::server_request::Kind::Resolve(request) => self.on_resolve(conn, request),
            pb::api::server_request::Kind::IdentityP254(request) => {
                self.on_identity_p254(conn, request)
            }
            pb::api::server_request::Kind::Compress(request) => self.on_compress(conn, request),
            pb::api::server_request::Kind::Verify(request) => self.on_verify(conn, request),
            pb::api::server_request::Kind::ProveZkr(request) => self.on_prove_zkr(conn, request),
        }
    }

    fn on_execute(
        &self,
        mut conn: ConnectionWrapper,
        request: pb::api::ExecuteRequest,
    ) -> Result<()> {
        fn inner(
            conn: &mut ConnectionWrapper,
            request: pb::api::ExecuteRequest,
        ) -> Result<pb::api::ServerReply> {
            let env_request = request.env.ok_or(malformed_err())?;
            let env = build_env(conn, &env_request)?;

            let binary = env_request.binary.ok_or(malformed_err())?;

            let segments_out = request.segments_out.ok_or(malformed_err())?;
            let bytes = binary.as_bytes()?;
            let mut exec = ExecutorImpl::from_elf(env, &bytes)?;

            let session = match AssetRequest::try_from(segments_out.clone())? {
                #[cfg(feature = "redis")]
                AssetRequest::Redis(params) => execute_redis(conn, &mut exec, params)?,
                _ => execute_default(conn, &mut exec, &segments_out)?,
            };

            let receipt_claim = session.claim()?;
            Ok(pb::api::ServerReply {
                kind: Some(pb::api::server_reply::Kind::Ok(pb::api::ClientCallback {
                    kind: Some(pb::api::client_callback::Kind::SessionDone(
                        pb::api::OnSessionDone {
                            session: Some(pb::api::SessionInfo {
                                segments: session.segments.len().try_into()?,
                                journal: session.journal.unwrap_or_default().bytes,
                                exit_code: Some(session.exit_code.into()),
                                receipt_claim: Some(pb::api::Asset::from_bytes(
                                    &pb::api::AssetRequest {
                                        kind: Some(pb::api::asset_request::Kind::Inline(())),
                                    },
                                    pb::core::ReceiptClaim::from(receipt_claim)
                                        .encode_to_vec()
                                        .into(),
                                    "session_info.claim",
                                )?),
                            }),
                        },
                    )),
                })),
            })
        }

        let msg = inner(&mut conn, request).unwrap_or_else(|err| pb::api::ServerReply {
            kind: Some(pb::api::server_reply::Kind::Error(pb::api::GenericError {
                reason: err.to_string(),
            })),
        });

        tracing::trace!("tx: {msg:?}");
        conn.send(msg)
    }

    fn on_prove(&self, mut conn: ConnectionWrapper, request: pb::api::ProveRequest) -> Result<()> {
        // 内部函数，用于处理证明请求
        fn inner(
            conn: &mut ConnectionWrapper,
            request: pb::api::ProveRequest,
        ) -> Result<pb::api::ServerReply> {
            // 获取并解析执行环境请求
            let env_request = request.env.ok_or(malformed_err())?;
            let env = build_env(conn, &env_request)?;

            // 获取并解析二进制数据
            let binary = env_request.binary.ok_or(malformed_err())?;
            let bytes = binary.as_bytes()?;

            // 获取并解析证明选项
            let opts: ProverOpts = request.opts.ok_or(malformed_err())?.try_into()?;
            // 获取证明服务器实例
            let prover = get_prover_server(&opts)?;
            // 创建验证上下文
            let ctx = VerifierContext::default();
            // 使用上下文和二进制数据进行证明
            let prove_info = prover.prove_with_ctx(env, &ctx, &bytes)?;

            // 将证明信息转换为 Protobuf 格式
            let prove_info: pb::core::ProveInfo = prove_info.into();
            let prove_info_bytes = prove_info.encode_to_vec();
            // 创建资产对象，用于存储证明信息
            let asset = pb::api::Asset::from_bytes(
                &request.receipt_out.ok_or(malformed_err())?,
                prove_info_bytes.into(),
                "prove_info.zkp",
            )?;

            // 返回成功的服务器回复，包含证明完成的回调
            Ok(pb::api::ServerReply {
                kind: Some(pb::api::server_reply::Kind::Ok(pb::api::ClientCallback {
                    kind: Some(pb::api::client_callback::Kind::ProveDone(
                        pb::api::OnProveDone {
                            prove_info: Some(asset),
                        },
                    )),
                })),
            })
        }

        // 调用内部函数处理请求，并处理可能的错误
        let msg = inner(&mut conn, request).unwrap_or_else(|err| pb::api::ServerReply {
            kind: Some(pb::api::server_reply::Kind::Error(pb::api::GenericError {
                reason: err.to_string(),
            })),
        });

        // 记录发送的消息并发送回复
        tracing::trace!("tx: {msg:?}");
        conn.send(msg)
    }

    fn on_prove_segment(
        &self,
        mut conn: ConnectionWrapper,
        request: pb::api::ProveSegmentRequest,
    ) -> Result<()> {
        // 内部函数，用于处理证明段请求
        fn inner(request: pb::api::ProveSegmentRequest) -> Result<pb::api::ProveSegmentReply> {
            // 获取并解析证明选项
            let opts: ProverOpts = request.opts.ok_or(malformed_err())?.try_into()?;
            // 获取并解析段数据
            let segment_bytes = request.segment.ok_or(malformed_err())?.as_bytes()?;
            let segment: Segment = bincode::deserialize(&segment_bytes)?;

            // 获取证明服务器实例
            let prover = get_prover_server(&opts)?;
            // 创建验证上下文
            let ctx = VerifierContext::default();
            // 使用上下文和段数据进行证明
            let receipt = prover.prove_segment(&ctx, &segment)?;

            // 将证明回执转换为 Protobuf 格式
            let receipt_pb: pb::core::SegmentReceipt = receipt.into();
            let receipt_bytes = receipt_pb.encode_to_vec();
            // 创建资产对象，用于存储证明回执
            let asset = pb::api::Asset::from_bytes(
                &request.receipt_out.ok_or(malformed_err())?,
                receipt_bytes.into(),
                "receipt.zkp",
            )?;

            // 返回成功的证明段回复
            Ok(pb::api::ProveSegmentReply {
                kind: Some(pb::api::prove_segment_reply::Kind::Ok(
                    pb::api::ProveSegmentResult {
                        receipt: Some(asset),
                    },
                )),
            })
        }

        // 调用内部函数处理请求，并处理可能的错误
        let msg = inner(request).unwrap_or_else(|err| pb::api::ProveSegmentReply {
            kind: Some(pb::api::prove_segment_reply::Kind::Error(
                pb::api::GenericError {
                    reason: err.to_string(),
                },
            )),
        });

        // 记录发送的消息并发送回复
        tracing::trace!("tx: {msg:?}");
        conn.send(msg)
    }

    fn on_prove_zkr(
        &self,
        mut conn: ConnectionWrapper,
        request: pb::api::ProveZkrRequest,
    ) -> Result<()> {
        // 内部函数，用于处理 ZKR 证明请求
        fn inner(request: pb::api::ProveZkrRequest) -> Result<pb::api::ProveZkrReply> {
            // 获取并解析控制 ID
            let control_id = request.control_id.ok_or(malformed_err())?.try_into()?;
            // 使用控制 ID 和输入数据进行 ZKR 证明
            let receipt = prove_zkr(&control_id, &request.input)?;

            // 将证明回执转换为 Protobuf 格式
            let receipt_pb: pb::core::SuccinctReceipt = receipt.into();
            let receipt_bytes = receipt_pb.encode_to_vec();
            // 创建资产对象，用于存储证明回执
            let asset = pb::api::Asset::from_bytes(
                &request.receipt_out.ok_or(malformed_err())?,
                receipt_bytes.into(),
                "receipt.zkp",
            )?;

            // 返回成功的 ZKR 证明回复
            Ok(pb::api::ProveZkrReply {
                kind: Some(pb::api::prove_zkr_reply::Kind::Ok(
                    pb::api::ProveZkrResult {
                        receipt: Some(asset),
                    },
                )),
            })
        }

        // 调用内部函数处理请求，并处理可能的错误
        let msg = inner(request).unwrap_or_else(|err| pb::api::ProveZkrReply {
            kind: Some(pb::api::prove_zkr_reply::Kind::Error(
                pb::api::GenericError {
                    reason: err.to_string(),
                },
            )),
        });

        // 记录发送的消息并发送回复
        tracing::trace!("tx: {msg:?}");
        conn.send(msg)
    }

    fn on_lift(&self, mut conn: ConnectionWrapper, request: pb::api::LiftRequest) -> Result<()> {
        // 内部函数，用于处理 Lift 请求
        fn inner(request: pb::api::LiftRequest) -> Result<pb::api::LiftReply> {
            // 获取并解析证明选项
            let opts: ProverOpts = request.opts.ok_or(malformed_err())?.try_into()?;
            // 获取并解析回执数据
            let receipt_bytes = request.receipt.ok_or(malformed_err())?.as_bytes()?;
            let segment_receipt: SegmentReceipt = bincode::deserialize(&receipt_bytes)?;

            // 获取证明服务器实例
            let prover = get_prover_server(&opts)?;
            // 使用段回执进行 Lift 操作
            let receipt = prover.lift(&segment_receipt)?;

            // 将 Lift 结果转换为 Protobuf 格式
            let succinct_receipt_pb: pb::core::SuccinctReceipt = receipt.into();
            let succinct_receipt_bytes = succinct_receipt_pb.encode_to_vec();
            // 创建资产对象，用于存储 Lift 结果
            let asset = pb::api::Asset::from_bytes(
                &request.receipt_out.ok_or(malformed_err())?,
                succinct_receipt_bytes.into(),
                "receipt.zkp",
            )?;

            // 返回成功的 Lift 回复
            Ok(pb::api::LiftReply {
                kind: Some(pb::api::lift_reply::Kind::Ok(pb::api::LiftResult {
                    receipt: Some(asset),
                })),
            })
        }

        // 调用内部函数处理请求，并处理可能的错误
        let msg = inner(request).unwrap_or_else(|err| pb::api::LiftReply {
            kind: Some(pb::api::lift_reply::Kind::Error(pb::api::GenericError {
                reason: err.to_string(),
            })),
        });

        // 记录发送的消息并发送回复
        conn.send(msg)
    }

    fn on_join(&self, mut conn: ConnectionWrapper, request: pb::api::JoinRequest) -> Result<()> {
        // 内部函数，用于处理 Join 请求
        fn inner(request: pb::api::JoinRequest) -> Result<pb::api::JoinReply> {
            // 获取并解析证明选项
            let opts: ProverOpts = request.opts.ok_or(malformed_err())?.try_into()?;
            // 获取并解析左侧回执数据
            let left_receipt_bytes = request.left_receipt.ok_or(malformed_err())?.as_bytes()?;
            let left_succinct_receipt: SuccinctReceipt<ReceiptClaim> =
                bincode::deserialize(&left_receipt_bytes)?;
            // 获取并解析右侧回执数据
            let right_receipt_bytes = request.right_receipt.ok_or(malformed_err())?.as_bytes()?;
            let right_succinct_receipt: SuccinctReceipt<ReceiptClaim> =
                bincode::deserialize(&right_receipt_bytes)?;

            // 获取证明服务器实例
            let prover = get_prover_server(&opts)?;
            // 使用左右回执进行 Join 操作
            let receipt = prover.join(&left_succinct_receipt, &right_succinct_receipt)?;

            // 将 Join 结果转换为 Protobuf 格式
            let succinct_receipt_pb: pb::core::SuccinctReceipt = receipt.into();
            let succinct_receipt_bytes = succinct_receipt_pb.encode_to_vec();
            // 创建资产对象，用于存储 Join 结果
            let asset = pb::api::Asset::from_bytes(
                &request.receipt_out.ok_or(malformed_err())?,
                succinct_receipt_bytes.into(),
                "receipt.zkp",
            )?;

            // 返回成功的 Join 回复
            Ok(pb::api::JoinReply {
                kind: Some(pb::api::join_reply::Kind::Ok(pb::api::JoinResult {
                    receipt: Some(asset),
                })),
            })
        }

        // 调用内部函数处理请求，并处理可能的错误
        let msg = inner(request).unwrap_or_else(|err| pb::api::JoinReply {
            kind: Some(pb::api::join_reply::Kind::Error(pb::api::GenericError {
                reason: err.to_string(),
            })),
        });

        // 记录发送的消息并发送回复
        conn.send(msg)
    }

    fn on_resolve(
        &self,
        mut conn: ConnectionWrapper,
        request: pb::api::ResolveRequest,
    ) -> Result<()> {
        // 内部函数，用于处理 Resolve 请求
        fn inner(request: pb::api::ResolveRequest) -> Result<pb::api::ResolveReply> {
            // 获取并解析证明选项
            let opts: ProverOpts = request.opts.ok_or(malformed_err())?.try_into()?;
            // 获取并解析条件回执数据
            let conditional_receipt_bytes = request
                .conditional_receipt
                .ok_or(malformed_err())?
                .as_bytes()?;
            let conditional_succinct_receipt: SuccinctReceipt<ReceiptClaim> =
                bincode::deserialize(&conditional_receipt_bytes)?;
            // 获取并解析假设回执数据
            let assumption_receipt_bytes = request
                .assumption_receipt
                .ok_or(malformed_err())?
                .as_bytes()?;
            let assumption_succinct_receipt: SuccinctReceipt<ReceiptClaim> =
                bincode::deserialize(&assumption_receipt_bytes)?;

            // 获取证明服务器实例
            let prover = get_prover_server(&opts)?;
            // 使用条件回执和假设回执进行 Resolve 操作
            let receipt = prover.resolve(
                &conditional_succinct_receipt,
                &assumption_succinct_receipt.into_unknown(),
            )?;

            // 将 Resolve 结果转换为 Protobuf 格式
            let succinct_receipt_pb: pb::core::SuccinctReceipt = receipt.into();
            let succinct_receipt_bytes = succinct_receipt_pb.encode_to_vec();
            // 创建资产对象，用于存储 Resolve 结果
            let asset = pb::api::Asset::from_bytes(
                &request.receipt_out.ok_or(malformed_err())?,
                succinct_receipt_bytes.into(),
                "receipt.zkp",
            )?;

            // 返回成功的 Resolve 回复
            Ok(pb::api::ResolveReply {
                kind: Some(pb::api::resolve_reply::Kind::Ok(pb::api::ResolveResult {
                    receipt: Some(asset),
                })),
            })
        }

        // 调用内部函数处理请求，并处理可能的错误
        let msg = inner(request).unwrap_or_else(|err| pb::api::ResolveReply {
            kind: Some(pb::api::resolve_reply::Kind::Error(pb::api::GenericError {
                reason: err.to_string(),
            })),
        });

        // 记录发送的消息并发送回复
        conn.send(msg)
    }

    fn on_identity_p254(
        &self,
        mut conn: ConnectionWrapper,
        request: pb::api::IdentityP254Request,
    ) -> Result<()> {
        // 内部函数，用于处理 IdentityP254 请求
        fn inner(request: pb::api::IdentityP254Request) -> Result<pb::api::IdentityP254Reply> {
            // 获取并解析回执数据
            let receipt_bytes = request.receipt.ok_or(malformed_err())?.as_bytes()?;
            let succinct_receipt: SuccinctReceipt<ReceiptClaim> =
                bincode::deserialize(&receipt_bytes)?;

            // 使用 P254 算法进行身份验证
            let receipt = identity_p254(&succinct_receipt)?;
            // 将身份验证结果转换为 Protobuf 格式
            let succinct_receipt_pb: pb::core::SuccinctReceipt = receipt.into();
            let succinct_receipt_bytes = succinct_receipt_pb.encode_to_vec();
            // 创建资产对象，用于存储身份验证结果
            let asset = pb::api::Asset::from_bytes(
                &request.receipt_out.ok_or(malformed_err())?,
                succinct_receipt_bytes.into(),
                "receipt.zkp",
            )?;

            // 返回成功的 IdentityP254 回复
            Ok(pb::api::IdentityP254Reply {
                kind: Some(pb::api::identity_p254_reply::Kind::Ok(
                    pb::api::IdentityP254Result {
                        receipt: Some(asset),
                    },
                )),
            })
        }

        // 调用内部函数处理请求，并处理可能的错误
        let msg = inner(request).unwrap_or_else(|err| pb::api::IdentityP254Reply {
            kind: Some(pb::api::identity_p254_reply::Kind::Error(
                pb::api::GenericError {
                    reason: err.to_string(),
                },
            )),
        });

        // 记录发送的消息并发送回复
        conn.send(msg)
    }

    fn on_compress(
        &self,
        mut conn: ConnectionWrapper,
        request: pb::api::CompressRequest,
    ) -> Result<()> {
        // 内部函数，用于处理压缩请求
        fn inner(request: pb::api::CompressRequest) -> Result<pb::api::CompressReply> {
            // 获取并解析证明选项
            let opts: ProverOpts = request.opts.ok_or(malformed_err())?.try_into()?;
            // 获取并解析回执数据
            let receipt_bytes = request.receipt.ok_or(malformed_err())?.as_bytes()?;
            let receipt: Receipt = bincode::deserialize(&receipt_bytes)?;

            // 获取证明服务器实例
            let prover = get_prover_server(&opts)?;
            // 使用证明服务器进行压缩操作
            let receipt = prover.compress(&opts, &receipt)?;

            // 将压缩后的回执转换为 Protobuf 格式
            let receipt_pb: pb::core::Receipt = receipt.into();
            let receipt_bytes = receipt_pb.encode_to_vec();
            // 创建资产对象，用于存储压缩后的回执
            let asset = pb::api::Asset::from_bytes(
                &request.receipt_out.ok_or(malformed_err())?,
                receipt_bytes.into(),
                "receipt.zkp",
            )?;

            // 返回成功的压缩回复
            Ok(pb::api::CompressReply {
                kind: Some(pb::api::compress_reply::Kind::Ok(pb::api::CompressResult {
                    receipt: Some(asset),
                })),
            })
        }

        // 调用内部函数处理请求，并处理可能的错误
        let msg = inner(request).unwrap_or_else(|err| pb::api::CompressReply {
            kind: Some(pb::api::compress_reply::Kind::Error(
                pb::api::GenericError {
                    reason: err.to_string(),
                },
            )),
        });

        // 记录发送的消息并发送回复
        // tracing::trace!("tx: {msg:?}");
        conn.send(msg)
    }

    fn on_verify(
        &self,
        mut conn: ConnectionWrapper,
        request: pb::api::VerifyRequest,
    ) -> Result<()> {
        // 内部函数，用于处理验证请求
        fn inner(request: pb::api::VerifyRequest) -> Result<()> {
            // 获取并解析回执数据
            let receipt_bytes = request.receipt.ok_or(malformed_err())?.as_bytes()?;
            let receipt: Receipt =
                bincode::deserialize(&receipt_bytes).context("deserialize receipt")?;
            // 获取并解析图像 ID
            let image_id: Digest = request.image_id.ok_or(malformed_err())?.try_into()?;
            // 使用图像 ID 验证回执
            receipt
                .verify(image_id)
                .map_err(|err| anyhow!("verify failed: {err}"))
        }

        // 将验证结果转换为通用回复格式
        let msg: pb::api::GenericReply = inner(request).into();
        // 记录发送的消息并发送回复
        // tracing::trace!("tx: {msg:?}");
        conn.send(msg)
    }
}

fn build_env<'a>(
    conn: &ConnectionWrapper,
    request: &pb::api::ExecutorEnv,
) -> Result<ExecutorEnv<'a>> {
    // 创建一个 ExecutorEnv 构建器
    let mut env_builder = ExecutorEnv::builder();

    // 设置环境变量
    env_builder.env_vars(request.env_vars.clone());

    // 设置命令行参数
    env_builder.args(&request.args);

    // 处理读取文件描述符
    for fd in request.read_fds.iter() {
        // 创建 PosixIoProxy 代理
        let proxy = PosixIoProxy::new(*fd, conn.clone());
        // 创建 BufReader 读取器
        let reader = BufReader::new(proxy);
        // 将读取器添加到环境构建器
        env_builder.read_fd(*fd, reader);
    }

    // 处理写入文件描述符
    for fd in request.write_fds.iter() {
        // 创建 PosixIoProxy 代理
        let proxy = PosixIoProxy::new(*fd, conn.clone());
        // 将写入代理添加到环境构建器
        env_builder.write_fd(*fd, proxy);
    }

    // 创建 SliceIoProxy 代理
    let proxy = SliceIoProxy::new(conn.clone());
    // 处理切片 IO
    for name in request.slice_ios.iter() {
        // 将切片 IO 代理添加到环境构建器
        env_builder.slice_io(name, proxy.clone());
    }

    // 设置段限制
    if let Some(segment_limit_po2) = request.segment_limit_po2 {
        env_builder.segment_limit_po2(segment_limit_po2);
    }

    // 设置会话限制
    env_builder.session_limit(request.session_limit);

    // 处理跟踪事件
    if request.trace_events.is_some() {
        // 创建 TraceProxy 代理
        let proxy = TraceProxy::new(conn.clone());
        // 将跟踪回调添加到环境构建器
        env_builder.trace_callback(proxy);
    }

    // 启用性能分析器
    if !request.pprof_out.is_empty() {
        env_builder.enable_profiler(Path::new(&request.pprof_out));
    }

    // 设置段路径
    if !request.segment_path.is_empty() {
        env_builder.segment_path(Path::new(&request.segment_path));
    }

    // 处理协处理器
    if request.coprocessor {
        // 创建 CoprocessorProxy 代理
        let proxy = CoprocessorProxy::new(conn.clone());
        // 将协处理器回调添加到环境构建器
        env_builder.coprocessor_callback(proxy);
    }

    // 处理假设
    for assumption in request.assumptions.iter() {
        match assumption.kind.as_ref().ok_or(malformed_err())? {
            // 处理已证明的假设
            pb::api::assumption_receipt::Kind::Proven(asset) => {
                let receipt: InnerAssumptionReceipt =
                    pb::core::InnerReceipt::decode(asset.as_bytes()?)?.try_into()?;
                env_builder.add_assumption(receipt)
            }
            // 处理未解决的假设
            pb::api::assumption_receipt::Kind::Unresolved(asset) => {
                let assumption: Assumption =
                    pb::core::Assumption::decode(asset.as_bytes()?)?.try_into()?;
                env_builder.add_assumption(assumption)
            }
        };
    }

    // 构建并返回 ExecutorEnv
    env_builder.build()
}

trait IoOtherError<T> {
    fn map_io_err(self) -> Result<T, IoError>;
}

impl<T, E: Into<Box<dyn StdError + Send + Sync>>> IoOtherError<T> for Result<T, E> {
    fn map_io_err(self) -> Result<T, IoError> {
        self.map_err(|err| IoError::new(IoErrorKind::Other, err))
    }
}

impl From<pb::api::GenericError> for IoError {
    fn from(err: pb::api::GenericError) -> Self {
        IoError::new(IoErrorKind::Other, err.reason)
    }
}

impl pb::api::Asset {
    pub fn from_bytes<P: AsRef<Path>>(
        request: &pb::api::AssetRequest,
        bytes: Bytes,
        path: P,
    ) -> Result<Self> {
        match request.kind.as_ref().ok_or(malformed_err())? {
            pb::api::asset_request::Kind::Inline(()) => Ok(Self {
                kind: Some(pb::api::asset::Kind::Inline(bytes.into())),
            }),
            pb::api::asset_request::Kind::Path(base_path) => {
                let base_path = PathBuf::from(base_path);
                let path = base_path.join(path);
                std::fs::write(&path, bytes)?;
                Ok(Self {
                    kind: Some(pb::api::asset::Kind::Path(path_to_string(path)?)),
                })
            }
            pb::api::asset_request::Kind::Redis(_) => {
                tracing::error!("It's likely that r0vm is not installed with the redis feature");
                bail!("from_bytes not supported for redis")
            }
        }
    }
}

#[allow(dead_code)]
fn check_client_version(client: &semver::Version, server: &semver::Version) -> bool {
    // 如果服务器版本没有预发布标签
    if server.pre.is_empty() {
        // 创建一个版本比较器，要求客户端版本大于等于服务器版本
        let comparator = semver::Comparator {
            op: semver::Op::GreaterEq,
            major: server.major,
            minor: Some(server.minor),
            patch: None,
            pre: semver::Prerelease::EMPTY,
        };
        // 检查客户端版本是否匹配比较器
        comparator.matches(client)
    } else {
        // 如果服务器版本有预发布标签，客户端版本必须完全相同
        client == server
    }
}

#[allow(dead_code)]
fn check_client_version_compat(client: &semver::Version, server: &semver::Version) -> bool {
    // 检查客户端和服务器的主版本号是否相同
    client.major == server.major
}

#[cfg(feature = "redis")]
fn execute_redis(
    conn: &mut ConnectionWrapper,
    exec: &mut ExecutorImpl,
    params: super::RedisParams,
) -> Result<Session> {
    use redis::{Client, Commands, ConnectionLike, SetExpiry, SetOptions};
    use std::{
        sync::{
            mpsc::{sync_channel, Receiver},
            Arc, Mutex,
        },
        thread::{spawn, JoinHandle},
    };

    // 获取 Redis 通道大小，默认为 100
    let channel_size = match std::env::var("RISC0_REDIS_CHANNEL_SIZE") {
        Ok(val_str) => val_str.parse::<usize>().unwrap_or(100),
        Err(_) => 100,
    };
    // 创建同步通道
    let (sender, receiver) = sync_channel::<(String, Segment)>(channel_size);
    // 设置 Redis 选项，包含过期时间
    let opts = SetOptions::default().with_expiration(SetExpiry::EX(params.ttl));

    // 创建一个共享的 Redis 错误变量
    let redis_err = Arc::new(Mutex::new(None));
    let redis_err_clone = redis_err.clone();

    // 克隆连接
    let conn = conn.clone();
    // 启动一个新线程处理 Redis 操作
    let join_handle: JoinHandle<()> = spawn(move || {
        fn inner(
            redis_url: String,
            receiver: &Receiver<(String, Segment)>,
            opts: SetOptions,
            mut conn: ConnectionWrapper,
        ) -> Result<()> {
            // 打开 Redis 客户端
            let client = Client::open(redis_url).context("Failed to open Redis connection")?;
            let mut connection = client
                .get_connection()
                .context("Failed to get redis connection")?;
            // 循环接收段数据并存储到 Redis
            while let Ok((segment_key, segment)) = receiver.recv() {
                if !connection.is_open() {
                    connection = client
                        .get_connection()
                        .context("Failed to get redis connection")?;
                }
                let segment_bytes =
                    bincode::serialize(&segment).context("Failed to deserialize segment")?;
                match connection.set_options(segment_key.clone(), segment_bytes.clone(), opts) {
                    Ok(()) => (),
                    Err(err) => {
                        tracing::warn!(
                            "Failed to set redis key with TTL, trying again. Error: {err}"
                        );
                        connection = client
                            .get_connection()
                            .context("Failed to get redis connection")?;
                        let _: () = connection
                            .set_options(segment_key.clone(), segment_bytes, opts)
                            .context("Failed to set redis key with TTL again")?;
                    }
                };
                let asset = pb::api::Asset {
                    kind: Some(pb::api::asset::Kind::Redis(segment_key)),
                };
                send_segment_done_msg(&mut conn, segment, Some(asset))
                    .context("Failed to send segment_done msg")?;
            }
            Ok(())
        }

        if let Err(err) = inner(params.url, &receiver, opts, conn) {
            *redis_err_clone.lock().unwrap() = Some(err);
        }
    });

    // 执行回调函数，处理段数据
    let session = exec.run_with_callback(|segment| {
        let segment_key = format!("{}:{}", params.key, segment.index);
        if let Err(send_err) = sender.send((segment_key, segment)) {
            let mut redis_err_opt = redis_err.lock().unwrap();
            let redis_err_inner = redis_err_opt.take();
            return Err(match redis_err_inner {
                Some(redis_thread_err) => {
                    tracing::error!(
                        "Redis err: {redis_thread_err} root: {:?}",
                        redis_thread_err.root_cause()
                    );
                    anyhow!(redis_thread_err)
                }
                None => send_err.into(),
            });
        }
        Ok(Box::new(NullSegmentRef))
    });

    // 关闭发送者
    drop(sender);

    // 等待线程结束
    join_handle
        .join()
        .map_err(|err| anyhow!("redis task join failed: {err:?}"))?;

    session
}

fn execute_default(
    conn: &mut ConnectionWrapper,
    exec: &mut ExecutorImpl,
    segments_out: &pb::api::AssetRequest,
) -> Result<Session> {
    // 执行回调函数，处理段数据
    exec.run_with_callback(|segment| {
        let segment_bytes = bincode::serialize(&segment)?;
        let asset = pb::api::Asset::from_bytes(
            segments_out,
            segment_bytes.into(),
            format!("segment-{}", segment.index),
        )?;
        send_segment_done_msg(conn, segment, Some(asset))?;
        Ok(Box::new(NullSegmentRef))
    })
}

fn send_segment_done_msg(
    conn: &mut ConnectionWrapper,
    segment: Segment,
    some_asset: Option<pb::api::Asset>,
) -> Result<()> {
    // 创建段信息
    let segment = Some(pb::api::SegmentInfo {
        index: segment.index,
        po2: segment.inner.po2 as u32,
        cycles: segment.inner.insn_cycles as u32,
        segment: some_asset,
    });

    // 创建服务器回复消息
    let msg = pb::api::ServerReply {
        kind: Some(pb::api::server_reply::Kind::Ok(pb::api::ClientCallback {
            kind: Some(pb::api::client_callback::Kind::SegmentDone(
                pb::api::OnSegmentDone { segment },
            )),
        })),
    };

    tracing::trace!("tx: {msg:?}");
    let reply: pb::api::GenericReply = conn.send_recv(msg)?;
    tracing::trace!("rx: {reply:?}");

    let kind = reply.kind.ok_or(malformed_err())?;
    if let pb::api::generic_reply::Kind::Error(err) = kind {
        bail!(err)
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use semver::Version;

    use super::{check_client_version, check_client_version_compat};

    fn test_inner(check_func: fn(&Version, &Version) -> bool, client: &str, server: &str) -> bool {
        check_func(
            &Version::parse(client).unwrap(),
            &Version::parse(server).unwrap(),
        )
    }

    #[test]
    fn check_version() {
        fn test(client: &str, server: &str) -> bool {
            test_inner(check_client_version, client, server)
        }

        assert!(test("0.18.0", "0.18.0"));
        assert!(test("0.18.1", "0.18.0"));
        assert!(test("0.18.0", "0.18.1"));
        assert!(test("0.19.0", "0.18.0"));
        assert!(test("1.0.0", "0.18.0"));
        assert!(test("1.1.0", "1.0.0"));
        assert!(test("0.19.0-alpha.1", "0.19.0-alpha.1"));

        assert!(!test("0.19.0-alpha.1", "0.19.0-alpha.2"));
        assert!(!test("0.18.0", "0.19.0"));
        assert!(!test("0.18.0", "1.0.0"));
    }

    #[test]
    fn check_version_compat() {
        fn test(client: &str, server: &str) -> bool {
            test_inner(check_client_version_compat, client, server)
        }

        assert!(test("1.1.0", "1.1.0"));
        assert!(test("1.1.1", "1.1.1"));
        assert!(test("1.2.0", "1.1.1"));
        assert!(test("1.2.0-rc.1", "1.1.1"));

        assert!(!test("2.0.0", "1.1.1"));
    }
    #[test]
    fn test_on_prove() {
        // Create a mock connection
        let conn = ConnectionWrapper::new_mock();

        // Create a sample ProveRequest
        let request = ProveRequest {
            env: Some(ExecutorEnv {
                env_vars: vec![],
                args: vec![],
                read_fds: vec![],
                write_fds: vec![],
                slice_ios: vec![],
                segment_limit_po2: None,
                session_limit: 0,
                trace_events: None,
                pprof_out: String::new(),
                segment_path: String::new(),
                coprocessor: false,
                assumptions: vec![],
                binary: None,
            }),
            opts: Some(ProverOpts::default().into()),
            receipt_out: Some(AssetRequest {
                kind: Some(pb::api::asset_request::Kind::Inline(())),
            }),
        };

        // Create a Server instance
        let server = Server::new(Box::new(conn.clone()));

        // Call the on_prove function
        let result = server.on_prove(conn, request);

        // Assert the result is Ok
        assert!(result.is_ok());
    }
}
