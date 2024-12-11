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

use std::rc::Rc;

use clap::Parser;
use risc0_zkvm::{
    get_prover_server, ExecutorEnv, ExecutorImpl, ProverOpts, ProverServer, VerifierContext,
};
use risc0_zkvm_methods::FIB_ELF;

#[derive(Parser)]
struct Args {
    /// Number of iterations.
    #[arg(short, long)]
    iterations: u32,

    /// Specify the hash function to use.
    #[arg(short = 'f', long)]
    hashfn: Option<String>,

    #[arg(short, long, default_value_t = false)]
    skip_prover: bool,

    #[arg(short, long, default_value_t = false)]
    puffin: bool,
}

#[derive(Debug)]
#[allow(unused)]
struct Metrics {
    segments: usize,
    user_cycles: u64,
    total_cycles: u64,
    seal: usize,
}

fn main() {
    // 初始化日志记录器，使用环境变量来设置日志级别
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // 解析命令行参数
    let args = Args::parse();

    // 如果启用了 Puffin 服务器，则启动它
    let _puffin_server = if args.puffin {
        puffin::set_scopes_on(true);
        let server_addr = format!("0.0.0.0:{}", puffin_http::DEFAULT_PORT);
        println!("Puffin server: {server_addr}");
        Some(puffin_http::Server::new(&server_addr).unwrap())
    } else {
        None
    };

    // 设置 Prover 选项
    let mut opts = ProverOpts::default();
    if let Some(hashfn) = args.hashfn {
        opts.hashfn = hashfn;
    }
    // 获取 Prover 服务器实例
    let prover = get_prover_server(&opts).unwrap();
    // 调用 top 函数并传递参数
    let metrics = top(prover, args.iterations, args.skip_prover);
    // 打印度量结果
    println!("{metrics:?}");

    // 如果启用了 Puffin，则记录一个新的帧
    if args.puffin {
        puffin::GlobalProfiler::lock().new_frame();
    }
}

// 定义 top 函数，执行主要逻辑
fn top(prover: Rc<dyn ProverServer>, iterations: u32, skip_prover: bool) -> Metrics {
    // 构建执行环境，写入迭代次数
    let env = ExecutorEnv::builder()
        .write_slice(&[iterations])
        .build()
        .unwrap();
    // 从 ELF 文件创建执行器实例
    let mut exec = ExecutorImpl::from_elf(env, FIB_ELF).unwrap();
    // 运行执行器并获取会话
    let session = exec.run().unwrap();
    // 如果跳过 Prover，则���封大小为 0，否则计算密封大小
    let seal = if skip_prover {
        0
    } else {
        let ctx = VerifierContext::default();
        prover
            .prove_session(&ctx, &session)
            .unwrap()
            .receipt
            .inner
            .composite()
            .unwrap()
            .segments
            .iter()
            .fold(0, |acc, segment| acc + segment.seal_size())
    };

    // 返回度量结果
    Metrics {
        segments: session.segments.len(),
        user_cycles: session.user_cycles,
        total_cycles: session.total_cycles,
        seal,
    }
}