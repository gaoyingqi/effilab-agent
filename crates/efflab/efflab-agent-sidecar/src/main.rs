//! efflab-agent-sidecar 的最小 ACP 运行时入口。
//!
//! 启动边界负责受控 CLI、RuntimeConfigV1、私有 home 和 stderr 日志；ACP 方法由
//! `runtime` 中的 current-thread Tokio + LocalSet 接管，stdout 只保留 JSON-RPC。
//!
//! 启动顺序：管理命令 → CLI/stdio 门禁 → 平台 capability → L3b binding →
//! env allowlist → stderr tracing → config 校验 → home 锁 → 安全 cwd →
//! current-thread Tokio + LocalSet。stderr 只记录稳定错误码与结构化元数据。
//! 退出码为：策略拒绝 2、runtime 错误 1、stdin EOF 正常退出 0。

use std::process::ExitCode;

use anyhow::{Context, Result};
use efflab_agent_sidecar::hardening;
use efflab_agent_sidecar::runtime::run_acp;
use efflab_agent_sidecar::sidecar_config::SidecarConfig;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;

fn main() -> ExitCode {
    // help/version 是管理命令，必须在平台、env 和文件系统检查前直接写 stderr。
    let cli = match SidecarConfig::parse_cli() {
        Ok(Some(cli)) => cli,
        Ok(None) => return ExitCode::SUCCESS,
        Err(_error) => {
            report_startup_rejection("cli_parse", "cli_arguments_invalid");
            return ExitCode::from(2);
        }
    };

    // 解析后立即拒绝非 stdio，避免触碰平台、环境和任何文件系统状态。
    if !cli.stdio {
        report_startup_rejection("transport", "stdio_only");
        return ExitCode::from(2);
    }

    // 平台能力必须在任何配置读取和环境处理前通过。
    if let Err(_error) = hardening::ensure_platform_supported() {
        report_startup_rejection("platform_capability", "platform_unavailable");
        return ExitCode::from(2);
    }

    // binding 必须在 runtime config、home lock 和 LocalSet 之前 fail-closed；错误不回显值。
    if let Err(_error) = hardening::validate_l3b_bind() {
        report_startup_rejection("l3b_binding", "l3b_bind_invalid");
        return ExitCode::from(2);
    }

    // 运行时尚未启动并发任务，此处一次性清理所有非 allowlist 环境变量。
    if let Err(_error) = hardening::sanitize_env() {
        report_startup_rejection("environment", "environment_sanitization_failed");
        return ExitCode::from(2);
    }

    // 在读取配置前安装固定 stderr subscriber，使核心 hardening 成功事件可审计。
    if let Err(_error) = init_tracing() {
        report_startup_rejection("tracing", "tracing_initialization_failed");
        return ExitCode::from(2);
    }

    // SidecarConfig 完成路径、文件权限和 v1 revision 校验；句柄贯穿后续启动阶段。
    let (sidecar, startup_handles) = match SidecarConfig::from_parsed_cli_with_startup(cli) {
        Ok(config) => config,
        Err(error) => {
            report_startup_rejection("startup_config", stable_config_error_code(&error));
            return ExitCode::from(2);
        }
    };
    // tracing 固定写 stderr；stdout 由 ACP gateway 作为唯一 writer 接管。
    tracing::debug!(event = "startup", "sidecar startup boundary passed");
    if sidecar.used_deprecated_alias {
        tracing::warn!(reason = "deprecated_alias", "deprecated --grok-home alias ignored");
    }
    if sidecar.legacy_config_present {
        tracing::warn!(reason = "ignored_legacy_config", "legacy config.toml ignored");
    }

    // 锁句柄贯穿整个进程生命周期，避免同一 home 出现两个 sidecar writer。
    let _home_lock = match startup_handles.acquire_home_lock() {
        Ok(lock) => {
            tracing::debug!(event = "home_lock_acquired", "private home lock acquired");
            lock
        }
        Err(_error) => {
            report_startup_rejection("home_lock", "home_lock_failed");
            return ExitCode::from(2);
        }
    };

    // 以已打开的 no-follow session fd 切换 cwd，避免检查后按路径重新打开。
    if let Err(_error) = startup_handles.set_current_dir_secure() {
        report_startup_rejection("session_cwd", "session_cwd_failed");
        return ExitCode::from(2);
    }
    tracing::debug!(event = "session_cwd_ready", "isolated session cwd ready");

    // current-thread runtime 与 LocalSet 是 ACP stdio transport 的固定接入形状。
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            tracing::error!(
                event = "runtime_build_failed",
                error_code = "runtime_build_failed",
                "构建 Tokio runtime 失败"
            );
            return ExitCode::from(1);
        }
    };
    let local = tokio::task::LocalSet::new();
    match runtime.block_on(local.run_until(run_acp(sidecar, startup_handles))) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            tracing::error!(
                event = "runtime_failed",
                error_code = "runtime_failed",
                "sidecar runtime 失败"
            );
            ExitCode::from(1)
        }
    }
}

/// 输出启动拒绝的固定英文阶段和错误码，不回显参数、路径或底层错误链。
fn report_startup_rejection(stage: &'static str, error_code: &'static str) {
    eprintln!(
        "efflab-agent-sidecar: startup_rejected stage={stage} error_code={error_code}"
    );
}

/// 将 runtime config 边界中少数稳定错误映射为日志错误码。
fn stable_config_error_code(error: &anyhow::Error) -> &'static str {
    if error
        .chain()
        .any(|cause| cause.to_string() == "stdio_mcp_unavailable")
    {
        return "stdio_mcp_unavailable";
    }
    if error
        .chain()
        .any(|cause| cause.to_string() == "runtime_config_invalid")
    {
        return "runtime_config_invalid";
    }
    "startup_config_invalid"
}

/// 初始化固定 stderr subscriber；只允许 sidecar 自身的稳定事件通过日志边界。
fn init_tracing() -> Result<()> {
    let filter = Targets::new()
        .with_default(LevelFilter::OFF)
        .with_target(env!("CARGO_CRATE_NAME"), LevelFilter::DEBUG);
    let layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_filter(filter);
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::set_global_default(subscriber)
        .context("安装 stderr tracing subscriber")?;
    Ok(())
}
