//! sidecar 启动边界的 CLI 与版本化 runtime 配置校验。
//!
//! 本模块按 `runtime-config.v1.toml`/`runtime-config.v2.toml` 文件名分派到对应版本的
//! contract loader，不读取旧 shell `config.toml`，也不从环境变量推导 home 或模型设置。
//! 文件系统写入与进程环境硬化分别由 `hardening` 负责。

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, error::ErrorKind};
use efflab_agent_contract::{
    RUNTIME_CONFIG_V1_FILENAME, RUNTIME_CONFIG_V2_FILENAME, RuntimeConfig,
    load_runtime_config_v1_from_str, load_runtime_config_v2_from_str,
};

/// sidecar 的固定命令行参数。
#[derive(Debug, Parser)]
#[command(
    name = "efflab-agent-sidecar",
    version,
    about = "Efflab 隔离 ACP stdio sidecar"
)]
pub struct Cli {
    /// 使用 ACP stdio 传输；Task 12 只允许该传输入口。
    #[arg(
        long,
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        default_value_t = true
    )]
    pub stdio: bool,

    /// Host 写出的版本化 runtime 配置，必须位于私有 home 内的
    /// `runtime-config.v1.toml` 或 `runtime-config.v2.toml`。
    #[arg(long, value_name = "ABS_TOML", required = true)]
    pub runtime_config: Option<PathBuf>,

    /// sidecar 私有 home 的绝对路径。
    #[arg(long, value_name = "ABS")]
    pub home: Option<PathBuf>,

    /// 已弃用的旧参数名；只在 `--home` 缺失或规范化后相等时接受。
    #[arg(long = "grok-home", value_name = "ABS", hide = true)]
    pub grok_home_alias: Option<PathBuf>,

    /// Host 创建并规范化的隔离会话目录绝对路径。
    #[arg(long, value_name = "ABS")]
    pub session_cwd: PathBuf,

    /// debug 构建专用的文件型测试 seam；release 构建不接受该参数。
    #[cfg(debug_assertions)]
    #[arg(long = "test-seam-dir", value_name = "ABS", hide = true)]
    pub test_seam_dir: Option<PathBuf>,
}

/// 完成 CLI、路径和版本化 runtime 配置校验后的启动配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarConfig {
    /// 是否使用固定的 ACP stdio 传输。
    pub stdio: bool,
    /// 归一化后的私有 home。
    pub home: PathBuf,
    /// 归一化后的版本化 runtime 配置路径。
    pub runtime_config_path: PathBuf,
    /// 已通过共享 contract 校验的版本化 runtime 配置。
    pub runtime_config: RuntimeConfig,
    /// 归一化后的隔离会话目录。
    pub session_cwd: PathBuf,
    /// 是否使用了 `--grok-home` 弃用 alias。
    pub used_deprecated_alias: bool,
    /// home 中是否存在旧 `config.toml`；该文件从未被读取。
    pub legacy_config_present: bool,
    /// debug 构建专用测试 seam 目录，不进入 release runtime 配置。
    #[cfg(debug_assertions)]
    pub test_seam_dir: Option<PathBuf>,
}

impl SidecarConfig {
    /// 解析命令行；help/version 只写 stderr，避免污染 ACP stdout。
    pub fn parse_cli() -> Result<Option<Cli>> {
        match Cli::try_parse() {
            Ok(cli) => Ok(Some(cli)),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
                ) =>
            {
                eprint!("{error}");
                Ok(None)
            }
            Err(error) => Err(anyhow::anyhow!(error.to_string())),
        }
    }

    /// 从进程命令行解析并校验 sidecar 启动配置。
    pub fn from_cli() -> Result<Self> {
        let cli = Self::parse_cli()?.context("管理命令不产生 sidecar runtime")?;
        Self::from_parsed_cli(cli)
    }

    /// 校验已经由 clap 解析的参数，供入口和单元测试复用。
    pub fn from_parsed_cli(cli: Cli) -> Result<Self> {
        let (config, _startup_handles) = Self::from_parsed_cli_with_startup(cli)?;
        Ok(config)
    }

    /// 校验参数并返回贯穿启动阶段的 no-follow 目录句柄集合。
    pub fn from_parsed_cli_with_startup(
        cli: Cli,
    ) -> Result<(Self, crate::hardening::StartupHandles)> {
        // 非 stdio 即使由其他调用方传入，也必须在路径与文件访问前拒绝。
        if !cli.stdio {
            bail!("当前仅支持 --stdio");
        }
        // 平台 capability 必须先通过，后续目录和文件访问才能继续。
        crate::hardening::ensure_platform_supported()?;

        let runtime_config_input = cli
            .runtime_config
            .as_deref()
            .context("缺少 --runtime-config；sidecar 不回退旧 config.toml")?;
        let session_cwd = canonicalize_directory(&cli.session_cwd, "--session-cwd")?;
        let (home, used_deprecated_alias) = resolve_home(
            cli.home.as_deref(),
            cli.grok_home_alias.as_deref(),
            &session_cwd,
        )?;
        // 先锁定 no-follow 的目录对象，再校验配置 basename；避免同名 symlink 先掩盖真实 home 错误。
        let startup_handles = crate::hardening::open_startup_handles(&home, &session_cwd)?;
        let (runtime_config_path, config_version) =
            canonicalize_runtime_config(runtime_config_input, &home)?;
        // 从这里开始只使用同一组目录 fd，避免配置校验后被替换的同名路径重新生效。
        let source = startup_handles
            .read_private_runtime_config(&runtime_config_path)
            .context("加载 --runtime-config 失败")?;
        let runtime_config = load_runtime_config_source(&source, config_version)
            .context("校验 --runtime-config 失败")?;

        let expected_session_cwd = session_cwd
            .to_str()
            .context("--session-cwd 必须是有效 UTF-8 路径")?;
        if runtime_config.session_cwd() != expected_session_cwd {
            bail!("runtime config 的 session_cwd 与 --session-cwd 不一致");
        }

        // 只检查同一 home fd 下旧文件项是否存在，不读取其内容；S2 不回退旧配置。
        let legacy_config_present = startup_handles.legacy_config_present()?;

        Ok((
            Self {
                stdio: cli.stdio,
                home,
                runtime_config_path,
                runtime_config,
                session_cwd,
                used_deprecated_alias,
                legacy_config_present,
                #[cfg(debug_assertions)]
                test_seam_dir: cli.test_seam_dir,
            },
            startup_handles,
        ))
    }
}

/// 只接受 v1 `--home`；旧 `--grok-home` 一律拒绝，避免新旧 sidecar 互相误启动。
fn resolve_home(
    home_input: Option<&Path>,
    alias_input: Option<&Path>,
    session_cwd: &Path,
) -> Result<(PathBuf, bool)> {
    if alias_input.is_some() {
        bail!("--home 与 --grok-home 冲突：v1 sidecar 拒绝旧 alias");
    }
    let selected_input = home_input.context("缺少 --home；v1 sidecar 不接受 --grok-home")?;
    let selected_home = canonicalize_private_home(selected_input, "--home")?;
    validate_home_isolated(&selected_home, session_cwd)?;
    Ok((selected_home, false))
}

/// 确保私有 home 不会落入用户 workspace，且不与 session cwd 形成任何祖先关系。
fn validate_home_isolated(home: &Path, session_cwd: &Path) -> Result<()> {
    if home == session_cwd {
        bail!("--home 不得与 --session-cwd 相同");
    }
    if home.starts_with(session_cwd) {
        bail!("拒绝位于隔离 workspace 内的 --home");
    }
    if session_cwd.starts_with(home) {
        bail!("--home 不得是 --session-cwd 的祖先目录");
    }
    Ok(())
}

/// 规范化已存在的 session cwd；目录存在性与 no-follow 校验由启动句柄一次完成。
fn canonicalize_directory(path: &Path, argument_name: &str) -> Result<PathBuf> {
    let normalized = normalize_path(path, argument_name)?;
    Ok(normalized)
}

/// 规范化可在后续阶段创建的私有 home；实际目录创建由 hardening 以 fd 完成。
fn canonicalize_private_home(path: &Path, argument_name: &str) -> Result<PathBuf> {
    let normalized = normalize_path(path, argument_name)?;
    if normalized
        .components()
        .any(|component| component.as_os_str() == ".grok")
    {
        bail!("拒绝用户全局 Grok 配置目录作为 {argument_name}");
    }
    Ok(normalized)
}

/// runtime 配置文件名对应的 schema 主版本；dispatch 只按文件名进入对应 loader。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeConfigFileVersion {
    V1,
    V2,
}

/// 校验 runtime 配置文件位置并判别版本；文件类型、权限、owner、nlink 和读取均由受保护 fd 负责。
///
/// 只接受私有 home 内两个精确文件名之一；`..` 与相对路径已由 `normalize_path` 拒绝，
/// 因此任何目录逃逸或未声明版本名都在内容校验前 fail-closed。
fn canonicalize_runtime_config(
    path: &Path,
    home: &Path,
) -> Result<(PathBuf, RuntimeConfigFileVersion)> {
    let normalized = normalize_path(path, "--runtime-config")?;
    if normalized == home.join(RUNTIME_CONFIG_V1_FILENAME) {
        return Ok((normalized, RuntimeConfigFileVersion::V1));
    }
    if normalized == home.join(RUNTIME_CONFIG_V2_FILENAME) {
        return Ok((normalized, RuntimeConfigFileVersion::V2));
    }
    bail!(
        "--runtime-config 必须位于私有 home 内的 {RUNTIME_CONFIG_V1_FILENAME} 或 {RUNTIME_CONFIG_V2_FILENAME}"
    )
}

/// 按文件名声明的版本加载已读取配置，并把任何非稳定错误收敛为固定分类，避免回显 runtime wire 原文。
fn load_runtime_config_source(
    source: &str,
    version: RuntimeConfigFileVersion,
) -> Result<RuntimeConfig> {
    let loaded = match version {
        RuntimeConfigFileVersion::V1 => {
            load_runtime_config_v1_from_str(source).map(RuntimeConfig::V1)
        }
        RuntimeConfigFileVersion::V2 => {
            load_runtime_config_v2_from_str(source).map(RuntimeConfig::V2)
        }
    };
    loaded.map_err(|error| {
        if error
            .chain()
            .any(|cause| cause.to_string() == "stdio_mcp_unavailable")
        {
            anyhow::anyhow!("stdio_mcp_unavailable")
        } else {
            anyhow::anyhow!("runtime_config_invalid")
        }
    })
}

/// 统一校验并规范化 CLI 路径，不解析文件系统中的符号链接。
fn normalize_path(path: &Path, argument_name: &str) -> Result<PathBuf> {
    validate_path_shape(path, argument_name)?;
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                normalized.push(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::Normal(value) => normalized.push(value),
            std::path::Component::ParentDir => {
                bail!("{argument_name} 不允许包含 ..");
            }
        }
    }
    Ok(normalized)
}

/// 路径边界统一拒绝相对路径、无效 UTF-8、超长值和 `..`。
fn validate_path_shape(path: &Path, argument_name: &str) -> Result<()> {
    crate::hardening::require_absolute_path(path, argument_name)
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use efflab_agent_contract::{
        ApprovedMcpConfig, LoopbackModelSpec, RuntimeConfig, RuntimeConfigV1, RuntimeConfigV2,
        render_runtime_config_v1, render_runtime_config_v2,
    };

    use super::{Cli, SidecarConfig, resolve_home, validate_path_shape};

    fn cli(
        runtime_config: Option<PathBuf>,
        home: Option<PathBuf>,
        alias: Option<PathBuf>,
        cwd: PathBuf,
    ) -> Cli {
        Cli {
            stdio: true,
            runtime_config,
            home,
            grok_home_alias: alias,
            session_cwd: cwd,
            #[cfg(debug_assertions)]
            test_seam_dir: None,
        }
    }

    #[test]
    fn missing_runtime_config_is_rejected_without_legacy_fallback() {
        let temporary = tempfile::tempdir().expect("创建临时目录");
        let cwd = temporary.path().join("session");
        let home = temporary.path().join("home");
        fs::create_dir(&cwd).expect("创建 session cwd");
        fs::create_dir(&home).expect("创建 home");
        fs::write(home.join("config.toml"), "legacy = true\n").expect("写入旧配置");

        let result = SidecarConfig::from_parsed_cli(cli(None, Some(home), None, cwd));

        let error = result.expect_err("缺少 runtime config 必须拒绝");
        assert!(format!("{error:#}").contains("runtime-config"));
    }

    #[test]
    fn deprecated_grok_home_alias_is_rejected_even_with_valid_v1_config() {
        use std::collections::BTreeSet;

        use efflab_agent_contract::{
            ApprovedMcpConfig, LoopbackModelSpec, RuntimeConfigV1, render_runtime_config_v1,
        };

        let temporary = tempfile::tempdir().expect("创建临时目录");
        let cwd = temporary.path().join("session");
        let home = temporary.path().join("home");
        fs::create_dir(&cwd).expect("创建 session cwd");
        fs::create_dir(&home).expect("创建 home");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&cwd, fs::Permissions::from_mode(0o700))
                .expect("设置 session cwd 权限");
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("设置 home 权限");
        }
        let runtime_config_path = home.join("runtime-config.v1.toml");
        let runtime_config = RuntimeConfigV1 {
            schema_version: 1,
            runtime_revision: String::new(),
            session_store_version: 1,
            session_cwd: cwd.to_str().expect("测试 cwd 必须是 UTF-8").to_owned(),
            model: LoopbackModelSpec {
                model_id: "alias-rejection-model".to_owned(),
                base_url: "http://127.0.0.1:4313/v1".to_owned(),
                backend: "chat_completions".to_owned(),
                token_env: "EFFLAB_L3B_BIND".to_owned(),
            },
            approved_mcp: ApprovedMcpConfig::default(),
            expected_tools: BTreeSet::new(),
            system_prompt: String::new(),
        };
        fs::write(
            &runtime_config_path,
            render_runtime_config_v1(&runtime_config).expect("v1 配置必须可渲染"),
        )
        .expect("写入 v1 配置");
        #[cfg(unix)]
        fs::set_permissions(&runtime_config_path, fs::Permissions::from_mode(0o600))
            .expect("设置 v1 配置权限");

        let result =
            SidecarConfig::from_parsed_cli(cli(Some(runtime_config_path), None, Some(home), cwd));

        let error = result.expect_err("旧 --grok-home alias 必须被 v1 sidecar 拒绝");
        assert!(format!("{error:#}").contains("--grok-home"));
    }

    #[test]
    fn home_alias_conflict_is_rejected() {
        let temporary = tempfile::tempdir().expect("创建临时目录");
        let cwd = temporary.path().join("session");
        let home = temporary.path().join("home");
        let alias = temporary.path().join("other-home");
        fs::create_dir(&cwd).expect("创建 session cwd");
        fs::create_dir(&home).expect("创建 home");
        fs::create_dir(&alias).expect("创建 alias home");

        let home_marker = home.to_str().expect("测试 home 必须是 UTF-8").to_owned();
        let alias_marker = alias.to_str().expect("测试 alias 必须是 UTF-8").to_owned();
        let result = SidecarConfig::from_parsed_cli(cli(
            Some(home),
            Some(temporary.path().join("not-used-runtime-config.toml")),
            Some(alias),
            cwd,
        ));

        let error = result.expect_err("home alias 冲突必须拒绝");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("冲突"));
        assert!(!rendered.contains(&home_marker), "错误不得回显 home 路径");
        assert!(!rendered.contains(&alias_marker), "错误不得回显 alias 路径");
    }

    #[test]
    fn home_must_not_be_an_ancestor_of_session_cwd() {
        let temporary = tempfile::tempdir().expect("创建临时目录");
        let session = temporary.path().join("session");
        fs::create_dir(&session).expect("创建 session cwd");

        let error = resolve_home(Some(temporary.path()), None, &session)
            .expect_err("session cwd 的祖先目录不得作为 home");

        assert!(format!("{error:#}").contains("祖先"));
    }

    #[test]
    fn cli_path_shape_rejects_oversized_and_non_utf8_paths() {
        let oversized = PathBuf::from("/").join("x".repeat(4096));
        let error = validate_path_shape(&oversized, "--home").expect_err("超长路径必须拒绝");
        assert!(format!("{error:#}").contains("4096"));

        #[cfg(unix)]
        {
            use std::ffi::OsString;
            use std::os::unix::ffi::OsStringExt;

            let raw = OsString::from_vec(vec![b'/', 0xff]);
            let error = validate_path_shape(raw.as_os_str().as_ref(), "--home")
                .expect_err("非 UTF-8 路径必须拒绝");
            assert!(format!("{error:#}").contains("UTF-8"));
        }
    }

    /// 建立受保护目录与权限，供 V1/V2 配置文件逐个落盘。
    fn prepared_dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temporary = tempfile::tempdir().expect("创建临时目录");
        let cwd = temporary.path().join("session");
        let home = temporary.path().join("home");
        fs::create_dir(&cwd).expect("创建 session cwd");
        fs::create_dir(&home).expect("创建 home");
        fs::set_permissions(&cwd, fs::Permissions::from_mode(0o700))
            .expect("设置 session cwd 权限");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("设置 home 权限");
        (temporary, cwd, home)
    }

    fn write_private_config(path: &PathBuf, rendered: &str) {
        fs::write(path, rendered).expect("写入 runtime config");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("设置配置权限");
    }

    fn v1_config(cwd: &PathBuf) -> RuntimeConfigV1 {
        RuntimeConfigV1 {
            schema_version: 1,
            runtime_revision: String::new(),
            session_store_version: 1,
            session_cwd: cwd.to_str().expect("测试 cwd 必须是 UTF-8").to_owned(),
            model: LoopbackModelSpec {
                model_id: "byok-user-model".to_owned(),
                base_url: "http://127.0.0.1:4312/v1".to_owned(),
                backend: "chat_completions".to_owned(),
                token_env: "EFFLAB_L3B_BIND".to_owned(),
            },
            approved_mcp: ApprovedMcpConfig::default(),
            expected_tools: BTreeSet::new(),
            system_prompt: String::new(),
        }
    }

    fn v2_config(cwd: &PathBuf) -> RuntimeConfigV2 {
        RuntimeConfigV2 {
            schema_version: 2,
            runtime_revision: String::new(),
            session_store_version: 1,
            session_cwd: cwd.to_str().expect("测试 cwd 必须是 UTF-8").to_owned(),
            model: v1_config(cwd).model,
            approved_mcp: ApprovedMcpConfig::default(),
            expected_tools: BTreeSet::new(),
            system_prompt: String::new(),
            context_window_tokens: 200_000,
            compact_threshold_percent: 70,
        }
    }

    /// V2 文件必须按文件名分派加载，且压缩字段由已验证配置驱动。
    #[test]
    fn v2_runtime_config_loads_with_validated_compact_fields() {
        let (_temporary, cwd, home) = prepared_dirs();
        let mut config = v2_config(&cwd);
        config.context_window_tokens = 128_000;
        config.compact_threshold_percent = 50;
        let path = home.join("runtime-config.v2.toml");
        write_private_config(
            &path,
            &render_runtime_config_v2(&config).expect("V2 配置必须可渲染"),
        );

        let parsed = SidecarConfig::from_parsed_cli(cli(Some(path), Some(home), None, cwd))
            .expect("V2 配置必须可加载");
        let RuntimeConfig::V2(loaded) = &parsed.runtime_config else {
            panic!("V2 文件名必须解析为 V2 配置");
        };
        assert_eq!(loaded.context_window_tokens, 128_000);
        assert_eq!(loaded.compact_threshold_percent, 50);
    }

    /// 既有 V1 文件加载行为不变：字段视图与 V1 默认压缩参数保持原样。
    #[test]
    fn v1_runtime_config_keeps_loading_with_original_defaults() {
        let (_temporary, cwd, home) = prepared_dirs();
        let path = home.join("runtime-config.v1.toml");
        write_private_config(
            &path,
            &render_runtime_config_v1(&v1_config(&cwd)).expect("V1 配置必须可渲染"),
        );

        let parsed = SidecarConfig::from_parsed_cli(cli(Some(path), Some(home), None, cwd))
            .expect("V1 配置必须可加载");
        let RuntimeConfig::V1(_) = &parsed.runtime_config else {
            panic!("V1 文件名必须解析为 V1 配置");
        };
        // V1 视图必须把压缩参数回退到 V1 编译期默认值（200k/70%）。
        assert_eq!(parsed.runtime_config.context_window_tokens(), 200_000);
        assert_eq!(parsed.runtime_config.compact_threshold_percent(), 70);
    }

    /// 文件名与内容版本不匹配必须拒绝：V1 名装 V2 内容、V2 名装 V1 内容都不可接受。
    #[test]
    fn mismatched_runtime_config_filename_and_content_are_rejected() {
        let (_temporary, cwd, home) = prepared_dirs();
        let v1_source = render_runtime_config_v1(&v1_config(&cwd)).expect("V1 配置必须可渲染");
        let v2_source = render_runtime_config_v2(&v2_config(&cwd)).expect("V2 配置必须可渲染");

        let wrong_v1 = home.join("runtime-config.v1.toml");
        write_private_config(&wrong_v1, &v2_source);
        let error = SidecarConfig::from_parsed_cli(cli(
            Some(wrong_v1),
            Some(home.clone()),
            None,
            cwd.clone(),
        ))
        .expect_err("V1 文件名装 V2 内容必须拒绝");
        assert!(format!("{error:#}").contains("runtime_config_invalid"));

        let wrong_v2 = home.join("runtime-config.v2.toml");
        write_private_config(&wrong_v2, &v1_source);
        let error = SidecarConfig::from_parsed_cli(cli(Some(wrong_v2), Some(home), None, cwd))
            .expect_err("V2 文件名装 V1 内容必须拒绝");
        assert!(format!("{error:#}").contains("runtime_config_invalid"));
    }

    /// 未声明版本名与 home 之外的配置路径都必须在内容校验前被拒绝。
    #[test]
    fn unknown_runtime_config_filename_and_home_escape_are_rejected() {
        let (temporary, cwd, home) = prepared_dirs();
        let unknown = home.join("runtime-config.v3.toml");
        write_private_config(
            &unknown,
            &render_runtime_config_v2(&v2_config(&cwd)).expect("V2 配置必须可渲染"),
        );
        let error = SidecarConfig::from_parsed_cli(cli(
            Some(unknown),
            Some(home.clone()),
            None,
            cwd.clone(),
        ))
        .expect_err("未声明版本名必须拒绝");
        assert!(format!("{error:#}").contains("runtime-config"));

        let outside = temporary.path().join("runtime-config.v2.toml");
        write_private_config(
            &outside,
            &render_runtime_config_v2(&v2_config(&cwd)).expect("V2 配置必须可渲染"),
        );
        let error = SidecarConfig::from_parsed_cli(cli(
            Some(outside),
            Some(home.clone()),
            None,
            cwd.clone(),
        ))
        .expect_err("home 之外的同名文件必须拒绝");
        assert!(format!("{error:#}").contains("runtime-config"));

        let escaped = home.join("..").join("runtime-config.v2.toml");
        let error = SidecarConfig::from_parsed_cli(cli(Some(escaped), Some(home), None, cwd))
            .expect_err("带 .. 的配置路径必须拒绝");
        assert!(format!("{error:#}").contains(".."));
    }

    /// V2 越界压缩字段必须 fail-closed，而不是被截断静默接受。
    #[test]
    fn v2_out_of_bounds_compact_fields_are_rejected() {
        let (_temporary, cwd, home) = prepared_dirs();
        let base = v2_config(&cwd);
        for tamper in [
            (
                "context_window_tokens = 200000",
                "context_window_tokens = 0",
            ),
            (
                "compact_threshold_percent = 70",
                "compact_threshold_percent = 101",
            ),
        ] {
            let rendered = render_runtime_config_v2(&base).expect("基准 V2 配置必须可渲染");
            let source = rendered.replacen(tamper.0, tamper.1, 1);
            let path = home.join("runtime-config.v2.toml");
            write_private_config(&path, &source);
            let error = SidecarConfig::from_parsed_cli(cli(
                Some(path),
                Some(home.clone()),
                None,
                cwd.clone(),
            ))
            .expect_err("越界压缩字段必须拒绝");
            assert!(format!("{error:#}").contains("runtime_config_invalid"));
        }
    }
}
