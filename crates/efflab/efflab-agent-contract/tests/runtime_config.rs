use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use efflab_agent_contract::{
    ApprovedMcpConfig, LoopbackModelSpec, McpServerSpec, RuntimeConfig, RuntimeConfigV1,
    RuntimeConfigV2, is_literal_loopback_http_url, is_prompt_id, is_qualified_tool_name,
    load_runtime_config_v1, load_runtime_config_v1_from_str, load_runtime_config_v2,
    load_runtime_config_v2_from_str, render_runtime_config_v1, render_runtime_config_v2,
};
use serde::Serialize;
use tempfile::TempDir;

const REVISION_PLACEHOLDER: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct FixturePath {
    _directory: TempDir,
    path: PathBuf,
}

fn fixture_source(name: &str) -> &'static str {
    match name {
        "runtime_config_v1_empty.toml" => {
            include_str!("fixtures/runtime_config_v1_empty.toml")
        }
        "runtime_config_v1_http_mcp.toml" => {
            include_str!("fixtures/runtime_config_v1_http_mcp.toml")
        }
        "runtime_config_v1_expected_tools_under_servers.toml" => {
            include_str!("fixtures/runtime_config_v1_expected_tools_under_servers.toml")
        }
        "runtime_config_v2_empty.toml" => {
            include_str!("fixtures/runtime_config_v2_empty.toml")
        }
        "runtime_config_v2_http_mcp.toml" => {
            include_str!("fixtures/runtime_config_v2_http_mcp.toml")
        }
        _ => panic!("未知 runtime config fixture: {name}"),
    }
}

/// 用目标平台临时目录替换 fixture 占位符，并用独立摘要实现填充 revision。
fn materialize_fixture_source(name: &str) -> String {
    let source = materialize_cwd(fixture_source(name));
    let template: RuntimeConfigV1 = toml::from_str(&source).expect("fixture 模板必须可解析");
    source.replace(REVISION_PLACEHOLDER, &independent_revision(&template))
}

/// V2 fixture 版本：同样替换 cwd 占位符，并用 V2 独立摘要填充 revision。
fn materialize_fixture_source_v2(name: &str) -> String {
    let source = materialize_cwd(fixture_source(name));
    let template: RuntimeConfigV2 = toml::from_str(&source).expect("V2 fixture 模板必须可解析");
    source.replace(REVISION_PLACEHOLDER, &independent_revision_v2(&template))
}

/// 测试只生成目标平台合法的绝对 cwd，不把本机路径写入 fixture。
fn session_cwd() -> PathBuf {
    std::env::temp_dir().join("efflab-runtime-config-v1")
}

fn session_cwd_string() -> String {
    session_cwd()
        .to_str()
        .expect("测试临时路径必须为 UTF-8")
        .to_owned()
}

/// 用 TOML 编码写入 cwd，确保 Windows 反斜杠不会破坏 basic string。
fn materialize_cwd(source: &str) -> String {
    source.replace(
        "session_cwd = \"<canonical-session-cwd>\"",
        &session_cwd_assignment(),
    )
}

fn session_cwd_assignment() -> String {
    let encoded = toml::Value::String(session_cwd_string()).to_string();
    format!("session_cwd = {encoded}")
}

fn fixture_path(name: &str) -> FixturePath {
    let directory = tempfile::tempdir().expect("创建 fixture 临时目录应成功");
    let source = materialize_fixture_source(name);
    let path = directory.path().join(name);
    fs::write(&path, source).expect("写入 fixture 临时文件应成功");
    FixturePath {
        _directory: directory,
        path,
    }
}

fn write_config(config: &RuntimeConfigV1) -> (TempDir, PathBuf) {
    let rendered = render_runtime_config_v1(config).expect("配置必须可渲染");
    write_config_source(&rendered)
}

/// V2 变体：渲染后以 `runtime-config.v2.toml` 文件名落盘。
fn write_config_v2(config: &RuntimeConfigV2) -> (TempDir, PathBuf) {
    let rendered = render_runtime_config_v2(config).expect("V2 配置必须可渲染");
    write_config_source_v2(&rendered)
}

fn write_config_source_v2(source: &str) -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("创建配置临时目录应成功");
    let path = directory.path().join("runtime-config.v2.toml");
    fs::write(&path, source).expect("写入配置临时文件应成功");
    (directory, path)
}

/// V2 策略负测：篡改后按 V2 payload 独立重算 revision，避免被摘要失败掩盖。
fn write_tampered_config_v2(
    config: &RuntimeConfigV2,
    tamper: impl FnOnce(String) -> String,
) -> (TempDir, PathBuf) {
    let rendered = render_runtime_config_v2(config).expect("V2 基准配置必须可渲染");
    let source = with_independent_revision_v2(&tamper(rendered));
    write_config_source_v2(&source)
}

fn with_independent_revision_v2(source: &str) -> String {
    let config: RuntimeConfigV2 =
        toml::from_str(source).expect("V2 策略负测必须保持 schema 可解析");
    source.replace(&config.runtime_revision, &independent_revision_v2(&config))
}

/// 修改后重算独立 revision，使策略负测不会被旧摘要错误掩盖。
fn write_tampered_config(
    config: &RuntimeConfigV1,
    tamper: impl FnOnce(String) -> String,
) -> (TempDir, PathBuf) {
    let rendered = render_runtime_config_v1(config).expect("基准配置必须可渲染");
    let source = with_independent_revision(&tamper(rendered));
    write_config_source(&source)
}

fn with_independent_revision(source: &str) -> String {
    let config: RuntimeConfigV1 = toml::from_str(source).expect("策略负测必须保持 schema 可解析");
    source.replace(&config.runtime_revision, &independent_revision(&config))
}

fn write_config_source(source: &str) -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("创建配置临时目录应成功");
    let path = directory.path().join("runtime-config.v1.toml");
    fs::write(&path, source).expect("写入配置临时文件应成功");
    (directory, path)
}

fn loaded_fixture(name: &str) -> (FixturePath, RuntimeConfigV1) {
    let fixture = fixture_path(name);
    let loaded = load_runtime_config_v1(&fixture.path).expect("fixture 必须可加载");
    (fixture, loaded)
}

/// 断言 loader 报告预期的安全分类，避免把解析失败归因到后续 revision 校验。
fn assert_loader_error(source: &str, expected: &str) {
    let (_directory, path) = write_config_source(source);
    let error = load_runtime_config_v1(&path).expect_err("非法 runtime config 必须拒绝");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(expected),
        "错误应包含 {expected:?}，实际为: {rendered}"
    );
}

/// V2 loader 变体：从已读文本直接断言，避免路径语义混入策略断言。
fn assert_loader_error_v2(source: &str, expected: &str) {
    let error =
        load_runtime_config_v2_from_str(source).expect_err("非法 V2 runtime config 必须拒绝");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(expected),
        "V2 错误应包含 {expected:?}，实际为: {rendered}"
    );
}

/// 以完整配置经过 loader 验证 HTTP MCP URL 的字段策略。
fn assert_http_url_rejected(url: &str) {
    let source = materialize_cwd(fixture_source("runtime_config_v1_http_mcp.toml"))
        .replace("http://127.0.0.1:4313/mcp", url);
    let source = with_independent_revision(&source);
    assert_loader_error(&source, "approved_mcp.servers.url_invalid");
}

#[test]
fn runtime_config_v1_can_validate_already_read_source() {
    let source = materialize_fixture_source("runtime_config_v1_empty.toml");
    let from_path = loaded_fixture("runtime_config_v1_empty.toml").1;
    let from_source = load_runtime_config_v1_from_str(&source).expect("已读取的 config 应可校验");

    assert_eq!(from_source, from_path);
}

#[test]
fn runtime_config_session_cwd_uses_one_absolute_utf8_lexical_contract() {
    let exact_limit = format!("/{}", "x".repeat(4095));
    let source = materialize_cwd(fixture_source("runtime_config_v1_empty.toml")).replace(
        &session_cwd_assignment(),
        &format!("session_cwd = {}", toml::Value::String(exact_limit.clone())),
    );
    let source = with_independent_revision(&source);
    let (_directory, path) = write_config_source(&source);
    assert!(
        load_runtime_config_v1(&path).is_ok(),
        "4096 字节绝对 UTF-8 session_cwd 应通过 shape 校验"
    );

    for (invalid, expected) in [
        ("relative/session", "绝对"),
        ("/safe/../session", ".."),
        ("/safe\0session", "NUL"),
    ] {
        let source = materialize_cwd(fixture_source("runtime_config_v1_empty.toml")).replace(
            &session_cwd_assignment(),
            &format!("session_cwd = {}", toml::Value::String(invalid.to_owned())),
        );
        let source = with_independent_revision(&source);
        let (_directory, path) = write_config_source(&source);
        let error = load_runtime_config_v1(&path).expect_err("非法 session_cwd 必须拒绝");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(expected),
            "session_cwd 错误应包含 {expected:?}，实际为 {rendered:?}"
        );
        assert!(
            !rendered.contains(invalid),
            "session_cwd 错误不得回显输入值: {rendered:?}"
        );
    }

    let oversized = format!("/{}", "x".repeat(4096));
    let source = materialize_cwd(fixture_source("runtime_config_v1_empty.toml")).replace(
        &session_cwd_assignment(),
        &format!("session_cwd = {}", toml::Value::String(oversized)),
    );
    let source = with_independent_revision(&source);
    let (_directory, path) = write_config_source(&source);
    assert_loader_error(&source, "4096");
    assert!(load_runtime_config_v1(&path).is_err());
}

#[test]
fn runtime_config_errors_never_echo_mcp_server_names_or_control_characters() {
    let malicious_name = "evil\u{001b}[31mserver";
    let server_key = toml::Value::String(malicious_name.to_owned()).to_string();
    let invalid_server_key = materialize_cwd(fixture_source("runtime_config_v1_empty.toml"))
        .replace(
            "[approved_mcp]\nservers = {}",
            &format!("[approved_mcp.servers.{server_key}]\nurl = \"http://127.0.0.1:4313/mcp\""),
        );
    let error = load_runtime_config_v1_from_str(&invalid_server_key)
        .expect_err("非法 MCP server key 必须拒绝");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("approved_mcp.servers.name_invalid"),
        "非法 server key 应归类为固定错误: {rendered:?}"
    );
    assert!(!rendered.contains(malicious_name));
    assert!(!rendered.contains('\u{001b}'));

    let invalid_url = materialize_cwd(fixture_source("runtime_config_v1_empty.toml")).replace(
        "[approved_mcp]\nservers = {}",
        "[approved_mcp.servers.demo]\nurl = \"http://localhost:4313/mcp\"",
    );
    let invalid_url = with_independent_revision(&invalid_url);
    let error = load_runtime_config_v1_from_str(&invalid_url).expect_err("非回环 MCP URL 必须拒绝");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("approved_mcp.servers.url_invalid"));
    assert!(!rendered.contains(malicious_name));
    assert!(!rendered.contains('\u{001b}'));
}

#[test]
fn runtime_config_v1_round_trips_empty_and_http() {
    let (empty_fixture, empty) = loaded_fixture("runtime_config_v1_empty.toml");
    assert!(empty.expected_tools.is_empty());
    assert!(empty.approved_mcp.servers.is_empty());
    let rendered_empty = render_runtime_config_v1(&empty).expect("empty config 必须可渲染");
    assert!(!rendered_empty.contains("[approved_mcp.servers]"));
    assert!(rendered_empty.contains("expected_tools = []"));
    assert!(rendered_empty.contains("system_prompt = \"\""));
    assert_eq!(
        rendered_empty,
        fs::read_to_string(&empty_fixture.path).unwrap()
    );

    let (http_fixture, http) = loaded_fixture("runtime_config_v1_http_mcp.toml");
    assert_eq!(http.expected_tools.iter().next().unwrap(), "demo__search");
    assert_eq!(http.approved_mcp.servers.len(), 1);
    let rendered_http = render_runtime_config_v1(&http).expect("HTTP config 必须可渲染");
    assert_eq!(
        rendered_http,
        fs::read_to_string(&http_fixture.path).unwrap()
    );
    let (_round_trip_dir, round_trip_path) = write_config(&http);
    assert_eq!(load_runtime_config_v1(&round_trip_path).unwrap(), http);
}

#[test]
fn system_prompt_is_optional_and_round_trips_product_text() {
    let missing = materialize_fixture_source("runtime_config_v1_empty.toml")
        .replace("system_prompt = \"\"\n", "");
    let missing = with_independent_revision(&missing);
    let loaded =
        load_runtime_config_v1_from_str(&missing).expect("缺省 system_prompt 必须按空字符串加载");
    assert!(loaded.system_prompt.is_empty());

    let mut config = loaded;
    config.system_prompt =
        "You are AIMO's music assistant.\nOperate only through Host tools.".to_owned();
    let rendered = render_runtime_config_v1(&config).expect("产品提示词必须可渲染");
    assert!(rendered.contains("You are AIMO's music assistant."));
    let round_trip = load_runtime_config_v1_from_str(&rendered).expect("产品提示词必须可回读");
    assert_eq!(round_trip.system_prompt, config.system_prompt);
}

#[test]
fn system_prompt_rejects_nul_and_oversized_text() {
    let empty = materialize_fixture_source("runtime_config_v1_empty.toml");
    let mut config: RuntimeConfigV1 = toml::from_str(&empty).expect("fixture 必须可解析");
    config.system_prompt = "bad\0prompt".to_owned();
    let error = render_runtime_config_v1(&config).expect_err("含 NUL 的提示词必须拒绝");
    assert!(format!("{error:#}").contains("system_prompt"));

    config.system_prompt = "x".repeat(32_769);
    let error = render_runtime_config_v1(&config).expect_err("超长提示词必须拒绝");
    assert!(format!("{error:#}").contains("32768"));
}

#[test]
fn expected_tools_under_servers_table_is_rejected() {
    let source = materialize_cwd(fixture_source(
        "runtime_config_v1_expected_tools_under_servers.toml",
    ))
    .replace(REVISION_PLACEHOLDER, &format!("sha256:{}", "0".repeat(64)));
    assert_loader_error(&source, "runtime_config_invalid");
}

#[test]
fn runtime_config_loader_rejects_invalid_expected_tool_names() {
    for name in [
        "",
        "demo",
        "demo__",
        "demo__search__extra",
        "1demo__search",
        "demo__1search",
        "demo__search.name",
        "demo__search name",
    ] {
        let expected_tools = toml::Value::String(name.to_owned()).to_string();
        let source = materialize_cwd(fixture_source("runtime_config_v1_http_mcp.toml")).replace(
            "expected_tools = [\"demo__search\"]",
            &format!("expected_tools = [{expected_tools}]"),
        );
        let source = with_independent_revision(&source);
        assert_loader_error(&source, "expected_tools");
    }
}

#[test]
fn runtime_config_loader_keeps_long_tool_segment_before_record_limit() {
    let tool_name = format!("tool_{}", "x".repeat(64));
    let qualified_name = format!("demo__{tool_name}");
    let expected_tools = toml::Value::String(qualified_name.clone()).to_string();
    let source = materialize_cwd(fixture_source("runtime_config_v1_http_mcp.toml")).replace(
        "expected_tools = [\"demo__search\"]",
        &format!("expected_tools = [{expected_tools}]"),
    );
    let source = with_independent_revision(&source);
    let loaded = load_runtime_config_v1_from_str(&source)
        .expect("合法且超过 64 字节的 tool segment 不应被 loader 错误拒绝");
    assert_eq!(loaded.expected_tools, BTreeSet::from([qualified_name]));
}

/// RuntimeConfigV1 的 server map key 必须执行 64-byte 和字符集边界，不能退回非空判断。
#[test]
fn runtime_config_loader_rejects_oversized_and_invalid_server_keys() {
    // 通过合法 HTTP 条目重算 revision，使断言命中 server key 校验而不是摘要错误。
    let source_for_server = |name: &str| {
        let key = toml::Value::String(name.to_owned()).to_string();
        let source = materialize_cwd(fixture_source("runtime_config_v1_empty.toml")).replace(
            "[approved_mcp]\nservers = {}",
            &format!("[approved_mcp.servers.{key}]\nurl = \"http://127.0.0.1:4313/mcp\""),
        );
        with_independent_revision(&source)
    };

    let oversized = source_for_server(&"s".repeat(65));
    assert_loader_error(&oversized, "approved_mcp.servers.name_invalid");

    for name in [
        "",
        "1demo",
        "demo.name",
        "demo name",
        "demo/tool",
        "demo__server",
    ] {
        let source = source_for_server(name);
        assert_loader_error(&source, "approved_mcp.servers.name_invalid");
    }
}

#[test]
fn literal_loopback_accepts_non_empty_root_path_but_model_requires_v1() {
    assert!(is_literal_loopback_http_url("http://127.0.0.1:4312/"));
    assert!(is_literal_loopback_http_url("http://[::1]:4312/"));
    assert!(is_literal_loopback_http_url("http://127.0.0.1:4312/v1"));
    assert!(is_literal_loopback_http_url("http://127.0.0.1:4313/mcp"));
    assert!(!is_literal_loopback_http_url("http://localhost:4312/v1"));
    assert!(!is_literal_loopback_http_url("https://127.0.0.1:4312/v1"));
    assert!(!is_literal_loopback_http_url(
        "http://127.0.0.1:4312/v1?x=1"
    ));
    assert!(!is_literal_loopback_http_url(
        "http://user@127.0.0.1:4312/v1"
    ));
    assert!(!is_literal_loopback_http_url("http://127.0.0.2:4312/v1"));
    assert!(!is_literal_loopback_http_url("http://127.0.0.1/v1"));
    assert!(!is_literal_loopback_http_url("http://[::1]:4312"));
    assert!(!is_literal_loopback_http_url("http://127.0.0.1:0/v1"));
    assert!(is_literal_loopback_http_url("http://127.0.0.1:65535/v1"));
    assert!(!is_literal_loopback_http_url("http://127.0.0.1:65536/v1"));

    let source = materialize_cwd(fixture_source("runtime_config_v1_http_mcp.toml"))
        .replace("http://127.0.0.1:4313/mcp", "http://127.0.0.1:4313/");
    let source = with_independent_revision(&source);
    let (_directory, path) = write_config_source(&source);
    let loaded = load_runtime_config_v1(&path).expect("HTTP MCP 根路径应可加载");
    assert_eq!(
        loaded.approved_mcp.servers["demo"],
        McpServerSpec::Http {
            url: "http://127.0.0.1:4313/".to_owned(),
        }
    );

    let source = materialize_cwd(fixture_source("runtime_config_v1_empty.toml"))
        .replace("http://127.0.0.1:4312/v1", "http://127.0.0.1:4312/");
    let source = with_independent_revision(&source);
    assert_loader_error(&source, "model.base_url");
}

#[test]
fn runtime_config_load_rejects_all_non_literal_http_mcp_urls() {
    for url in [
        "http://localhost:4313/mcp",
        "http://LOCALHOST:4313/mcp",
        "https://127.0.0.1:4313/mcp",
        "http://user@127.0.0.1:4313/mcp",
        "http://user@[::1]:4313/mcp",
        "http://127.0.0.1:4313/mcp?x=1",
        "http://127.0.0.1:4313/mcp#fragment",
        "http://127.0.0.2:4313/mcp",
        "http://127.0.0.1:4313",
        "http://127.0.0.1:0/mcp",
        "http://127.0.0.1:65536/mcp",
    ] {
        assert_http_url_rejected(url);
    }

    for url in [
        "http://127.0.0.1:1/",
        "http://127.0.0.1:65535/mcp",
        "http://[::1]:4313/",
    ] {
        let source = materialize_cwd(fixture_source("runtime_config_v1_http_mcp.toml"))
            .replace("http://127.0.0.1:4313/mcp", url);
        let source = with_independent_revision(&source);
        let (_directory, path) = write_config_source(&source);
        assert!(
            load_runtime_config_v1(&path).is_ok(),
            "合法 HTTP MCP URL 应通过完整 loader: {url}"
        );
    }
}

#[test]
fn runtime_config_rejects_invalid_fixed_values_and_model_id_with_field_errors() {
    let (_fixture, config) = loaded_fixture("runtime_config_v1_empty.toml");

    let (_dir, path) = write_tampered_config(&config, |source| {
        source.replace("schema_version = 1", "schema_version = 2")
    });
    let error = load_runtime_config_v1(&path).unwrap_err();
    assert!(error.to_string().contains("schema_version"));

    let (_dir, path) = write_tampered_config(&config, |source| {
        source.replace("session_store_version = 1", "session_store_version = 2")
    });
    let error = load_runtime_config_v1(&path).unwrap_err();
    assert!(error.to_string().contains("session_store_version"));

    let (_dir, path) = write_tampered_config(&config, |source| {
        source.replace("backend = \"chat_completions\"", "backend = \"responses\"")
    });
    let error = load_runtime_config_v1(&path).unwrap_err();
    assert!(error.to_string().contains("model.backend"));

    let (_dir, path) = write_tampered_config(&config, |source| {
        source.replace(
            "token_env = \"EFFLAB_L3B_BIND\"",
            "token_env = \"OTHER_TOKEN\"",
        )
    });
    let error = load_runtime_config_v1(&path).unwrap_err();
    assert!(error.to_string().contains("model.token_env"));

    let (_dir, path) = write_tampered_config(&config, |source| {
        source.replace("model_id = \"byok-user-model\"", "model_id = \"bad model\"")
    });
    let error = load_runtime_config_v1(&path).unwrap_err();
    assert!(error.to_string().contains("model.model_id"));

    let (_dir, path) = write_tampered_config(&config, |source| {
        source.replace(
            "model_id = \"byok-user-model\"",
            &format!("model_id = \"{}\"", "m".repeat(129)),
        )
    });
    let error = load_runtime_config_v1(&path).unwrap_err();
    assert!(error.to_string().contains("model.model_id"));
}

#[test]
fn runtime_config_rejects_invalid_cwd_and_model_base_url_with_field_errors() {
    let (_fixture, config) = loaded_fixture("runtime_config_v1_empty.toml");

    let (_dir, path) = write_tampered_config(&config, |source| {
        source.replace(&session_cwd_assignment(), "session_cwd = \"relative/path\"")
    });
    let error = load_runtime_config_v1(&path).unwrap_err();
    assert!(error.to_string().contains("session_cwd"));

    let (_dir, path) = write_tampered_config(&config, |source| {
        source.replace(
            &session_cwd_assignment(),
            &format!("session_cwd = \"{}\"", "x".repeat(4097)),
        )
    });
    let error = load_runtime_config_v1(&path).unwrap_err();
    assert!(error.to_string().contains("session_cwd"));

    let (_dir, path) = write_tampered_config(&config, |source| {
        source.replace(
            "base_url = \"http://127.0.0.1:4312/v1\"",
            "base_url = \"http://localhost:4312/v1\"",
        )
    });
    let error = load_runtime_config_v1(&path).unwrap_err();
    assert!(error.to_string().contains("model.base_url"));

    let (_dir, path) = write_tampered_config(&config, |source| {
        source.replace(
            "base_url = \"http://127.0.0.1:4312/v1\"",
            "base_url = \"http://127.0.0.1:4312/v1/\"",
        )
    });
    let error = load_runtime_config_v1(&path).unwrap_err();
    assert!(error.to_string().contains("model.base_url"));

    let (_dir, path) = write_tampered_config(&config, |source| {
        source.replace(
            "base_url = \"http://127.0.0.1:4312/v1\"",
            "base_url = \"http://127.0.0.1:4312/prefix/v1\"",
        )
    });
    let error = load_runtime_config_v1(&path).unwrap_err();
    assert!(error.to_string().contains("model.base_url"));
}

#[test]
fn runtime_config_loader_rejects_unknown_fields_at_each_wire_level() {
    let empty = materialize_fixture_source("runtime_config_v1_empty.toml");
    assert_loader_error(
        &empty.replace("\n[model]\n", "\nunknown_root = true\n\n[model]\n"),
        "runtime_config_invalid",
    );

    assert_loader_error(
        &empty.replace("[model]\n", "[model]\nunknown_model = true\n"),
        "runtime_config_invalid",
    );

    assert_loader_error(
        &empty.replace(
            "[approved_mcp]\nservers = {}",
            "[approved_mcp]\nservers = {}\nunknown_approved = true",
        ),
        "runtime_config_invalid",
    );

    let http = materialize_fixture_source("runtime_config_v1_http_mcp.toml");
    assert_loader_error(
        &http.replace(
            "url = \"http://127.0.0.1:4313/mcp\"",
            "url = \"http://127.0.0.1:4313/mcp\"\nunknown_http = true",
        ),
        "runtime_config_invalid",
    );

    let stdio = materialize_fixture_source("runtime_config_v1_empty.toml").replace(
        "[approved_mcp]\nservers = {}",
        "[approved_mcp.servers.demo]\ncommand = \"echo\"\nargs = []\nunknown_stdio = true",
    );
    assert_loader_error(&stdio, "runtime_config_invalid");
}

#[test]
fn runtime_config_loader_rejects_missing_required_fields_independently() {
    let empty = materialize_fixture_source("runtime_config_v1_empty.toml");
    for source in [
        empty.replace("schema_version = 1\n", ""),
        empty.replace("expected_tools = []\n", ""),
        empty.replace("model_id = \"byok-user-model\"\n", ""),
        empty.replace("[approved_mcp]\nservers = {}", "[approved_mcp]"),
    ] {
        assert_loader_error(&source, "runtime_config_invalid");
    }

    let http = materialize_fixture_source("runtime_config_v1_http_mcp.toml");
    assert_loader_error(
        &http.replace("url = \"http://127.0.0.1:4313/mcp\"\n", ""),
        "runtime_config_invalid",
    );

    let stdio = materialize_fixture_source("runtime_config_v1_empty.toml").replace(
        "[approved_mcp]\nservers = {}",
        "[approved_mcp.servers.demo]\nargs = []",
    );
    assert_loader_error(&stdio, "runtime_config_invalid");
}

#[test]
fn load_runtime_config_v1_rejects_stdio_with_stable_error() {
    let source = materialize_fixture_source("runtime_config_v1_empty.toml").replace(
        "[approved_mcp]\nservers = {}",
        "[approved_mcp.servers.demo]\ncommand = \"echo\"\nargs = []",
    );
    let (_directory, path) = write_config_source(&source);

    let error = load_runtime_config_v1(&path).expect_err("stdio MCP 必须拒绝");
    assert!(error.to_string().contains("stdio_mcp_unavailable"));
}

#[test]
fn runtime_revision_matches_independent_empty_and_complete_golden_payloads() {
    assert_eq!(
        independent_sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let config = golden_config();
    assert_eq!(
        canonical_revision_json(&config),
        GOLDEN_CANONICAL_JSON,
        "golden JSON 必须明确不包含 runtime_revision 并保持字段/集合排序"
    );
    assert_eq!(independent_revision(&config), GOLDEN_REVISION);

    let rendered = render_runtime_config_v1(&config).expect("golden 配置必须可渲染");
    let parsed: RuntimeConfigV1 = toml::from_str(&rendered).expect("golden TOML 必须可解析");
    assert_eq!(parsed.runtime_revision, GOLDEN_REVISION);
    let source = rendered.replace(&parsed.runtime_revision, GOLDEN_REVISION);
    let (_directory, path) = write_config_source(&source);
    assert_eq!(
        load_runtime_config_v1(&path)
            .expect("loader 必须接受独立 golden revision")
            .runtime_revision,
        GOLDEN_REVISION
    );
}

#[test]
fn runtime_revision_mismatch_is_rejected_independently() {
    let source = materialize_fixture_source("runtime_config_v1_empty.toml");
    let config: RuntimeConfigV1 = toml::from_str(&source).expect("fixture 必须可解析");
    let tampered = source.replace(
        &config.runtime_revision,
        &format!("sha256:{}", "f".repeat(64)),
    );
    assert_loader_error(&tampered, "runtime_revision");
}

#[test]
fn runtime_revision_is_stable_for_sorted_sets_and_changes_for_participating_fields() {
    let config = golden_config();
    let mut reversed = golden_config();
    reversed.expected_tools =
        BTreeSet::from(["zeta__search".to_owned(), "alpha__search".to_owned()]);
    reversed.approved_mcp.servers = BTreeMap::from([
        (
            "zeta".to_owned(),
            McpServerSpec::Http {
                url: "http://127.0.0.1:4313/".to_owned(),
            },
        ),
        (
            "alpha".to_owned(),
            McpServerSpec::Http {
                url: "http://[::1]:4314/mcp".to_owned(),
            },
        ),
    ]);
    assert_eq!(
        independent_revision(&config),
        independent_revision(&reversed)
    );
    assert_eq!(
        canonical_revision_json(&config),
        canonical_revision_json(&reversed)
    );

    let mut changed = config.clone();
    changed.expected_tools.insert("alpha__zebra".to_owned());
    assert_ne!(
        independent_revision(&config),
        independent_revision(&changed)
    );

    let mut changed = config.clone();
    if let Some(McpServerSpec::Http { url }) = changed.approved_mcp.servers.get_mut("alpha") {
        *url = "http://[::1]:4315/mcp".to_owned();
    }
    assert_ne!(
        independent_revision(&config),
        independent_revision(&changed)
    );

    let mut changed = config.clone();
    changed.session_cwd = golden_cwd_changed().to_owned();
    assert_ne!(
        independent_revision(&config),
        independent_revision(&changed)
    );

    let mut changed = config.clone();
    changed.system_prompt = "You are the product-specific agent.".to_owned();
    assert_ne!(
        independent_revision(&config),
        independent_revision(&changed)
    );
}

#[test]
fn runtime_config_v1_serializes_only_the_frozen_root_keys() {
    let (_fixture, config) = loaded_fixture("runtime_config_v1_empty.toml");
    let value = serde_json::to_value(&config).expect("RuntimeConfigV1 必须可序列化");
    let mut keys = value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "approved_mcp",
            "expected_tools",
            "model",
            "runtime_revision",
            "schema_version",
            "session_cwd",
            "session_store_version",
            "system_prompt",
        ]
    );
    assert_eq!(value["approved_mcp"]["servers"], serde_json::json!({}));
}

#[test]
fn runtime_wire_rejects_serializing_legacy_stdio_fields() {
    let mut config = golden_config();
    config.approved_mcp.servers.insert(
        "stdio".to_owned(),
        McpServerSpec::Stdio {
            command: PathBuf::from("secret-command"),
            args: vec!["--token".to_owned()],
        },
    );
    let error = serde_json::to_value(&config).expect_err("stdio 不得进入 runtime wire");
    assert!(error.to_string().contains("stdio_mcp_unavailable"));
}

#[test]
fn runtime_config_v1_types_are_constructible_for_future_host_spawn() {
    let cwd = std::env::temp_dir().join("efflab-runtime-config-v1-session");
    let config = RuntimeConfigV1 {
        schema_version: 1,
        runtime_revision: String::new(),
        session_store_version: 1,
        session_cwd: cwd.to_str().expect("测试临时路径必须为 UTF-8").to_owned(),
        model: LoopbackModelSpec {
            model_id: "byok-user-model".to_string(),
            base_url: "http://[::1]:4312/v1".to_string(),
            backend: "chat_completions".to_string(),
            token_env: "EFFLAB_L3B_BIND".to_string(),
        },
        approved_mcp: ApprovedMcpConfig::default(),
        expected_tools: Default::default(),
        system_prompt: String::new(),
    };
    assert_eq!(config.model.base_url, "http://[::1]:4312/v1");
}

#[derive(Serialize)]
struct TestRevisionPayload<'a> {
    schema_version: u32,
    session_store_version: u32,
    session_cwd: &'a str,
    model: TestModelPayload<'a>,
    approved_mcp: TestApprovedMcpPayload<'a>,
    expected_tools: &'a BTreeSet<String>,
    system_prompt: &'a str,
}

#[derive(Serialize)]
struct TestModelPayload<'a> {
    model_id: &'a str,
    base_url: &'a str,
    backend: &'a str,
    token_env: &'a str,
}

#[derive(Serialize)]
struct TestApprovedMcpPayload<'a> {
    servers: BTreeMap<&'a str, TestMcpServerPayload<'a>>,
}

#[derive(Serialize)]
struct TestMcpServerPayload<'a> {
    url: &'a str,
}

/// 测试侧独立构造规范化 JSON，不能调用 production renderer 的摘要投影。
fn canonical_revision_json(config: &RuntimeConfigV1) -> String {
    let servers = config
        .approved_mcp
        .servers
        .iter()
        .map(|(name, server)| {
            let McpServerSpec::Http { url } = server else {
                panic!("golden revision 不允许 stdio MCP")
            };
            (name.as_str(), TestMcpServerPayload { url: url.as_str() })
        })
        .collect();
    let payload = TestRevisionPayload {
        schema_version: config.schema_version,
        session_store_version: config.session_store_version,
        session_cwd: &config.session_cwd,
        model: TestModelPayload {
            model_id: &config.model.model_id,
            base_url: &config.model.base_url,
            backend: &config.model.backend,
            token_env: &config.model.token_env,
        },
        approved_mcp: TestApprovedMcpPayload { servers },
        expected_tools: &config.expected_tools,
        system_prompt: &config.system_prompt,
    };
    serde_json::to_string(&payload).expect("测试 canonical JSON 必须可序列化")
}

fn independent_revision(config: &RuntimeConfigV1) -> String {
    format!(
        "sha256:{}",
        independent_sha256_hex(canonical_revision_json(config).as_bytes())
    )
}

/// V2 revision 的独立投影：字段顺序必须与 production RuntimeRevisionPayloadV2 一致。
#[derive(Serialize)]
struct TestRevisionPayloadV2<'a> {
    schema_version: u32,
    session_store_version: u32,
    session_cwd: &'a str,
    model: TestModelPayload<'a>,
    approved_mcp: TestApprovedMcpPayload<'a>,
    expected_tools: &'a BTreeSet<String>,
    system_prompt: &'a str,
    context_window_tokens: u64,
    compact_threshold_percent: u64,
}

/// V2 canonical JSON：测试侧独立构造，不能调用 production renderer 的摘要投影。
fn canonical_revision_json_v2(config: &RuntimeConfigV2) -> String {
    let servers = config
        .approved_mcp
        .servers
        .iter()
        .map(|(name, server)| {
            let McpServerSpec::Http { url } = server else {
                panic!("V2 golden revision 不允许 stdio MCP")
            };
            (name.as_str(), TestMcpServerPayload { url: url.as_str() })
        })
        .collect();
    let payload = TestRevisionPayloadV2 {
        schema_version: config.schema_version,
        session_store_version: config.session_store_version,
        session_cwd: &config.session_cwd,
        model: TestModelPayload {
            model_id: &config.model.model_id,
            base_url: &config.model.base_url,
            backend: &config.model.backend,
            token_env: &config.model.token_env,
        },
        approved_mcp: TestApprovedMcpPayload { servers },
        expected_tools: &config.expected_tools,
        system_prompt: &config.system_prompt,
        context_window_tokens: config.context_window_tokens,
        compact_threshold_percent: config.compact_threshold_percent,
    };
    serde_json::to_string(&payload).expect("V2 测试 canonical JSON 必须可序列化")
}

fn independent_revision_v2(config: &RuntimeConfigV2) -> String {
    format!(
        "sha256:{}",
        independent_sha256_hex(canonical_revision_json_v2(config).as_bytes())
    )
}

/// 独立 SHA-256 实现仅服务测试 golden 与负测摘要重算。
fn independent_sha256_hex(input: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let padded_len = (input.len() + 9).div_ceil(64) * 64;
    let mut padded = vec![0u8; padded_len];
    padded[..input.len()].copy_from_slice(input);
    padded[input.len()] = 0x80;
    padded[padded_len - 8..].copy_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).take(16).enumerate() {
            words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let mut working = state;
        for index in 0..64 {
            let s1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let choose = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
            let temp1 = working[7]
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let majority =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let temp2 = s0.wrapping_add(majority);
            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3].wrapping_add(temp1);
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = temp1.wrapping_add(temp2);
        }
        for index in 0..8 {
            state[index] = state[index].wrapping_add(working[index]);
        }
    }

    state.iter().map(|word| format!("{word:08x}")).collect()
}

#[cfg(not(windows))]
const GOLDEN_CWD: &str = "/var/empty";
#[cfg(windows)]
const GOLDEN_CWD: &str = r"C:\efflab\session";

#[cfg(not(windows))]
const GOLDEN_CANONICAL_JSON: &str = r#"{"schema_version":1,"session_store_version":1,"session_cwd":"/var/empty","model":{"model_id":"golden-model","base_url":"http://127.0.0.1:4312/v1","backend":"chat_completions","token_env":"EFFLAB_L3B_BIND"},"approved_mcp":{"servers":{"alpha":{"url":"http://[::1]:4314/mcp"},"zeta":{"url":"http://127.0.0.1:4313/"}}},"expected_tools":["alpha__search","zeta__search"],"system_prompt":""}"#;
#[cfg(windows)]
const GOLDEN_CANONICAL_JSON: &str = r#"{"schema_version":1,"session_store_version":1,"session_cwd":"C:\\efflab\\session","model":{"model_id":"golden-model","base_url":"http://127.0.0.1:4312/v1","backend":"chat_completions","token_env":"EFFLAB_L3B_BIND"},"approved_mcp":{"servers":{"alpha":{"url":"http://[::1]:4314/mcp"},"zeta":{"url":"http://127.0.0.1:4313/"}}},"expected_tools":["alpha__search","zeta__search"],"system_prompt":""}"#;

#[cfg(not(windows))]
const GOLDEN_REVISION: &str =
    "sha256:8bc2b4db94c3ec2fb03c506c129635f96edef871f1d73fc5a15741cd889dd5e9";
#[cfg(windows)]
const GOLDEN_REVISION: &str =
    "sha256:c4ddd5a6249b3185ff9833910b7858cd506fba7bbd02471d38db9d03682c1dc6";

fn golden_config() -> RuntimeConfigV1 {
    RuntimeConfigV1 {
        schema_version: 1,
        runtime_revision: "ignored-by-independent-payload".to_owned(),
        session_store_version: 1,
        session_cwd: GOLDEN_CWD.to_owned(),
        model: LoopbackModelSpec {
            model_id: "golden-model".to_owned(),
            base_url: "http://127.0.0.1:4312/v1".to_owned(),
            backend: "chat_completions".to_owned(),
            token_env: "EFFLAB_L3B_BIND".to_owned(),
        },
        approved_mcp: ApprovedMcpConfig {
            servers: BTreeMap::from([
                (
                    "zeta".to_owned(),
                    McpServerSpec::Http {
                        url: "http://127.0.0.1:4313/".to_owned(),
                    },
                ),
                (
                    "alpha".to_owned(),
                    McpServerSpec::Http {
                        url: "http://[::1]:4314/mcp".to_owned(),
                    },
                ),
            ]),
        },
        expected_tools: BTreeSet::from(["zeta__search".to_owned(), "alpha__search".to_owned()]),
        system_prompt: String::new(),
    }
}

fn golden_cwd_changed() -> &'static str {
    #[cfg(not(windows))]
    {
        "/var/changed"
    }
    #[cfg(windows)]
    {
        r"C:\efflab\changed"
    }
}

#[test]
fn qualified_tool_name_helper_enforces_shared_wire_shape() {
    assert!(is_qualified_tool_name("demo__search"));
    assert!(is_qualified_tool_name(&format!(
        "demo__tool_{}",
        "x".repeat(64)
    )));

    for invalid in [
        "",
        "demo",
        "demo__",
        "demo__search__extra",
        "1demo__search",
        "demo__1search",
        "demo__search.name",
        "demo__search name",
        "demo__search/tool",
        "demo__search\u{0000}",
        "demo__search\u{001b}[31m",
        "demo__tool__suffix",
    ] {
        assert!(
            !is_qualified_tool_name(invalid),
            "非法 qualified tool name 不得通过共享 helper: {invalid:?}"
        );
    }

    assert!(!is_qualified_tool_name(&format!(
        "{}__search",
        "s".repeat(65)
    )));
}

#[test]
fn prompt_id_helper_enforces_non_empty_control_free_byte_boundary() {
    assert!(is_prompt_id("prompt-1"));
    assert!(is_prompt_id(&"x".repeat(1024)));
    assert!(is_prompt_id(&"é".repeat(512)), "UTF-8 1024 bytes 应通过");

    for invalid in ["", "prompt\n", "prompt\u{0000}", "prompt\u{001f}"] {
        assert!(
            !is_prompt_id(invalid),
            "非法 promptId 不得通过共享 helper: {invalid:?}"
        );
    }
    assert!(!is_prompt_id(&"x".repeat(1025)));
    assert!(
        !is_prompt_id(&"é".repeat(513)),
        "超过 1024 UTF-8 bytes 应拒绝"
    );
}

/// 构造合法 V2 配置；所有 V2 测试共用同一基线形状，只改关注字段。
fn runtime_config_v2_fixture() -> RuntimeConfigV2 {
    RuntimeConfigV2 {
        schema_version: 2,
        runtime_revision: String::new(),
        session_store_version: 1,
        session_cwd: session_cwd_string(),
        model: LoopbackModelSpec {
            model_id: "byok-user-model".to_owned(),
            base_url: "http://127.0.0.1:4312/v1".to_owned(),
            backend: "chat_completions".to_owned(),
            token_env: "EFFLAB_L3B_BIND".to_owned(),
        },
        approved_mcp: ApprovedMcpConfig::default(),
        expected_tools: BTreeSet::new(),
        system_prompt: String::new(),
        context_window_tokens: 200_000,
        compact_threshold_percent: 70,
    }
}

/// V2 渲染输出必须能回读为同值配置，且字段顺序保持 schema_version→新增字段→表。
#[test]
fn runtime_config_v2_round_trips_with_rendered_defaults() {
    let config = runtime_config_v2_fixture();
    let rendered = render_runtime_config_v2(&config).expect("V2 配置必须可渲染");
    assert!(rendered.contains("schema_version = 2"));
    assert!(rendered.contains("context_window_tokens = 200000"));
    assert!(rendered.contains("compact_threshold_percent = 70"));
    assert!(
        rendered.find("context_window_tokens").unwrap() < rendered.find("[model]").unwrap(),
        "新增标量必须在 [model] 表之前渲染"
    );
    let parsed = load_runtime_config_v2_from_str(&rendered).expect("V2 渲染输出必须可回读");
    assert_eq!(parsed.context_window_tokens, 200_000);
    assert_eq!(parsed.compact_threshold_percent, 70);
    assert_eq!(parsed.schema_version, 2);
}

/// V2 缺失新增字段时必须回落到 200k/70% 默认，而不是拒绝或硬编码零值。
#[test]
fn runtime_config_v2_missing_compact_fields_default_to_200k_70() {
    let rendered =
        render_runtime_config_v2(&runtime_config_v2_fixture()).expect("基准 V2 配置必须可渲染");
    let missing = rendered
        .replace("context_window_tokens = 200000\n", "")
        .replace("compact_threshold_percent = 70\n", "");
    let parsed =
        load_runtime_config_v2_from_str(&missing).expect("缺失新增字段的 V2 配置必须按默认值加载");
    assert_eq!(parsed.context_window_tokens, 200_000);
    assert_eq!(parsed.compact_threshold_percent, 70);
}

/// V1 文件内容进入 V2 入口会因 schema_version 判别失败，V2 loader 不会吞错。
#[test]
fn runtime_config_v2_loader_rejects_v1_schema_version() {
    let source = materialize_fixture_source("runtime_config_v1_empty.toml");
    assert_loader_error_v2(&source, "schema_version");
}

/// V2 磁盘 fixture 必须能经 from_str loader 走通字段与 revision 双重校验。
#[test]
fn runtime_config_v2_fixtures_round_trip_through_loader() {
    let empty = materialize_fixture_source_v2("runtime_config_v2_empty.toml");
    let parsed = load_runtime_config_v2_from_str(&empty).expect("V2 empty fixture 必须可加载");
    assert_eq!(parsed.context_window_tokens, 200_000);
    assert_eq!(parsed.compact_threshold_percent, 70);
    assert!(parsed.approved_mcp.servers.is_empty());

    let http = materialize_fixture_source_v2("runtime_config_v2_http_mcp.toml");
    let parsed = load_runtime_config_v2_from_str(&http).expect("V2 HTTP fixture 必须可加载");
    assert_eq!(parsed.expected_tools.iter().next().unwrap(), "demo__search");
    assert_eq!(parsed.approved_mcp.servers.len(), 1);
}

/// V2 上下文窗口与压缩百分比必须走上下界校验：零、超界和超上限都拒绝。
///
/// 非法值在 renderer 校验阶段就被拒绝，因此负测先渲染合法文本再逐字段篡改，
/// 并独立重算 revision，保证断言命中字段校验而不是摘要失败。
#[test]
fn runtime_config_v2_rejects_out_of_bounds_compact_fields() {
    let base = runtime_config_v2_fixture();
    let rendered = render_runtime_config_v2(&base).expect("基准配置必须可渲染");

    for (needle, replacement, expected) in [
        (
            "context_window_tokens = 200000",
            "context_window_tokens = 0",
            "context_window_tokens",
        ),
        (
            "context_window_tokens = 200000",
            "context_window_tokens = 100000001",
            "context_window_tokens",
        ),
        (
            "compact_threshold_percent = 70",
            "compact_threshold_percent = 0",
            "compact_threshold_percent",
        ),
        (
            "compact_threshold_percent = 70",
            "compact_threshold_percent = 101",
            "compact_threshold_percent",
        ),
    ] {
        let tampered = rendered.replacen(needle, replacement, 1);
        let tampered = with_independent_revision_v2(&tampered);
        assert_loader_error_v2(&tampered, expected);
    }

    // renderer 自身也必须 fail-closed：越界值不能等到 loader 才被发现。
    let mut zero_window = base.clone();
    zero_window.context_window_tokens = 0;
    let error =
        render_runtime_config_v2(&zero_window).expect_err("context_window_tokens 为零必须拒绝渲染");
    assert!(format!("{error:#}").contains("context_window_tokens"));

    // 边界值本身必须可接受：上限值与 1/100 都属于合法输入。
    let mut edge = base.clone();
    edge.context_window_tokens = 100_000_000;
    edge.compact_threshold_percent = 100;
    let rendered = render_runtime_config_v2(&edge).expect("边界 V2 配置必须可渲染");
    let parsed = load_runtime_config_v2_from_str(&rendered).expect("边界 V2 配置必须可通过 loader");
    assert_eq!(parsed.context_window_tokens, 100_000_000);
    assert_eq!(parsed.compact_threshold_percent, 100);

    let mut low_percent = base;
    low_percent.context_window_tokens = 1;
    low_percent.compact_threshold_percent = 1;
    let rendered = render_runtime_config_v2(&low_percent).expect("最小边界 V2 配置必须可渲染");
    let parsed =
        load_runtime_config_v2_from_str(&rendered).expect("最小边界 V2 配置必须可通过 loader");
    assert_eq!(parsed.context_window_tokens, 1);
    assert_eq!(parsed.compact_threshold_percent, 1);
}

/// V2 也要拒绝未知字段，避免运行期 wire 扩张破坏闭集。
#[test]
fn runtime_config_v2_rejects_unknown_fields() {
    let rendered =
        render_runtime_config_v2(&runtime_config_v2_fixture()).expect("基准 V2 配置必须可渲染");
    for injected in [
        rendered.replacen(
            "context_window_tokens",
            "unknown_compact = true\ncontext_window_tokens",
            1,
        ),
        rendered.replacen("[model]\n", "[model]\nunknown_model = true\n", 1),
        rendered.replacen(
            "[approved_mcp]\nservers = {}",
            "[approved_mcp]\nservers = {}\nunknown_approved = true",
            1,
        ),
    ] {
        assert_loader_error_v2(&injected, "runtime_config_invalid");
    }
}

/// V1/V2 混合：同一文件名的 V1 内容走 V1 loader，同名 V2 内容走 V2 loader；枚举暴露统一视图。
#[test]
fn runtime_config_mixed_versions_share_one_view() {
    let v1_config: RuntimeConfigV1 = {
        let source = materialize_fixture_source("runtime_config_v1_empty.toml");
        load_runtime_config_v1_from_str(&source).expect("V1 fixture 必须可加载")
    };
    let v2_rendered =
        render_runtime_config_v2(&runtime_config_v2_fixture()).expect("V2 fixture 必须可渲染");
    let v2_config = load_runtime_config_v2_from_str(&v2_rendered).expect("V2 fixture 必须可加载");

    let v1_view = RuntimeConfig::V1(v1_config.clone());
    let v2_view = RuntimeConfig::V2(v2_config.clone());
    assert_eq!(v1_view.context_window_tokens(), 200_000);
    assert_eq!(v1_view.compact_threshold_percent(), 70);
    assert_eq!(v2_view.context_window_tokens(), 200_000);
    assert_eq!(v2_view.compact_threshold_percent(), 70);
    assert_eq!(v1_view.session_cwd(), v1_config.session_cwd);
    assert_eq!(v2_view.session_cwd(), v2_config.session_cwd);
    assert_eq!(v1_view.model().base_url, v2_view.model().base_url);
}

/// V2 的 session_cwd 与共享模型约束必须与 V1 完全一致。
#[test]
fn runtime_config_v2_keeps_shared_path_and_model_contract() {
    let base = runtime_config_v2_fixture();

    let mut relative_cwd = base.clone();
    relative_cwd.session_cwd = "relative/path".to_owned();
    let error = render_runtime_config_v2(&relative_cwd).expect_err("相对 session_cwd 必须拒绝渲染");
    assert!(format!("{error:#}").contains("session_cwd"));

    let mut escaped_cwd = base.clone();
    escaped_cwd.session_cwd = "/safe/../session".to_owned();
    let error = render_runtime_config_v2(&escaped_cwd).expect_err("带 .. 的路径必须拒绝渲染");
    assert!(format!("{error:#}").contains("session_cwd"));

    let mut upstream_url = base.clone();
    upstream_url.model.base_url = "http://localhost:4312/v1".to_owned();
    let error = render_runtime_config_v2(&upstream_url).expect_err("非回环 URL 必须拒绝渲染");
    assert!(format!("{error:#}").contains("model.base_url"));

    let mut wrong_backend = base.clone();
    wrong_backend.model.backend = "responses".to_owned();
    let error = render_runtime_config_v2(&wrong_backend).expect_err("非 chat_completions 必须拒绝");
    assert!(format!("{error:#}").contains("model.backend"));

    let tampered = render_runtime_config_v2(&base)
        .expect("基准 V2 必须可渲染")
        .replacen("schema_version = 2", "schema_version = 1", 1);
    assert_loader_error_v2(&tampered, "schema_version");
}

/// Host 新写的 V2 文件与 V1 文件路径并列时，路径校验仍拒绝目录逃逸与未知版本名。
#[test]
fn runtime_config_v2_from_path_round_trip_and_escape_rejection() {
    let (dir, path) = write_config_v2(&runtime_config_v2_fixture());
    let loaded = load_runtime_config_v2(&path).expect("V2 文件必须可从路径加载");
    assert_eq!(loaded.schema_version, 2);

    let escaped = dir.path().join("../runtime-config.v2.toml");
    let error = load_runtime_config_v2(&escaped).expect_err("目录逃逸的 V2 路径必须拒绝读取");
    assert!(format!("{error:#}").contains("读取 RuntimeConfigV2 TOML 失败"));
}
