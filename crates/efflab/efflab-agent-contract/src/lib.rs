//! Efflab Agent Kit 的无运行时共享契约。
//!
//! 本 crate 只承载 Host 与 sidecar 共用的校验、DTO 和 TOML 渲染；不得引入
//! grok-shell、ACP runtime 或进程管理依赖。

pub mod host_contract;
pub mod mcp_config;
pub mod model;
pub mod render;
pub mod stdio_mcp;

pub use host_contract::{
    HOST_ACP_PROTOCOL_VERSION, HostPolicy, HostRejection, PromptTextRejection, is_prompt_id,
    validate_host_request, validate_prompt_text,
};
pub use mcp_config::{ApprovedMcpConfig, McpServerSpec, is_qualified_tool_name, is_server_name};
pub use model::{
    DEFAULT_COMPACT_THRESHOLD_PERCENT, DEFAULT_CONTEXT_WINDOW_TOKENS, LoopbackModelSpec,
    RUNTIME_SCHEMA_VERSION_V2, RuntimeConfig, RuntimeConfigV1, RuntimeConfigV2, SidecarModelSpec,
};
pub use render::{
    RUNTIME_CONFIG_V1_FILENAME, RUNTIME_CONFIG_V2_FILENAME, is_literal_loopback_http_url,
    load_runtime_config_v1, load_runtime_config_v1_from_str, load_runtime_config_v2,
    load_runtime_config_v2_from_str, render_authoritative_config, render_runtime_config_v1,
    render_runtime_config_v2, validate_authoritative_config, validate_session_cwd,
};
pub use stdio_mcp::deny_stdio_mcp;
