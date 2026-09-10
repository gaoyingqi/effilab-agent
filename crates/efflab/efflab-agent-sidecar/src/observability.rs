//! sidecar 本地可观测性边界。
//!
//! 生命周期事件只发固定字段到 stderr。DEBUG 级别只记录 ACP JSON-RPC 的结构化元数据，
//! 不记录请求/响应 payload；binding、Authorization 和其它用户内容都不会进入日志。

use serde_json::Value;

/// ACP stdout 尚未成行的缓冲上限，避免无换行攻击撑爆内存。
const ACP_WIRE_PENDING_MAX: usize = 1_048_576;
/// 记录 ACP runtime 已开始接管 stdio。
pub(crate) fn runtime_started() {
    tracing::debug!(event = "acp_runtime_started", "ACP runtime 已启动");
}

/// 记录 stdin reader 已看到 EOF。
pub(crate) fn stdin_eof() {
    tracing::debug!(event = "stdin_eof", "sidecar stdin 已到 EOF");
}

/// 记录 ACP gateway 已完成 EOF 收尾。
pub(crate) fn acp_eof() {
    tracing::debug!(event = "acp_eof", "ACP gateway 已完成 EOF 收尾");
}

/// 记录 ACP I/O 发生非敏感传输错误。
pub(crate) fn acp_io_failed() {
    tracing::debug!(event = "acp_io_failed", "ACP gateway I/O 失败");
}

/// 记录 gateway receiver 已停止。
pub(crate) fn gateway_stopped() {
    tracing::debug!(event = "acp_gateway_stopped", "ACP gateway receiver 已停止");
}

/// 记录 stdin bridge 因下游关闭而停止。
pub(crate) fn stdin_bridge_stopped() {
    tracing::debug!(event = "stdin_bridge_stopped", "stdin bridge 已停止");
}

/// 记录 runtime 已释放 ACP transport 与本地状态。
pub(crate) fn runtime_cleanup() {
    tracing::debug!(event = "acp_runtime_cleanup", "ACP runtime 清理完成");
}

/// 记录收到 initialize，但不记录客户端字段。
pub(crate) fn initialize_received() {
    tracing::debug!(event = "acp_initialize", "收到 ACP initialize");
}

/// 记录创建了一个内存 session。
pub(crate) fn session_created() {
    tracing::debug!(event = "session_created", "内存 session 已创建");
}

/// 记录 session/load 的结果，不记录 session 标识。
pub(crate) fn session_loaded(found: bool) {
    tracing::debug!(event = "session_loaded", found, "处理 ACP session/load");
}

/// 记录 session/list 返回的数量。
pub(crate) fn sessions_listed(count: usize) {
    tracing::debug!(event = "sessions_listed", count, "处理 ACP session/list");
}

/// 记录 session/close 已删除内存与持久化状态，不记录 session 标识。
pub(crate) fn session_closed() {
    tracing::debug!(event = "session_closed", "处理 ACP session/close");
}

/// 记录最小 prompt 已完成，不记录 prompt 内容。
pub(crate) fn prompt_completed() {
    tracing::debug!(event = "prompt_completed", "最小 ACP prompt 已完成");
}

/// 记录取消通知是否对应已知 session，不记录 session 标识。
pub(crate) fn cancel_received(known_session: bool) {
    tracing::debug!(
        event = "session_cancel",
        known_session,
        "收到 ACP session/cancel"
    );
}

/// 记录扩展方法已返回最小 catalog。
pub(crate) fn extension_served() {
    tracing::debug!(event = "mcp_catalog_served", "返回最小 MCP catalog");
}

/// 记录未知扩展被拒绝，不回显方法名。
pub(crate) fn extension_rejected() {
    tracing::debug!(
        event = "extension_method_not_found",
        "拒绝未知 ACP extension"
    );
}

/// 解析并记录一条 ACP JSON-RPC 行，仅记录结构化元数据，不记录 payload。
pub(crate) fn log_acp_wire_bytes(direction: &'static str, line: &[u8]) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let text = String::from_utf8_lossy(line);
    let trimmed = text.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        return;
    }
    let payload_bytes = trimmed.len();
    match serde_json::from_str::<Value>(trimmed) {
        Ok(value) => {
            let has_method = value.get("method").is_some();
            let has_id = value.get("id").is_some();
            let kind = if has_method {
                if has_id { "request" } else { "notification" }
            } else if value.get("error").is_some() {
                "error_response"
            } else {
                "response"
            };
            tracing::debug!(
                event = "acp_wire",
                direction,
                kind,
                has_method,
                has_id,
                has_error = value.get("error").is_some(),
                payload_bytes,
                "ACP Host↔sidecar 消息"
            );
        }
        Err(_) => {
            tracing::debug!(
                event = "acp_wire",
                direction,
                kind = "unparsed",
                payload_bytes,
                "ACP Host↔sidecar 非 JSON 行"
            );
        }
    }
}

/// 从 stdout 缓冲中拆出完整 JSON-RPC 行并记入 DEBUG。
pub(crate) fn drain_acp_stdout_lines(pending: &mut Vec<u8>) {
    while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
        let line: Vec<u8> = pending.drain(..=newline).collect();
        log_acp_wire_bytes("sidecar_to_host", &line);
    }
    if pending.len() > ACP_WIRE_PENDING_MAX {
        log_acp_wire_bytes("sidecar_to_host", pending);
        pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_acp_stdout_lines_consumes_complete_json_lines() {
        let mut pending = b"{\"jsonrpc\":\"2.0\",\"method\":\"session/update\"}\npartial".to_vec();
        drain_acp_stdout_lines(&mut pending);
        assert_eq!(pending, b"partial");
    }
}
