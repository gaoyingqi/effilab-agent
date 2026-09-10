//! Windows 真实 sidecar ACP 回合黑盒测试。
//!
//! 该测试只使用受保护的 Windows fixture、loopback 模型和真实 release/debug sidecar
//! 二进制，证明 Windows 不是只通过 capability 编译门禁，而是可以完成最小 ACP 回合。

#![cfg(windows)]

mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use common::acp_client::AcpClient;
use efflab_agent_contract::{
    ApprovedMcpConfig, LoopbackModelSpec, RuntimeConfigV1, render_runtime_config_v1,
};
use tempfile::TempDir;

const SIDECAR_BIN: &str = env!("CARGO_BIN_EXE_efflab-agent-sidecar");
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const EXIT_TIMEOUT: Duration = Duration::from_secs(15);
const L3B_BIND: &str = "efflab-windows-test-binding";

/// 为 Windows 黑盒测试创建一个使用共享平台原语的受保护 loopback 模型。
struct ModelServer {
    address: std::net::SocketAddr,
    request_count: Arc<AtomicUsize>,
    authorization: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ModelServer {
    /// 启动只服务一次请求的 Chat Completions SSE server。
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("绑定 Windows ACP 模型 loopback");
        listener
            .set_nonblocking(true)
            .expect("设置 Windows ACP 模型 listener");
        let address = listener.local_addr().expect("读取 Windows ACP 模型地址");
        let request_count = Arc::new(AtomicUsize::new(0));
        let authorization = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let request_count_for_thread = Arc::clone(&request_count);
        let authorization_for_thread = Arc::clone(&authorization);
        let stop_for_thread = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !stop_for_thread.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        if let Some((headers, _body)) = read_http_request(&mut stream) {
                            if let Some(value) = headers.iter().find_map(|(name, value)| {
                                name.eq_ignore_ascii_case("authorization")
                                    .then(|| value.clone())
                            }) && let Ok(mut values) = authorization_for_thread.lock()
                            {
                                values.push(value);
                            }
                            request_count_for_thread.fetch_add(1, Ordering::AcqRel);
                            write_sse_response(&mut stream);
                        }
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            address,
            request_count,
            authorization,
            stop,
            thread: Some(thread),
        }
    }

    /// 返回 RuntimeConfigV1 所需的字面量 loopback URL。
    fn base_url(&self) -> String {
        format!("http://{}/v1", self.address)
    }

    /// 返回 sidecar 实际使用的 Chat Completions endpoint，供日志脱敏回归断言使用。
    fn endpoint(&self) -> String {
        format!("http://{}/v1/chat/completions", self.address)
    }

    /// 等待 sidecar 发出模型请求。
    fn wait_for_request(&self) {
        let deadline = Instant::now() + EXIT_TIMEOUT;
        while self.request_count.load(Ordering::Acquire) == 0 {
            assert!(Instant::now() < deadline, "Windows sidecar 未请求 loopback 模型");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// 返回模型端点收到的授权头，确认 sidecar 使用的是 binding token。
    fn authorization_values(&self) -> Vec<String> {
        self.authorization
            .lock()
            .expect("读取模型授权头")
            .clone()
    }
}

impl Drop for ModelServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// 读取本地测试 HTTP 请求的 headers 与固定长度正文。
fn read_http_request(stream: &mut TcpStream) -> Option<(Vec<(String, String)>, Vec<u8>)> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut buffer).ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() > 64 * 1024 {
            return None;
        }
    };
    let header_text = String::from_utf8(bytes[..header_end].to_vec()).ok()?;
    let mut lines = header_text.split("\r\n");
    let _request_line = lines.next()?;
    let headers = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect::<Vec<_>>();
    let content_length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())?;
    while bytes.len() < header_end + content_length {
        let read = stream.read(&mut buffer).ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Some((
        headers,
        bytes[header_end..header_end + content_length].to_vec(),
    ))
}

/// 返回最小合法的流式 Chat Completions 响应。
fn write_sse_response(stream: &mut TcpStream) {
    let response = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Connection: close\r\n",
        "Content-Type: text/event-stream\r\n",
        "\r\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"windows response\"}}]}\n\n",
        "data: [DONE]\n\n"
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Both);
}

/// 黑盒 fixture 的受保护 home、session cwd 和 runtime config。
struct Fixture {
    _temporary: TempDir,
    home: PathBuf,
    session_cwd: PathBuf,
    runtime_config: PathBuf,
}

impl Fixture {
    /// 创建 Windows 平台原语可以验证的临时 fixture。
    fn new(model_url: String) -> Self {
        let temporary = tempfile::Builder::new()
            .prefix("efflab-agent-sidecar-acp-windows-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("创建 Windows ACP fixture 根目录");
        let home = temporary.path().join("home");
        let session_cwd = temporary.path().join("session-cwd");
        efflab_agent_platform::create_private_directory(&home).expect("创建 Windows 私有 home");
        efflab_agent_platform::create_private_directory(&session_cwd)
            .expect("创建 Windows 私有 session cwd");

        let config = RuntimeConfigV1 {
            schema_version: 1,
            runtime_revision: String::new(),
            session_store_version: 1,
            session_cwd: session_cwd
                .to_str()
                .expect("Windows ACP session cwd 必须是 UTF-8")
                .to_owned(),
            model: LoopbackModelSpec {
                model_id: "efflab-windows-test-model".to_owned(),
                base_url: model_url,
                backend: "chat_completions".to_owned(),
                token_env: "EFFLAB_L3B_BIND".to_owned(),
            },
            approved_mcp: ApprovedMcpConfig::default(),
            expected_tools: Default::default(),
            system_prompt: String::new(),
        };
        let rendered = render_runtime_config_v1(&config).expect("渲染 Windows ACP runtime config");
        let runtime_config = home.join("runtime-config.v1.toml");
        efflab_agent_platform::atomic_write_private(&runtime_config, rendered.as_bytes())
            .expect("写入 Windows 受保护 runtime config");

        Self {
            _temporary: temporary,
            home,
            session_cwd,
            runtime_config,
        }
    }

    /// 构造清理环境后的 sidecar 命令，只注入 Windows 运行时必要变量和 binding。
    fn command(&self) -> Command {
        let mut command = Command::new(SIDECAR_BIN);
        command
            .arg("--runtime-config")
            .arg(&self.runtime_config)
            .arg("--home")
            .arg(&self.home)
            .arg("--session-cwd")
            .arg(&self.session_cwd)
            .arg("--stdio")
            .current_dir(&self.session_cwd)
            .env_clear()
            .env("EFFLAB_L3B_BIND", L3B_BIND)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for name in [
            "PATH",
            "SystemRoot",
            "WINDIR",
            "ComSpec",
            "PATHEXT",
            "TEMP",
            "TMP",
            "USERPROFILE",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
    }
}

/// sidecar 子进程的有界收尾器，避免黑盒测试遗留进程。
struct TestProcess {
    child: Child,
    stderr_thread: Option<JoinHandle<Vec<u8>>>,
}

impl TestProcess {
    /// 启动 sidecar，并在独立线程持续 drain stderr。
    fn spawn(fixture: &Fixture) -> (Self, AcpClient) {
        let mut command = fixture.command();
        #[allow(clippy::disallowed_methods)]
        let mut child = command.spawn().expect("启动 Windows sidecar 黑盒进程");
        let stdin = child.stdin.take().expect("Windows sidecar stdin pipe");
        let stdout = child.stdout.take().expect("Windows sidecar stdout pipe");
        let mut stderr = child.stderr.take().expect("Windows sidecar stderr pipe");
        let stderr_thread = thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes);
            bytes
        });
        let client = AcpClient::new(stdin, stdout);
        (
            Self {
                child,
                stderr_thread: Some(stderr_thread),
            },
            client,
        )
    }

    /// 关闭 stdin，等待正常 EOF，并返回 sidecar stderr 供日志合同断言使用。
    fn finish(&mut self, client: &mut AcpClient) -> String {
        client.close_stdin();
        let deadline = Instant::now() + EXIT_TIMEOUT;
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Ok(None) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    panic!("Windows sidecar 未在 {EXIT_TIMEOUT:?} 内退出");
                }
                Err(error) => panic!("检查 Windows sidecar 退出状态失败: {error}"),
            }
        };
        let stderr = self
            .stderr_thread
            .take()
            .expect("stderr drain thread")
            .join()
            .unwrap_or_default();
        assert!(
            status.success(),
            "Windows sidecar ACP 回合应正常退出：status={status:?}; stderr={:?}",
            String::from_utf8_lossy(&stderr)
        );
        String::from_utf8_lossy(&stderr).into_owned()
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(thread) = self.stderr_thread.take() {
            let _ = thread.join();
        }
    }
}

/// 构造 ACP initialize 请求的固定最小参数。
fn initialize_params() -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": 1,
        "clientCapabilities": {
            "fs": {"readTextFile": false, "writeTextFile": false},
            "terminal": false
        },
        "clientInfo": {"name": "efflab-windows-test", "version": "1"}
    })
}

/// 断言 stdout 所有非空行都是 JSON-RPC，防止日志污染 ACP 通道。
fn assert_jsonrpc_lines(lines: &[String]) {
    assert!(!lines.is_empty(), "Windows ACP 回合必须产生 JSON-RPC 输出");
    for (index, line) in lines.iter().enumerate() {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("Windows sidecar stdout 第 {index} 行不是 JSON: {error}"));
        assert_eq!(value["jsonrpc"], "2.0");
        assert!(
            value.get("id").is_some()
                || value.get("method").and_then(serde_json::Value::as_str).is_some(),
            "Windows sidecar stdout 第 {index} 行缺少 JSON-RPC id 或 method"
        );
    }
}

#[test]
fn windows_sidecar_completes_minimal_acp_round_trip() {
    let model = ModelServer::start();
    let fixture = Fixture::new(model.base_url());
    let (mut process, mut client) = TestProcess::spawn(&fixture);

    let initialized = client
        .request("initialize", initialize_params(), REQUEST_TIMEOUT)
        .expect("Windows sidecar initialize 必须成功");
    assert_eq!(initialized["result"]["protocolVersion"], 1);
    assert_eq!(
        initialized["result"]["_meta"]["efflabRuntime"],
        "minimal-v1"
    );

    let session = client
        .request(
            "session/new",
            serde_json::json!({
                "cwd": fixture.session_cwd,
                "mcpServers": []
            }),
            REQUEST_TIMEOUT,
        )
        .expect("Windows sidecar session/new 必须成功");
    let session_id = session["result"]["sessionId"]
        .as_str()
        .expect("Windows session/new 必须返回 sessionId")
        .to_owned();

    let response = client
        .request(
            "session/prompt",
            serde_json::json!({
                "sessionId": session_id,
                "prompt": [{"type": "text", "text": "Windows ACP smoke"}],
                "_meta": {"promptId": "windows-acp-smoke"}
            }),
            REQUEST_TIMEOUT,
        )
        .expect("Windows sidecar session/prompt 必须成功");
    assert_eq!(response["result"]["stopReason"], "end_turn");

    model.wait_for_request();
    assert_eq!(model.authorization_values(), [format!("Bearer {L3B_BIND}")]);
    assert_jsonrpc_lines(&client.raw_lines());
    let _ = process.finish(&mut client);
}

#[test]
fn windows_sidecar_stderr_excludes_prompt_endpoint_and_model_payloads() {
    let model = ModelServer::start();
    let fixture = Fixture::new(model.base_url());
    let (mut process, mut client) = TestProcess::spawn(&fixture);
    let _ = client
        .request("initialize", initialize_params(), REQUEST_TIMEOUT)
        .expect("Windows sidecar initialize 必须成功");
    let session = client
        .request(
            "session/new",
            serde_json::json!({
                "cwd": fixture.session_cwd,
                "mcpServers": []
            }),
            REQUEST_TIMEOUT,
        )
        .expect("Windows sidecar session/new 必须成功");
    let session_id = session["result"]["sessionId"]
        .as_str()
        .expect("Windows session/new 必须返回 sessionId")
        .to_owned();
    let prompt_secret = "windows-log-prompt-secret";
    let response_secret = "windows response";
    let response = client
        .request(
            "session/prompt",
            serde_json::json!({
                "sessionId": session_id,
                "prompt": [{"type": "text", "text": prompt_secret}],
                "_meta": {"promptId": "windows-log-redaction"}
            }),
            REQUEST_TIMEOUT,
        )
        .expect("Windows sidecar session/prompt 必须成功");
    assert_eq!(response["result"]["stopReason"], "end_turn");
    model.wait_for_request();

    let stderr = process.finish(&mut client);
    for forbidden in [
        prompt_secret,
        response_secret,
        L3B_BIND,
        &model.endpoint(),
    ] {
        assert!(
            !stderr.contains(forbidden),
            "sidecar stderr 不得包含敏感或正文内容 {forbidden:?}: {stderr:?}"
        );
    }
    for forbidden_field in ["payload=", "user_text=", "assistant_text=", "endpoint="] {
        assert!(
            !stderr.contains(forbidden_field),
            "sidecar stderr 不得包含正文日志字段 {forbidden_field:?}: {stderr:?}"
        );
    }
}

// 保持 Path 在 Windows 条件代码中明确可见，避免未来扩展 fixture 时误用字符串路径。
#[allow(dead_code)]
fn _assert_absolute_path(path: &Path) {
    assert!(path.is_absolute());
}

// 保持 ExitStatus 在黑盒 helper 的类型合同中明确，便于平台测试扩展退出码断言。
#[allow(dead_code)]
fn _assert_success(status: ExitStatus) {
    assert!(status.success());
}
