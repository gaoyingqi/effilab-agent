# Windows Agent Kit capability 已开放

日期：2026-09-08
仓库：`effilab-agent` 与产品仓 `ai_music_organizer`

## 根因

Windows 发布版能找到 `efflab-agent-sidecar.exe`，但 Host 的 `supervisor::capability()` 仍在 `cfg(windows)` 下固定返回 `Unavailable { SidecarHardeningUnavailable }`。Host 因此在 `GetCapability` 阶段拒绝进入 sidecar 流程，Web 最终显示 Agent 不可用。

## 本次改动

- `crates/efflab/efflab-agent-host/src/supervisor.rs`：Windows 与非 Windows 统一返回 `SupervisorCapability::Available`。
- `crates/efflab/efflab-agent-host/tests/pr0_windows_hardening.rs`：Windows 回归测试改为要求 capability 为 `Available`，并保留五项 Windows API 符号链接测试。
- 产品仓后续重新构建 release sidecar 与 app，继续使用当前 exe 同级的 Windows sidecar 资源路径；不改 Kit JSON、Tauri command 或前端错误映射。

## 已完成的 Windows 证据

在 sibling 仓根执行：

- `cargo test --locked -p efflab-agent-host --test pr0_windows_hardening -- --nocapture`
  - 修复前红测：`windows_sidecar_capability_is_available_after_hardening` 失败，实际为 `Unavailable { SidecarHardeningUnavailable }`；五项 API 链接测试通过。
  - 修复后预期：2 passed。
- `cargo test --locked -p efflab-agent-sidecar --test acp_windows -- --nocapture`
  - 既有基线：1 passed，Windows sidecar 完成最小 ACP 回合。

## 边界与未验证项

- 必须在产品 release 重建后重新验证 `app.exe` 实际加载的是包含本次 Host 修复的版本。
- 需要重新确认用户启动 Agent Kit 后生成与 `app.log` 同级的 `{app_log_dir}/sidecar.log`，并检查日志不含 API key、token 或 Authorization 值。
- Authenticode 签名、MSIX 安装、真实商店安装和真实 BYOK 仍未在本条记录中证明。
- 若 Windows 真实启动链路失败，回滚 `capability()` 为 `Unavailable { reason: SidecarHardeningUnavailable }`，并恢复旧回归断言。

## 回滚顺序

1. 恢复 Host `capability()` 的 Windows unavailable 分支。
2. 恢复 Windows capability 回归测试的 unavailable 断言。
3. 重新构建 Host、sidecar 和产品 release；不要只替换单个二进制。

## 2026-09-09 普通 Debug 验证状态覆盖

用户要求本轮不构建主应用 release，以下只记录普通 Debug 结果：

- 产品仓串行执行 `cargo build --locked --manifest-path src-tauri/Cargo.toml --features tauri/custom-protocol`，退出码 0，输出为 `Finished dev profile`；生成 `build/debug/app.exe`。
- 产品 Debug 构建入口 `tools/tauri_build_debug.ps1` 的构建流程也已进入并完成 Debug 构建；首次透传 `--no-bundle` 的 PowerShell 调用因参数歧义在编译前退出，随后改用 `-ExtraArgs '--no-bundle'`。
- 最终串行产物检查：`build/debug/app.exe`、`build/debug/efflab-agent-sidecar.exe` 和 `src-tauri/resources/efflab-agent-sidecar.exe` 均存在、非 reparse point；同级 sidecar 与资源 sidecar 长度均为 `6457856`，SHA-256 均为 `985AF1C412A78399E6D3B9964994C838D2023D94A7E61FD9701D82972528EACC`；同级 sidecar `--version` 退出码 0。
- 构建脚本仍按现行资源合同在 nested target 中执行 `cargo build -p efflab-agent-sidecar --release --locked`；因此“主应用是 Debug”不等于“sidecar 使用 Debug 编译”。资源 sidecar 与应用同级 sidecar 最终已串行复核为同一内容。
- 验证过程中发现 sibling 普通 Cargo 测试与产品共享产品仓的 `build` target 时，Cargo 的测试二进制可能覆盖 `build/debug/efflab-agent-sidecar.exe`。该差异不是运行时路径逻辑变化；最终通过停止共享 target 写入并串行重跑产品 Debug build 修正，再做哈希断言。后续应避免在产品 Debug sidecar 产物复核前并行运行 sibling Cargo 命令。

### 本轮命令结果

- 产品 adapter：`Set-Location src-tauri; cargo test --locked --lib sidecar_log_path`，`1 passed`。
- sibling Host/sidecar：`pr0_windows_hardening` `2 passed`、`acp_windows` `1 passed`、`supervisor windows_` `3 passed`。
- 产品合同：四个 sidecar/MSIX/FFmpeg 测试文件，`34 passed | 1 skipped`。
- 产品与 sibling `git diff --check`：退出码 0，仅有 Git 的 LF/CRLF 提示。

### 未验证边界

- 本轮未构建主应用 release；此前 release 主应用链接因 LTO/内存资源未完成，不能把旧的 `build/release/app.exe` 当作本次修复产物。
- 未完成真实 Tauri UI 点击、产品 Host→sidecar→ACP 闭环、Authenticode 签名、MSIX/商店安装和真实 BYOK 验证；现有 sibling ACP 黑盒与 Host 定向测试不替代这些验证。
- 产品 `src-tauri/resources/efflab-agent.expected-rev` 仍为 `fd098155427574afc89185f8769964a2012b5aed`，sibling 当前 HEAD 为 `93cc8f12181031775e5f8281c551328812de93fa`，两者不匹配；没有 matched release tuple，不能宣称发布闭包或 S4。
- Web 仓未修改；Kit JSON、ACP、reducer/hook、Tauri command 和真实 BYOK 接缝未改。
