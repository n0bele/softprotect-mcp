# SoftProtect MCP

把 SoftProtect 加壳能力接进 AI IDE / Agent 的 MCP 服务端。**stdio 传输，无 SSE、无端口、无后台常驻进程**。

```
IDE/Agent  ──stdio(NDJSON JSON-RPC)──▶  softprotect-mcp  ──HTTPS + Bearer sp_xxx──▶  服务端 /api/v1/*
                                          ├ 本地扫描/方案（不上传）
                                          ├ 任务模式（立即返回 job_id + 轮询）
                                          └ 基线对比式功能回测
```

API 密钥**只存在于 MCP 进程的配置文件/环境变量**，任何工具参数里都没有密钥字段——即使模型被提示注入，也拿不到密钥。

---

## 0. 安装

**方式 A：直接下载二进制**（推荐，无需任何环境）——到 [Releases](https://github.com/n0bele/softprotect-mcp/releases) 下载对应平台的 `softprotect-mcp-<os>-<arch>`（Windows 版带 `.exe`），放到 PATH 或任意目录，从第 2 步「生成配置模板」开始。

**方式 B：源码构建**（Go ≥ 1.24，零第三方依赖）：

```bash
git clone https://github.com/n0bele/softprotect-mcp && cd softprotect-mcp
go build -o softprotect-mcp ./cmd/softprotect-mcp
```

## 1. 30 秒上手

```bash
# 2) 生成配置模板
./softprotect-mcp --init-config ~/.config/softprotect-mcp/config.json
#    编辑：base_url + api_key（Web 后台「API 密钥」生成，sp_ 开头）

# 3) 自检（协议 + 连通性 + 鉴权）
./softprotect-mcp --config ~/.config/softprotect-mcp/config.json --self-test

# 4) 全链路自检（上传→加壳→下载→功能回测，会真实产生一个任务）
./softprotect-mcp --config ~/.config/softprotect-mcp/config.json --self-test-file ./bin/App.dll
```

## 2. 配置

```json
{
  "base_url": "https://softprotect.si",
  "api_key": "sp_xxxxxxxxxxxxxxxx",
  "work_dir": "~/SoftProtectMCP",
  "poll":   { "initial_interval_ms": 800, "max_interval_ms": 5000, "max_wait_s": 1800 },
  "verify": { "default_profile": "run", "timeout_s": 300 },
  "record": { "path": "data/history.jsonl", "keep_days": 180 }
}
```

| 优先级 | 来源 |
|---|---|
| 1 | 环境变量 `SOFTPROTECT_BASE_URL` / `SOFTPROTECT_API_KEY` / `SOFTPROTECT_WORK_DIR` |
| 2 | `--config <path>` |
| 3 | `~/.config/softprotect-mcp/config.json`、`~/.softprotect-mcp.json`、`./softprotect-mcp.json` |

`--print-config` 会打印解析后的配置，密钥显示为 `sp_f08…01bb`（前 6 位 + 后 4 位）。

> **不要用 `X-Api-Key` 全局脚本密钥**：实测该通道每次请求生成新的匿名会话，上传记录随后找不到（`400 err.upload_not_found`）。本服务只支持 `sp_` 用户密钥，并在启动时用 `GET /api/v1/jobs` 验活。

## 3. 工具（9 个）

| 工具 | 作用 | 阻塞? |
|---|---|---|
| `sp_ping` | 服务端可达性、密钥有效性、工作目录、版本 | 否（<1s） |
| `sp_scan_project` | **本地**识别 PE/.NET/ELF/Mach-O + 枚举函数（.NET 无需 pdb） | 否 |
| `sp_build_plan` | 生成可解释方案：预设 + 函数清单（带打分/理由）+ 风险 | 否 |
| `sp_upload` | 上传产物（可带 .pdb/.map），返回权威 `functions[]` | 是（按文件大小） |
| `sp_protect` | 建任务，**立即返回** `job_id`（202 语义） | 否 |
| `sp_job_status` | 单次查询状态/进度/排队位，可 `wait_s` 内部轮询 | 可选 |
| `sp_fetch_result` | 下载产物 + sha256 校验 + 字节数校验 | 是（按产物大小） |
| `sp_verify` | **基线对比**功能回测（run / tests / smoke） | 是（按用例） |
| `sp_history` | 本地任务记录（JSONL） | 否 |

推荐顺序：`sp_ping → sp_scan_project → sp_build_plan → sp_upload → sp_protect → sp_job_status → sp_fetch_result → sp_verify`

## 4. IDE / Agent 接入

> WorkBuddy / Codex / Claude / DeepSeek Harness 四平台的逐项配置见
> [PLATFORMS.md](PLATFORMS.md)。

**Claude Code**

```bash
claude mcp add softprotect -- softprotect-mcp --config ~/.config/softprotect-mcp/config.json
```

**Codex CLI**（`~/.codex/config.toml`）

```toml
[mcp_servers.softprotect]
command = "softprotect-mcp"
args = ["--config", "/home/me/.config/softprotect-mcp/config.json"]
```

**Cline / Roo Code / Cursor**（`mcp_settings.json` 或 `.cursor/mcp.json`，结构相同）

```json
{
  "mcpServers": {
    "softprotect": {
      "command": "softprotect-mcp",
      "args": ["--config", "/home/me/.config/softprotect-mcp/config.json"]
    }
  }
}
```

**自研 harness / CI**

```bash
python scripts/mcp_probe.py --exe ./softprotect-mcp --config cfg.json list
python scripts/mcp_probe.py --exe ./softprotect-mcp --config cfg.json call sp_ping
python scripts/mcp_probe.py --exe ./softprotect-mcp --config cfg.json call sp_scan_project '{"paths":["C:/proj/bin/App.dll"]}'
```

`scripts/mcp_probe.py` 是一份 120 行的最小 MCP 客户端（只用标准库），可以直接抄进自己的工具链。

## 5. 为什么这样设计

### 5.1 长耗时任务 = 立即返回 + 轮询

`sp_protect` 只等到服务端 202 就返回 `job_id`；`sp_job_status` 每次一个 HTTP GET。**不使用服务端已有的 `/events` SSE 通道**：SSE 要求长连接与事件流解析，在 stdio 客户端里既难做超时也很难恢复，轮询天然可重试、可跨进程续查（`job_id` 存本地记录里）。

`sp_job_status` 支持 `wait_s`（≤300）让单次调用内部轮询到结束，减少"多轮对话"，但仍是轮询。

### 5.2 验证必须采基线

只跑受保护产物"看起来正常"没有意义——本仓库历史上多次出现"能加壳、能启动、但功能已坏"。`sp_verify` 强制先在**原始产物**上跑同一套动作：

| 判定 | 条件 |
|---|---|
| `fail` | 产物字节与原始相同（假保护）/ 退出码变化 / 期望正则不再命中 / 无法启动 |
| `degraded` | 退出码一致但规范化输出不同（路径、耗时等差异也算） |
| `pass` | 退出码 + 规范化输出完全一致 |

`profile=tests` 会把受保护产物**临时替换**到原路径跑项目测试，跑完 `defer` 还原原始字节（并保留 `.sp-orig-backup`）。

### 5.3 记录

`<work_dir>/data/history.jsonl`，append-only，同 `job_id` 以最后一条为准。选 JSONL 而不是 SQLite：单文件静态二进制、无 CGO、零依赖，任务量级只有每天几十~几百条，而且人能直接读、直接删。

## 6. 实测记录（2026-10-19，服务端 v1.6.3 本机实例）

| 验证 | 方法与样本 | 结果 |
|---|---|---|
| 全链路 | `--self-test-file net_virt.exe`（.NET x64，3 方法） | 13/13 步通过，`verdict=pass`，产物 239616 B |
| 扫描差分 | 本地解析 vs 服务端枚举：net_virt/net_vp/hello_net/testdll + 5×ELF | **9/9 一致**；`net_vp.exe` 两侧均 400 条（同为上限） |
| ELF 正向 | `hello.elf` / `hello386.elf` | 1797 / 1823 个符号，**与服务端完全一致** |
| 负对照 | 篡改 PE 头 / 字节相同 / 替换-还原 / smoke | 18/18 通过（篡改→`fail` 且 `started=false`；字节相同→`fail` 且 `applied=false`） |
| 协议边界 | 老版本协商、通知、未知工具、坏 JSON、未知 method、坏帧后继续 | 10/10 通过 |
| 错误映射 | 401 密钥无效、400 upload_not_found、415 格式不支持、404 任务不存在 | 均带可执行建议 |
| 预设语义 | `preset=balanced + options=[pack]`；`preset=custom + options=[pack]`；空 preset | options 被忽略（仍 10 项）/ 仅 pack / **零保护（7168→10240 B）** |
| 扫描性能 | `softprotect/` 目录 depth=3 | 0.03 s / 14 个构件 |

## 7. 已知限制（都是实测出来的，不是猜的）

| 限制 | 说明 |
|---|---|
| Go 编译的 ELF/PE 无符号 | 没有 `.symtab`/导出表，本地与服务端都只能返回 0~1 个候选 → 只能做选项级保护 |
| Mach-O chained fixups / 新版 bind info | 服务端 `415 err.unsupported_type`（detail: `malformed bind info`），本地扫描仍能列出符号 |
| .NET 单文件（PublishSingleFile） | 服务端明确拒绝（会破坏 bundle 清单），改普通发布方式 |
| Span/ref struct、ref return、泛型方法 | 引擎安全回退（方法体原样）——`sp_verify` 能证明"没坏"，但证明不了"被保护了" |
| 函数上限 64 | 服务端硬限制，`sp_build_plan` 会自动裁剪并提示 |
| 上传 1 小时过期 | 过期后需重新 `sp_upload` |
| 产物下载一次 | 完整下载后服务端标记并清理；本地丢了只能重跑任务 |
| 枚举上限 400 | 与服务端一致，超出部分两侧都看不到（已在扫描结果里注明） |

## 8. 故障排查

| 现象 | 原因 / 处理 |
|---|---|
| `auth_ok=false` + `err.api_key_invalid` | 密钥失效：后台重新生成；确认是 `sp_` 用户密钥而非 `X-Api-Key` |
| `400 err.upload_not_found` | 上传过期（1h）或密钥换了账号：重新 `sp_upload` |
| `415 err.unsupported_type` | 看 `detail`：ZIP 容器需解包；单文件需改发布方式；Mach-O 看 chained fixups |
| `403 err.quota_exceeded` | 流量额度不足：上传与下载都计量 |
| `429 err.queue_full` | 服务端队列满，按 `Retry-After` 重试 |
| 任务 `failed` | `sp_job_status(include_log=true)` 看 `log_tail`；常见是选项与文件类型冲突 |
| IDE 里看不到工具 | 用 `--self-test` 确认二进制能跑；检查客户端配置里的绝对路径 |

调试：`--verbose` 把每次工具调用打到 stderr（stdout 永远只有协议帧）；`--quiet` 关掉日志。
