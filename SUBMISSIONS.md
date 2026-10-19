# MCP 目录收录：提交材料与步骤

> 本文档是提交到各 MCP 目录/注册表的**统一材料包**。所有平台用同一套名称、描述、链接，
> 避免版本与口径漂移。最后核对日期：2026-10-19（各站表单可能变化，提交前扫一眼为准）。

## 0. 统一文案（复制即用）

**Title（标题）**

```
SoftProtect MCP
```

**Description（官方 registry 用，≤100 字符）**

```
MCP server letting AI agents pack and verify binaries via the SoftProtect anti-RE service.
```

**Description（目录站长版）**

```
SoftProtect MCP connects AI IDEs and agents (Claude, Cursor, Cline, Windsurf, VS Code,
WorkBuddy, ...) to the SoftProtect binary protection service. Agents can scan a project,
enumerate protectable functions (.NET methods without pdb, PE exports/ELF symbols),
draft a protection plan, submit packing/virtualization jobs (PE / .NET / ELF / Mach-O),
poll progress, download outputs and run baseline functional verification — all in one
conversation. Keys live only in a local config/env, never as tool parameters.
Zero third-party dependencies; ships as a single static binary for 6 platforms.
```

**Tags / Category**

```
security, reverse-engineering, software-protection, binary-protection,
code-virtualization, packing, dotnet, dev-tools
```

**链接**

- Website: https://softprotect.si
- Repository: https://github.com/n0bele/softprotect-mcp
- Releases: https://github.com/n0bele/softprotect-mcp/releases
- License: MIT

**示例提示词（部分平台要求 example prompts）**

```
"Scan ./bin and tell me what can be protected in MyApp.dll"
"Protect the auth functions of App.exe with the balanced preset"
"Download the protected build and verify it still behaves like the original"
```

---

## 1. 官方 MCP Registry（先做这个，其他站会自动收录）

registry.modelcontextprotocol.io — Anthropic/GitHub/PulseMCP/Microsoft 共同背书的
权威元数据注册表。Glama、PulseMCP、VS Code gallery 等会自动从它拉取。

**前置说明（重要）**：官方 registry 的 server.json 要么有 `packages`（npm/PyPI 等包），
要么有 `remotes`（公网 streamable-http 端点）。我们目前是 GitHub Releases 二进制分发
（不在两者之列），因此：

- **远端端点（softprotect.si/mcp）上线后**：在 `server.json` 加上
  `"remotes":[{"type":"streamable-http","url":"https://softprotect.si/mcp"}]`，
  bump version，即可发布——这是最顺的路径。
- 想提前发：需要一个 npm 空壳包（`mcpName` 对应）或先做 remote 端点，二选一。

**步骤**（等 remote 端点就绪后执行，约 5 分钟）：

```bash
# 1) 安装 publisher CLI
curl -L "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_windows_amd64.tar.gz" | tar xz
#   （或 npm i -g @modelcontextprotocol/registry-publisher）

# 2) 登录（设备码流程，浏览器确认 github.com/login/device；需登录 n0bele 账号）
mcp-publisher login github

# 3) 发布（读取仓库根目录的 server.json；每次发布 version 必须递增且不可撤回）
mcp-publisher publish

# 4) 验证
curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.n0bele"
```

**注意**：`name` 已定为 `io.github.n0bele/softprotect-mcp`（GitHub 命名空间，与登录
账号绑定）；以后想用 `com.softprotect/...` 品牌命名，需在 softprotect.si 做 DNS TXT
或 `/.well-known/mcp-registry-auth` 域名验证。发布过的版本**不可删除**，提交前检查好
server.json。

---

## 2. Glama（自动索引 + 认领）

- 已做：仓库根目录已放 `glama.json`（maintainers: n0bele）；GitHub topics 已加
  `mcp-server`（Glama 按此 topic 抓取）。
- 你要做的：提交后访问 https://glama.ai/mcp/servers → 搜 "softprotect" → 点进列表页
  → 用 GitHub 登录 **Claim**（认领后可改文案、看使用统计）。

---

## 3. Smithery（最大目录站，支持 stdio 自托管列表）

1. 打开 https://smithery.ai/new ，用 GitHub 登录
2. stdio 服务器选仓库方式：填 `https://github.com/n0bele/softprotect-mcp`
3. 元数据直接粘贴本文档第 0 节的标题/描述/标签；auth 说明填
   `API key (sp_...) in local config file or SOFTPROTECT_API_KEY env`
4. 提交后 Smithery 会扫描 README 生成列表；定期回扫，保持 README 即可

（远端端点上线后可改走 URL 方式获得一键安装徽标：`smithery mcp publish https://softprotect.si/mcp -n n0bele/softprotect-mcp`）

---

## 4. PulseMCP（编辑审核制）

1. 打开 https://www.pulsemcp.com/submit （表单：repo、文档、协议合规等字段）
2. 各字段照第 0 节填；Server URL 暂填 GitHub 仓库；auth 填 local config API key
3. 也可不做：官方 registry 发布后 PulseMCP 约 1 周内自动收录

---

## 5. mcp.so（社区站，已提交 ✅）

- 已通过官方收录帖提交：chatmcp/mcpso 仓库 issue「Submit Your MCP Servers here」
  （https://github.com/chatmcp/mcpso/issues/1#issuecomment-6265966615 ，2026-10-19；
  审核后上线）。
- 催审/更新：在同一 issue 下追评即可。付费快审通道（$39）可选，不必要。

---

## 6. awesome-mcp-servers（83k+ star 的awesome 列表）

前置：Glama 列表存在后才会被收（这是该列表 2026 年的硬性要求）。

1. Fork https://github.com/punkpeye/awesome-mcp-servers
2. 找到 Security 相关分类，按字母序加一行：

```
- [SoftProtect MCP](https://github.com/n0bele/softprotect-mcp) - Binary protection (packing/virtualization) for PE, .NET, ELF and Mach-O via AI agents, with baseline functional verification
```

3. PR 标题：`Add SoftProtect MCP (security)`；正文一句话说明 + Glama 列表链接。

---

## 7. 已完成清单

- [x] GitHub 仓库公开 + MIT + 六平台 Release 二进制
- [x] GitHub topics：mcp-server 等（Glama 抓取源）
- [x] server.json（官方 registry 格式，待 remote 端点后发布）
- [x] glama.json（认领用）
- [x] mcp.so 社区提交（issue）
- [ ] 官方 registry 发布（等 softprotect.si/mcp 上线）
- [ ] Glama 认领（手动，1 分钟）
- [ ] Smithery / PulseMCP 表单（手动，各 5 分钟）
- [ ] awesome-mcp-servers PR（等 Glama 列表）
