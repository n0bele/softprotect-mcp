# 各 AI 平台接入指南（WorkBuddy / Codex / Claude / DeepSeek Harness）

> 四个平台都支持 **stdio MCP**——下载 [Release 二进制](https://github.com/n0bele/softprotect-mcp/releases)
> 后按下面配置即可，无需任何上架审批。
>
> 密钥两种给法（任选）：① 写在 `~/.config/softprotect-mcp/config.json`（`--init-config`
> 生成模板，推荐，一次配置全平台生效）；② 在平台配置里传环境变量 `SOFTPROTECT_API_KEY`。

---

## 1. WorkBuddy

编辑 `~/.workbuddy/mcp.json`：

```json
{
  "mcpServers": {
    "softprotect": {
      "command": "C:\\tools\\softprotect-mcp.exe",
      "args": []
    }
  }
}
```

然后在连接器管理页对 `softprotect` 点「信任」并重开会话。工具以
`mcp__softprotect__sp_*` 出现。

## 2. OpenAI Codex（CLI / 桌面 App，配置互通）

`~/.codex/config.toml`（TOML 格式，不是 JSON）：

```toml
[mcp_servers.softprotect]
command = "/usr/local/bin/softprotect-mcp"   # Windows: C:\\tools\\softprotect-mcp.exe
args = []
startup_timeout_sec = 30
```

或一条命令免手写：

```bash
codex mcp add softprotect -- /usr/local/bin/softprotect-mcp
```

Codex 桌面 App：Settings → MCP Servers → Add server → **STDIO** → 填同一命令。
重启 Codex 后 `codex mcp list` 应显示 softprotect 已初始化。

## 3. Claude（Desktop / Code）

**Claude Desktop** — `claude_desktop_config.json`（Settings → Developer → Edit Config）：

```json
{
  "mcpServers": {
    "softprotect": {
      "command": "/usr/local/bin/softprotect-mcp",
      "args": []
    }
  }
}
```

**Claude Code**：

```bash
claude mcp add softprotect -- /usr/local/bin/softprotect-mcp
```

**claude.ai 网页版**：仅支持 remote MCP（streamable HTTP）端点，暂不可用——
等 `https://softprotect.si/mcp` 上线后在 Settings → Connectors 添加。

## 4. DeepSeek Harness（DSH）

DSH 通过官方插件 `@deepseek-ai/dsh-mcp-client` 桥接，stdio 配置写进
`~/.dsh/profiles/web/cordis.patch.yml`：

```yaml
- insert:
  - id: mcp-softprotect
    name: '@deepseek-ai/dsh-mcp-client'
    config:
      serverName: softprotect
      transport: stdio
      command: /usr/local/bin/softprotect-mcp
      args: []
```

重启 `dsh web` 后工具以 `mcp__softprotect__sp_ping` 等命名出现
（工具名 ≤64 字符合规，无需担心命名截断）。

---

## 5. 传密钥的环境变量方式（可选）

如果不想用默认配置文件，在各平台配置里传环境变量即可：

| 平台 | 传法 |
|---|---|
| WorkBuddy | mcp.json 的 `"env": { "SOFTPROTECT_API_KEY": "sp_..." }` |
| Codex | `[mcp_servers.softprotect.env]` `SOFTPROTECT_API_KEY = "sp_..."` |
| Claude Desktop | mcpServers 里的 `"env": { "SOFTPROTECT_API_KEY": "sp_..." }` |
| DeepSeek | 上面 yaml 的 `config.env` |

## 6. 接入后验证

任一平台里说一句 **「用 sp_ping 检查 SoftProtect 连接」**——返回
`auth_ok: true` 即全通；401 则检查密钥，连不通则查 base_url 与网络。
