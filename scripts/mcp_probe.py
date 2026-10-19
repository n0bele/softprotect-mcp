#!/usr/bin/env python3
"""最小 MCP stdio 客户端：用于在没有 IDE 的环境里验证 softprotect-mcp。

用途：
  python mcp_probe.py --exe ./softprotect-mcp --config cfg.json list
  python mcp_probe.py ... call sp_ping
  python mcp_probe.py ... call sp_scan_project '{"paths":["C:/proj/bin/App.dll"]}'

它只说 NDJSON JSON-RPC 2.0（MCP 标准 stdio 传输），不依赖任何 SDK；
自研 harness / CI 可以直接复用这份实现。
"""
import argparse
import json
import os
import subprocess
import sys
import threading


class MCPClient:
    def __init__(self, exe, config=None, env=None, cwd=None):
        cmd = [exe]
        if config:
            cmd += ["--config", config]
        e = dict(os.environ)
        if env:
            e.update(env)
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, cwd=cwd, env=e, bufsize=1,
                                     text=True, encoding="utf-8", errors="replace")
        self._id = 0
        self._lock = threading.Lock()
        self.stderr_lines = []
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _drain_stderr(self):
        for line in self.proc.stderr:
            self.stderr_lines.append(line.rstrip("\n"))

    def _send(self, obj):
        self.proc.stdin.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()

    def request(self, method, params=None, timeout=600):
        with self._lock:
            self._id += 1
            rid = self._id
            msg = {"jsonrpc": "2.0", "id": rid, "method": method}
            if params is not None:
                msg["params"] = params
            self._send(msg)
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    raise RuntimeError("服务进程已退出；stderr:\n" + "\n".join(self.stderr_lines[-20:]))
                line = line.strip()
                if not line:
                    continue
                try:
                    resp = json.loads(line)
                except json.JSONDecodeError:
                    raise RuntimeError("stdout 出现非 JSON 帧（协议污染）: " + line[:200])
                if resp.get("id") != rid:
                    continue  # 忽略通知/错序响应
                if "error" in resp:
                    raise RuntimeError("JSON-RPC 错误: %s" % resp["error"])
                return resp.get("result")

    def call(self, name, args=None):
        res = self.request("tools/call", {"name": name, "arguments": args or {}})
        text = "".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")
        if res.get("isError"):
            raise RuntimeError("%s 返回错误: %s" % (name, text))
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--config")
    ap.add_argument("action", choices=["list", "call", "init"])
    ap.add_argument("tool", nargs="?")
    ap.add_argument("args", nargs="?", default="{}")
    a = ap.parse_args()

    c = MCPClient(a.exe, a.config)
    try:
        init = c.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                        "clientInfo": {"name": "mcp_probe", "version": "1"}})
        print("initialize:", json.dumps(init, ensure_ascii=False))
        if a.action in ("list", "init"):
            tools = c.request("tools/list", {})["tools"]
            for t in tools:
                print("  - %-16s %s" % (t["name"], t.get("title", "")))
            return 0
        if not a.tool:
            print("需要工具名", file=sys.stderr)
            return 2
        out = c.call(a.tool, json.loads(a.args))
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    finally:
        c.close()


if __name__ == "__main__":
    sys.exit(main())
