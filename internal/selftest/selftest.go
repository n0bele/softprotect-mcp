// Package selftest 内置一个最小 MCP 客户端，把整条链路真跑一遍。
//
// 目的：把"能不能用"从口头承诺变成可执行的证据。self-test 走的是和 IDE
// 完全相同的协议层（JSON-RPC 帧 → tools/call → 工具实现），不是直接调函数。
package selftest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/n0bele/softprotect-mcp/internal/mcp"
	"github.com/n0bele/softprotect-mcp/internal/tools"
)

// Step 一步的结果。
type Step struct {
	Name   string
	OK     bool
	Detail string
	Took   time.Duration
}

// Runner 自检执行器。
type Runner struct {
	srv  *mcp.Server
	out  io.Writer
	next float64
	ctx  context.Context
}

// Run 执行自检。sample 为空时只验证协议与连通性（不产生任务）。
// 返回进程退出码：0 = 全通过。
func Run(deps *tools.Deps, toolList []mcp.Tool, sample string, out io.Writer) int {
	ctx := context.Background()
	r := &Runner{
		srv: mcp.New(mcp.ServerInfo{Name: "softprotect-mcp", Version: tools.Version}, toolList, io.Discard,
			log.New(io.Discard, "", 0)),
		out: out,
		ctx: ctx,
	}

	var steps []Step
	add := func(name string, ok bool, format string, args ...any) {
		steps = append(steps, Step{Name: name, OK: ok, Detail: fmt.Sprintf(format, args...)})
		fmt.Fprintf(out, "%-5s %-28s %s\n", mark(ok), name, fmt.Sprintf(format, args...))
	}

	// 1) initialize
	res, err := r.call("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "sp-self-test", "version": "1"},
	})
	if err != nil {
		add("protocol/initialize", false, "%v", err)
		return finish(steps, out)
	}
	sinfo, _ := res["serverInfo"].(map[string]any)
	add("protocol/initialize", sinfo != nil && sinfo["name"] == "softprotect-mcp",
		"protocolVersion=%v serverInfo=%v", res["protocolVersion"], sinfo["name"])

	// 2) tools/list
	res, err = r.call("tools/list", map[string]any{})
	if err != nil {
		add("protocol/tools/list", false, "%v", err)
		return finish(steps, out)
	}
	var got []string
	for _, it := range mcp.AsSlice(res["tools"]) {
		if m, ok := it.(map[string]any); ok {
			got = append(got, fmt.Sprint(m["name"]))
		}
	}
	want := []string{}
	for _, t := range toolList {
		want = append(want, t.Name)
	}
	sort.Strings(got)
	sort.Strings(want)
	add("protocol/tools/list", strings.Join(got, ",") == strings.Join(want, ","),
		"%d 个工具: %s", len(got), strings.Join(got, ", "))

	// 3) ping（连通性 + 鉴权）
	ping, err := r.tool("sp_ping", map[string]any{})
	if err != nil {
		add("sp_ping", false, "%v", err)
		return finish(steps, out)
	}
	authOK, _ := ping["auth_ok"].(bool)
	reach, _ := ping["reachable"].(bool)
	detail := fmt.Sprintf("base_url=%v reachable=%v auth_ok=%v key=%v",
		ping["base_url"], reach, authOK, ping["api_key"])
	if !authOK {
		if h, ok := ping["hint"].(string); ok {
			detail += " → " + h
		}
	}
	add("sp_ping", authOK, "%s", detail)
	if !authOK {
		return finish(steps, out)
	}

	if sample == "" {
		add("e2e", true, "未指定样本文件（--self-test=<file> 可跑完整加壳+回测链路），协议与鉴权已通过")
		return finish(steps, out)
	}
	if _, err := os.Stat(sample); err != nil {
		add("sample", false, "样本不存在: %v", err)
		return finish(steps, out)
	}

	// 4) scan
	scan, err := r.tool("sp_scan_project", map[string]any{"paths": []string{sample}, "include_functions": true})
	if err != nil {
		add("sp_scan_project", false, "%v", err)
		return finish(steps, out)
	}
	files := mcp.AsSlice(scan["files"])
	add("sp_scan_project", len(files) > 0, "识别 %d 个文件, scanned=%v", len(files), scan["scanned"])
	if len(files) == 0 {
		return finish(steps, out)
	}
	f0, _ := files[0].(map[string]any)
	add("sp_scan/detail", true, "format=%v arch=%v functions=%v quality=%v",
		f0["format"], f0["arch"], f0["function_count"], f0["symbol_quality"])

	// 5) build_plan
	pl, err := r.tool("sp_build_plan", map[string]any{"paths": []string{sample}, "goal": "balanced"})
	if err != nil {
		add("sp_build_plan", false, "%v", err)
		pl = map[string]any{}
	} else {
		fn := mcp.AsSlice(pl["functions"])
		add("sp_build_plan", true, "preset=%v functions=%d warnings=%d",
			pl["preset"], len(fn), len(mcp.AsSlice(pl["warnings"])))
	}

	// 6) upload
	up, err := r.tool("sp_upload", map[string]any{"path": sample})
	if err != nil {
		add("sp_upload", false, "%v", err)
		return finish(steps, out)
	}
	uploadID := fmt.Sprint(up["upload_id"])
	srvFns := mcp.AsSlice(up["functions"])
	add("sp_upload", uploadID != "", "upload_id=%s kind=%v arch=%v server_functions=%d",
		uploadID, up["kind"], up["arch"], len(srvFns))
	if cmp, ok := up["scan_compare"].(map[string]any); ok {
		same, _ := cmp["match"].(bool)
		add("scan==server", same, "local=%v server=%v only_server=%v only_local=%v",
			cmp["local_functions"], cmp["server_functions"], cmp["only_on_server"], cmp["only_locally"])
	}

	// 7) protect：取服务端前 2 个函数做虚拟化
	args := map[string]any{"upload_id": uploadID, "preset": "balanced"}
	var sels []map[string]any
	for i, it := range srvFns {
		if i >= 2 {
			break
		}
		if m, ok := it.(map[string]any); ok {
			if addr, ok := m["address"].(float64); ok {
				sels = append(sels, map[string]any{"address": addr, "type": "virtualization"})
			}
		}
	}
	if len(sels) > 0 {
		args["functions"] = sels
	}
	job, err := r.tool("sp_protect", args)
	if err != nil {
		add("sp_protect", false, "%v", err)
		return finish(steps, out)
	}
	jobID := fmt.Sprint(job["job_id"])
	add("sp_protect", jobID != "", "job_id=%s status=%v functions=%d", jobID, job["status"], len(sels))

	// 8) status（本次调用内最多等 180s）
	st, err := r.tool("sp_job_status", map[string]any{"job_id": jobID, "wait_s": 180})
	if err != nil {
		add("sp_job_status", false, "%v", err)
		return finish(steps, out)
	}
	status := fmt.Sprint(st["status"])
	add("sp_job_status", status == "done", "status=%s progress=%v stage=%v duration_ms=%v",
		status, st["progress"], st["stage_name"], st["duration_ms"])
	if status != "done" {
		if lt, ok := st["log_tail"].(string); ok && lt != "" {
			add("sp_job_status/log", false, "%s", lastLines(lt, 8))
		}
		return finish(steps, out)
	}

	// 9) fetch
	fr, err := r.tool("sp_fetch_result", map[string]any{"job_id": jobID, "overwrite": true})
	if err != nil {
		add("sp_fetch_result", false, "%v", err)
		return finish(steps, out)
	}
	protPath := fmt.Sprint(fr["path"])
	if fi, err := os.Stat(protPath); err != nil {
		add("sp_fetch_result", false, "落盘失败: %v", err)
		return finish(steps, out)
	} else {
		add("sp_fetch_result", true, "path=%s size=%d sha256=%v", protPath, fi.Size(), shortSHA(fmt.Sprint(fr["sha256"])))
	}

	// 10) verify（基线对比）
	vr, err := r.tool("sp_verify", map[string]any{
		"original":  sample,
		"protected": protPath,
		"profile":   "run",
		"job_id":    jobID,
	})
	if err != nil {
		add("sp_verify", false, "%v", err)
		return finish(steps, out)
	}
	verdict := fmt.Sprint(vr["verdict"])
	base, _ := vr["baseline"].(map[string]any)
	cand, _ := vr["protected_run"].(map[string]any)
	add("sp_verify", verdict == "pass", "verdict=%s exit(基线)=%v exit(受保护)=%v applied=%v",
		verdict, base["exit_code"], cand["exit_code"], vr["protection_applied"])
	if diffs := mcp.AsSlice(vr["diffs"]); len(diffs) > 0 {
		add("sp_verify/diffs", false, "%d 处差异：%v", len(diffs), diffs[0])
	}

	// 11) history
	h, err := r.tool("sp_history", map[string]any{"job_id": jobID})
	if err != nil {
		add("sp_history", false, "%v", err)
	} else {
		add("sp_history", intOf(h["count"]) >= 1, "count=%v file=%v", h["count"], h["record_file"])
	}

	return finish(steps, out)
}

// call 直接喂给协议层，返回 result 对象。
func (r *Runner) call(method string, params any) (map[string]any, error) {
	r.next++
	req := map[string]any{"jsonrpc": "2.0", "id": r.next, "method": method}
	if params != nil {
		req["params"] = params
	}
	b, _ := json.Marshal(req)
	frame := r.srv.Handle(r.ctx, b)
	if len(frame) == 0 {
		return nil, fmt.Errorf("%s 没有返回帧（应为通知）", method)
	}
	var resp struct {
		Result map[string]any `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(frame, &resp); err != nil {
		return nil, fmt.Errorf("%s 返回非 JSON: %s", method, string(frame[:min(len(frame), 200)]))
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("[%d] %s", resp.Error.Code, resp.Error.Message)
	}
	return resp.Result, nil
}

// tool 调一个工具并把 text 内容解析回对象。
func (r *Runner) tool(name string, args map[string]any) (map[string]any, error) {
	res, err := r.call("tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return nil, err
	}
	text := ""
	for _, it := range mcp.AsSlice(res["content"]) {
		if m, ok := it.(map[string]any); ok {
			if s, ok := m["text"].(string); ok {
				text += s
			}
		}
	}
	if isErr, _ := res["isError"].(bool); isErr {
		return nil, fmt.Errorf("%s 失败: %s", name, clip(text, 600))
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		return nil, fmt.Errorf("%s 返回内容不是 JSON 对象: %s", name, clip(text, 300))
	}
	return out, nil
}

func finish(steps []Step, out io.Writer) int {
	pass, fail := 0, 0
	for _, s := range steps {
		if s.OK {
			pass++
		} else {
			fail++
		}
	}
	fmt.Fprintf(out, "\n自检结果: %d 通过 / %d 失败（共 %d 步）\n", pass, fail, len(steps))
	if fail > 0 {
		return 1
	}
	return 0
}

func mark(ok bool) string {
	if ok {
		return "[OK]"
	}
	return "[FAIL]"
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func shortSHA(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// intOf JSON 数字统一是 float64。
func intOf(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}
