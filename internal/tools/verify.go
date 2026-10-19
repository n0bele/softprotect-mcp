package tools

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/softprotect/softprotect-mcp/internal/mcp"
	"github.com/softprotect/softprotect-mcp/internal/store"
	"github.com/softprotect/softprotect-mcp/internal/verify"
)

// ---------- sp_verify ----------

func (d *Deps) verify(ctx context.Context, args map[string]any) (any, error) {
	origArg, _ := mcp.ArgString(args, "original")
	protArg, _ := mcp.ArgString(args, "protected")
	if origArg == "" || protArg == "" {
		return nil, errors.New("需要 original 与 protected 两个绝对路径")
	}
	orig, err := absPath(origArg, "original")
	if err != nil {
		return nil, err
	}
	prot, err := absPath(protArg, "protected")
	if err != nil {
		return nil, err
	}

	req := &verify.Request{
		Original:  orig,
		Protected: prot,
		Profile:   verify.Profile(mcp.ArgStringDefault(args, "profile", d.Cfg.Verify.DefaultProfile)),
		TimeoutS:  mcp.ArgInt(args, "timeout_s", d.Cfg.Verify.TimeoutS),
	}

	if m := mcp.ArgMap(args, "run"); m != nil {
		rs := &verify.RunSpec{
			Exe:               strOf(m["exe"]),
			Args:              strsOf(m["args"]),
			Cwd:               strOf(m["cwd"]),
			ExpectStdoutRegex: strOf(m["expect_stdout_regex"]),
			Env:               strsOf(m["env"]),
		}
		if v, ok := m["expect_exit"].(float64); ok {
			n := int(v)
			rs.ExpectExit = &n
		}
		req.Run = rs
	}
	if m := mcp.ArgMap(args, "tests"); m != nil {
		req.Tests = &verify.TestsSpec{
			Cmd:      strOf(m["cmd"]),
			Cwd:      strOf(m["cwd"]),
			TimeoutS: intOf(m["timeout_s"]),
			Env:      strsOf(m["env"]),
		}
	}

	res, err := verify.Run(ctx, req)
	if err != nil {
		return nil, err
	}

	out := map[string]any{
		"verdict":            res.Verdict,
		"profile":            res.Profile,
		"protection_applied": res.ProtectionApplied,
		"baseline":           res.Baseline,
		"protected_run":      res.Protected,
		"checks":             res.Checks,
		"artifacts":          res.Artifacts,
		"scope_note": "本工具证明的是「保护前后行为一致」；字节相同会被直接判 fail（假保护）。" +
			"是否真的虚拟化了指定函数，请核对 sp_protect 的 functions 与服务端日志（sp_job_status include_log=true），本工具不做二进制取证",
	}
	if len(res.Diffs) > 0 {
		out["diffs"] = res.Diffs
	}
	if len(res.Notes) > 0 {
		out["notes"] = res.Notes
	}

	switch res.Verdict {
	case "pass":
		out["conclusion"] = "受保护产物与原始产物功能一致（退出码 + 输出都匹配）"
	case "degraded":
		out["conclusion"] = "退出码正确但输出有差异：若这些输出属于业务行为，请按 fail 处理并调整方案（减少虚拟化函数/target 选项）"
	case "fail":
		out["conclusion"] = "受保护产物功能异常，**不要发布**：按 diffs 与 log_tail 定位；先缩小函数范围再复测"
	case "error":
		out["conclusion"] = "验证用例本身没跑通（不是加壳的问题）：先让基线能正常执行"
	}

	// 回填记录
	if jobID, ok := mcp.ArgString(args, "job_id"); ok && jobID != "" && d.Store != nil {
		_ = d.Store.Append(store.Record{
			JobID:  jobID,
			Status: "done",
			Verify: map[string]any{
				"profile": res.Profile,
				"verdict": res.Verdict,
				"checks":  len(res.Checks),
				"diffs":   res.Diffs,
				"at":      time.Now().Format(time.RFC3339),
			},
			UpdatedAt: time.Now(),
		})
	}
	return out, nil
}

// ---------- sp_history ----------

func (d *Deps) history(ctx context.Context, args map[string]any) (any, error) {
	limit := mcp.ArgInt(args, "limit", 20)
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	var since time.Time
	if s, ok := mcp.ArgString(args, "since"); ok && s != "" {
		t, err := time.ParseInLocation("2006-01-02", s, time.Local)
		if err != nil {
			return nil, fmt.Errorf("since 格式应为 2026-10-01：%w", err)
		}
		since = t
	}
	jobID, _ := mcp.ArgString(args, "job_id")
	status, _ := mcp.ArgString(args, "status")

	recs, err := d.Store.List(limit, jobID, status, since)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(recs))
	for _, r := range recs {
		it := map[string]any{
			"job_id":     r.JobID,
			"status":     r.Status,
			"input":      r.Input,
			"preset":     r.Preset,
			"updated_at": r.UpdatedAt.Format(time.RFC3339),
			"started_at": r.StartedAt.Format(time.RFC3339),
		}
		if r.UploadID != "" {
			it["upload_id"] = r.UploadID
		}
		if len(r.Options) > 0 {
			it["options"] = r.Options
		}
		if len(r.Functions) > 0 {
			it["functions"] = len(r.Functions)
		}
		if r.Error != "" {
			it["error"] = r.Error
		}
		if r.Artifact != nil {
			it["artifact"] = r.Artifact
		}
		if r.Verify != nil {
			it["verify"] = r.Verify
		}
		if r.Server != nil {
			it["server"] = r.Server
		}
		items = append(items, it)
	}
	return map[string]any{
		"record_file": d.Store.Path(),
		"count":       len(items),
		"items":       items,
	}, nil
}

// ---------- 小工具 ----------

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

func intOf(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

func strsOf(v any) []string {
	arr := mcp.AsSlice(v)
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
