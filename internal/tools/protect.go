package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/softprotect/softprotect-mcp/internal/binfmt"
	"github.com/softprotect/softprotect-mcp/internal/mcp"
	"github.com/softprotect/softprotect-mcp/internal/spapi"
	"github.com/softprotect/softprotect-mcp/internal/store"
)

// ---------- sp_upload ----------

func (d *Deps) upload(ctx context.Context, args map[string]any) (any, error) {
	pathArg, _ := mcp.ArgString(args, "path")
	abs, err := absPath(pathArg, "path")
	if err != nil {
		return nil, err
	}
	symbolPath := ""
	if sp, ok := mcp.ArgString(args, "symbol_path"); ok && sp != "" {
		symbolPath, err = absPath(sp, "symbol_path")
		if err != nil {
			return nil, err
		}
	}
	// 上传大文件可能很久：给 10 分钟上限，超时也保留"任务未创建"的明确语义
	c, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	resp, err := d.API.Upload(c, abs, symbolPath)
	if err != nil {
		return nil, err
	}
	u := resp.Upload

	// 本地扫描 vs 服务端枚举：差集能直接暴露"符号没带上"或"本地解析漏了"
	var compare map[string]any
	if info, _, serr := binfmt.ScanFile(abs); serr == nil {
		local := map[uint64]string{}
		for _, f := range info.Functions {
			local[f.Address] = f.Name
		}
		server := map[uint64]string{}
		for _, f := range u.Functions {
			server[f.Address] = f.Name
		}
		onlyServer, onlyLocal := 0, 0
		for a := range server {
			if _, ok := local[a]; !ok {
				onlyServer++
			}
		}
		for a := range local {
			if _, ok := server[a]; !ok {
				onlyLocal++
			}
		}
		compare = map[string]any{
			"local_functions":  len(local),
			"server_functions": len(server),
			"only_on_server":   onlyServer,
			"only_locally":     onlyLocal,
			"match":            onlyServer == 0 && onlyLocal == 0,
		}
	}

	opts := make([]map[string]any, 0, len(resp.Options))
	for _, o := range resp.Options {
		opts = append(opts, map[string]any{
			"key": o.Key, "default": o.Default, "advanced": o.Advanced,
			"dotnet_ok": o.DotNetOK, "native_only": o.NativeOnly, "heavy": o.Heavy,
		})
	}

	out := map[string]any{
		"upload_id":  u.ID,
		"name":       u.Name,
		"size":       u.Size,
		"kind":       u.Kind,
		"arch":       u.Arch,
		"is_64bit":   u.Is64Bit,
		"type_name":  u.TypeName,
		"expires_in": u.ExpiresIn,
		"functions":  u.Functions,
		"options":    opts,
		"presets":    resp.Presets,
		"next":       "sp_protect(upload_id=..., preset=\"balanced\" 或 functions=[...])",
	}
	if u.DotNetCoreLib != "" {
		out["dotnet_corelib"] = u.DotNetCoreLib
	}
	if u.DotNetAnyCPU {
		out["dotnet_anycpu"] = true
		out["note_anycpu"] = "Framework AnyCPU：服务端会对 pack/memory_protection 自动钉 32 位进程（产物将始终以 32 位 CLR 运行）"
	}
	if u.HasSymbolMap {
		out["has_symbol_map"] = true
	}
	if compare != nil {
		out["scan_compare"] = compare
		if m, _ := compare["match"].(bool); !m {
			out["note_functions"] = "本地枚举与服务端不一致：以服务端 functions 为准（本工具的 sp_protect 用服务端地址才有效）"
		}
	}
	if len(u.Functions) == 0 {
		out["warning"] = "服务端没有枚举到任何函数：可以只用选项级保护；若想函数级虚拟化，请补充同名 .pdb/.map 后重新上传"
	}
	return out, nil
}

// ---------- sp_protect ----------

func (d *Deps) protect(ctx context.Context, args map[string]any) (any, error) {
	uploadID, _ := mcp.ArgString(args, "upload_id")
	if uploadID == "" {
		return nil, errors.New("缺少 upload_id：先调 sp_upload")
	}
	preset := mcp.ArgStringDefault(args, "preset", "balanced")
	switch preset {
	case "fast", "balanced", "maximum", "custom":
	default:
		return nil, fmt.Errorf("preset=%q 不合法（fast/balanced/maximum/custom）", preset)
	}
	options := mcp.ArgStrings(args, "options")
	var warns []string

	// 实测语义：preset 非 custom 时 options 被整段忽略；custom 且 options 为空 = 零保护。
	if preset != "custom" && len(options) > 0 {
		warns = append(warns, fmt.Sprintf("preset=%s 时 options 会被服务端忽略（实测），你的 %d 个选项不会生效；要精细控制请传 preset=custom 并给完整选项列表", preset, len(options)))
	}
	if preset == "custom" && len(options) == 0 {
		return nil, errors.New("preset=custom 但 options 为空 = 零保护（实测：产物与输入几乎相同）：要么给完整选项列表，要么改用 fast/balanced/maximum")
	}

	sels, ferr := parseFunctions(args["functions"])
	if ferr != nil {
		return nil, ferr
	}
	if len(sels) > 64 {
		return nil, fmt.Errorf("函数数量 %d 超过服务端上限 64：先用 sp_build_plan 裁剪，或拆成多个任务", len(sels))
	}

	msgs := mcp.ArgStrings(args, "messages")
	if len(msgs) > 5 {
		return nil, fmt.Errorf("messages 最多 5 条，当前 %d 条", len(msgs))
	}

	req := spapi.StartJobRequest{
		UploadID:      uploadID,
		Preset:        preset,
		Options:       options,
		VMSectionName: mcp.ArgStringDefault(args, "vm_section_name", ""),
		Messages:      msgs,
		Functions:     sels,
	}

	c, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	job, err := d.API.StartJob(c, req)
	if err != nil {
		return nil, err
	}

	// 落记录（此时还不知道结果）
	d.recordJob(job, uploadID, "")

	// 可选：本次调用内最多再等 wait_s 秒（仍是轮询，不是 SSE）
	waitS := mcp.ArgInt(args, "wait_s", 0)
	if waitS > 0 {
		if waitS > 300 {
			waitS = 300
		}
		job = d.poll(ctx, job.ID, time.Duration(waitS)*time.Second, false)
		d.recordJob(job, uploadID, "")
	}

	out := job.Compact()
	out["started_with"] = map[string]any{
		"preset": preset, "options": options, "functions": len(sels),
	}
	if len(warns) > 0 {
		out["warnings"] = warns
	}
	if job.Status == "done" {
		out["next"] = "sp_fetch_result(job_id=...) 下载产物，然后 sp_verify 做功能回测"
	} else {
		out["next"] = "sp_job_status(job_id=...) 单次查询（不必循环；1–5 秒一次即可）"
	}
	if job.Status == "failed" {
		out["error_detail"] = d.jobLogText(job.ID, 4000)
	}
	return out, nil
}

// parseFunctions 支持 [12345] / [{address:12345,type:"virtualization"}] 两种写法。
func parseFunctions(v any) ([]spapi.FunctionSel, error) {
	items := mcp.AsSlice(v)
	if len(items) == 0 {
		return nil, nil
	}
	seen := map[uint64]bool{}
	out := make([]spapi.FunctionSel, 0, len(items))
	for i, it := range items {
		var addr uint64
		typ := "virtualization"
		switch x := it.(type) {
		case float64:
			addr = uint64(x)
		case int:
			addr = uint64(x)
		case map[string]any:
			if a, ok := x["address"].(float64); ok {
				addr = uint64(a)
			}
			if t, ok := x["type"].(string); ok && t != "" {
				typ = t
			}
		default:
			return nil, fmt.Errorf("functions[%d] 类型不支持：用整数 address 或 {address,type}", i)
		}
		switch typ {
		case "virtualization", "mutation", "ultra":
		default:
			return nil, fmt.Errorf("functions[%d].type=%q 不合法（virtualization/mutation/ultra）", i, typ)
		}
		if addr == 0 {
			return nil, fmt.Errorf("functions[%d] 地址为 0（.NET/原生都要用服务端 functions[].address 的 VA）", i)
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, spapi.FunctionSel{Address: addr, Type: typ})
	}
	return out, nil
}

// ---------- sp_job_status ----------

func (d *Deps) jobStatus(ctx context.Context, args map[string]any) (any, error) {
	jobID, _ := mcp.ArgString(args, "job_id")
	if jobID == "" {
		return nil, errors.New("缺少 job_id（可从 sp_protect 返回或 sp_history 查）")
	}
	waitS := mcp.ArgInt(args, "wait_s", 0)
	if waitS < 0 {
		waitS = 0
	}
	if waitS > 300 {
		waitS = 300
	}

	c, cancel := context.WithTimeout(ctx, time.Duration(waitS+30)*time.Second)
	defer cancel()

	job := d.poll(c, jobID, time.Duration(waitS)*time.Second, false)
	if job == nil {
		return nil, fmt.Errorf("任务 %s 查询失败（可能不存在、不属于当前密钥账号，或网络异常）", jobID)
	}
	d.recordJob(job, "", "")

	out := job.Compact()
	if mcp.ArgBool(args, "include_log", false) || job.Status == "failed" {
		out["log_tail"] = d.jobLogText(job.ID, 4000)
	}
	switch job.Status {
	case "done":
		out["next"] = "sp_fetch_result(job_id=...) 下载产物；随后 sp_verify 回测"
	case "failed":
		out["next"] = "看 log_tail 定位；常见原因：选项组合与文件类型不兼容、函数地址不属于该文件、Span/ref struct 等已回退项"
	case "killed":
		out["next"] = "任务被取消：确认是否有人调用了 DELETE，或服务端重启"
	default:
		out["next"] = "继续每 1–5 秒查一次；有 queue_pos 说明在排队"
	}
	return out, nil
}

// poll 轮询到终态或超时。wait<=0 表示只查一次。
func (d *Deps) poll(ctx context.Context, jobID string, wait time.Duration, _ bool) *spapi.Job {
	deadline := time.Now().Add(wait)
	interval := time.Duration(d.Cfg.Poll.InitialIntervalMS) * time.Millisecond
	if interval <= 0 {
		interval = 800 * time.Millisecond
	}
	maxInterval := time.Duration(d.Cfg.Poll.MaxIntervalMS) * time.Millisecond
	if maxInterval < interval {
		maxInterval = interval
	}

	for {
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		job, err := d.API.GetJob(c, jobID)
		cancel()
		if err == nil {
			switch job.Status {
			case "done", "failed", "killed":
				return job
			}
			if wait <= 0 || time.Now().After(deadline) {
				return job
			}
		} else {
			if wait <= 0 || time.Now().After(deadline) {
				d.logf("查询任务 %s 失败: %v", jobID, err)
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
		if interval < maxInterval {
			interval = interval * 3 / 2
			if interval > maxInterval {
				interval = maxInterval
			}
		}
	}
}

// ---------- sp_fetch_result ----------

func (d *Deps) fetchResult(ctx context.Context, args map[string]any) (any, error) {
	jobID, _ := mcp.ArgString(args, "job_id")
	if jobID == "" {
		return nil, errors.New("缺少 job_id")
	}
	c, cancel := context.WithTimeout(ctx, 60*time.Second)
	job, err := d.API.GetJob(c, jobID)
	cancel()
	if err != nil {
		return nil, err
	}
	if job.Status != "done" {
		return nil, fmt.Errorf("任务状态是 %s（progress %d%%），产物还不存在：先用 sp_job_status 查到 done", job.Status, job.Progress)
	}
	name := job.OutputName
	if name == "" {
		name = "protected.bin"
	}

	var dest string
	if p, ok := mcp.ArgString(args, "out_path"); ok && p != "" {
		dest = p
		if !filepath.IsAbs(dest) {
			dest = filepath.Join(d.workDir(), dest)
		}
	} else {
		// 默认落在工作目录，避免把产物写进用户源码树
		dest = filepath.Join(d.workDir(), "outputs", jobID, filepath.Base(name))
	}
	overwrite := mcp.ArgBool(args, "overwrite", false)
	if !overwrite {
		if _, err := os.Stat(dest); err == nil {
			return nil, fmt.Errorf("目标已存在：%s（要覆盖请传 overwrite=true）", dest)
		}
	}

	dlCtx, dlCancel := context.WithTimeout(ctx, 15*time.Minute)
	defer dlCancel()
	res, err := d.API.DownloadResult(dlCtx, jobID, dest)
	if err != nil {
		return nil, err
	}
	if job.OutputSize > 0 && res.Size != job.OutputSize {
		return nil, fmt.Errorf("下载字节数 %d 与任务记录 %d 不一致（网络截断？）：文件已写入 %s，建议重新下载",
			res.Size, job.OutputSize, res.Path)
	}

	// 回填记录
	d.recordJob(job, "", "")
	rec := store.Record{
		JobID: jobID, Status: job.Status,
		Artifact:  map[string]any{"path": res.Path, "size": res.Size, "sha256": res.SHA256},
		UpdatedAt: time.Now(),
		Server:    map[string]any{"output_name": job.OutputName, "output_size": job.OutputSize},
	}
	_ = d.Store.Append(rec)

	out := map[string]any{
		"path":   res.Path,
		"size":   res.Size,
		"sha256": res.SHA256,
		"job":    job.Compact(),
		"next":   "必须做功能回测：sp_verify(original=原始产物, protected=" + res.Path + ")",
	}
	if job.Downloaded {
		out["note"] = "服务端已标记该任务产物为已下载（同一任务只扣一次流量；若本地文件丢了需重跑任务）"
	}
	return out, nil
}

// ---------- 记录辅助 ----------

// recordJob 写一条任务快照（同 job_id 多次写入以最后一条为准）。
func (d *Deps) recordJob(job *spapi.Job, uploadID, _ string) {
	if d.Store == nil || job == nil {
		return
	}
	r := store.Record{
		JobID:     job.ID,
		UploadID:  uploadID,
		Input:     job.InputName,
		Kind:      job.FileKind,
		Preset:    job.Preset,
		Options:   job.Options,
		Status:    job.Status,
		Error:     job.ErrorMsg,
		UpdatedAt: time.Now(),
		Server: map[string]any{
			"output_name": job.OutputName,
			"output_size": job.OutputSize,
			"duration_ms": job.DurationMS,
			"progress":    job.Progress,
			"stage":       job.Stage,
		},
	}
	if len(job.Functions) > 0 {
		for _, f := range job.Functions {
			r.Functions = append(r.Functions, map[string]any{"address": f.Address, "type": f.Type})
		}
	}
	if job.StartedAt != nil {
		r.StartedAt = *job.StartedAt
	}
	if job.LogTail != "" && (job.Status == "failed" || job.Status == "killed") {
		r.Server["log_tail"] = job.LogTail
	}
	if err := d.Store.Append(r); err != nil {
		d.logf("写本地记录失败: %v", err)
	}
}

// jobLogText 取日志尾部（失败时给模型看的最后一段）。
func (d *Deps) jobLogText(jobID string, max int) string {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := d.API.JobLog(c, jobID)
	if err != nil {
		return "（日志获取失败：" + err.Error() + "）"
	}
	s = strings.TrimRight(s, "\n")
	if max > 0 && len(s) > max {
		return "…" + s[len(s)-max:]
	}
	return s
}
