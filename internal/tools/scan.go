package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/n0bele/softprotect-mcp/internal/binfmt"
	"github.com/n0bele/softprotect-mcp/internal/config"
	"github.com/n0bele/softprotect-mcp/internal/mcp"
	"github.com/n0bele/softprotect-mcp/internal/plan"
)

// ---------- sp_ping ----------

func (d *Deps) ping(ctx context.Context, _ map[string]any) (any, error) {
	c, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	out := map[string]any{
		"base_url":    d.Cfg.BaseURL,
		"api_key":     config.MaskKey(d.Cfg.APIKey),
		"key_source":  d.Cfg.Source,
		"work_dir":    d.workDir(),
		"record_file": d.Cfg.Record.Path,
		"mcp_version": Version,
		"transport":   "stdio (NDJSON JSON-RPC 2.0)",
	}

	health, err := d.API.Health(c)
	if err != nil {
		out["reachable"] = false
		out["error"] = err.Error()
		out["hint"] = "检查 base_url、网络与代理；若服务端在私有网络，先确认隧道/网关"
		return out, nil
	}
	out["reachable"] = true
	out["server"] = health

	if err := d.API.CheckAuth(c); err != nil {
		out["auth_ok"] = false
		out["auth_error"] = err.Error()
		out["hint"] = "密钥无效/过期：Web 后台「API 密钥」重新生成，更新配置文件后重启本进程"
		return out, nil
	}
	out["auth_ok"] = true

	// 顺手给出账户视角的最近任务，便于确认"这个密钥看到的是不是同一个账号"
	if jobs, err := d.API.ListJobs(c); err == nil {
		out["jobs_running"] = jobs.Running
		out["jobs_queued"] = jobs.Queue
		out["recent_jobs"] = len(jobs.Jobs)
	}
	return out, nil
}

// ---------- sp_scan_project ----------

// scanEntry 一个文件的扫描摘要。
type scanEntry struct {
	Path          string            `json:"path"`
	Size          int64             `json:"size"`
	Format        string            `json:"format"`
	Arch          string            `json:"arch"`
	Is64          bool              `json:"is_64bit"`
	SymbolQuality string            `json:"symbol_quality"`
	SymbolFile    string            `json:"symbol_file,omitempty"`
	FunctionCount int               `json:"function_count"`
	Functions     []binfmt.Function `json:"functions,omitempty"`
	Notes         []string          `json:"notes,omitempty"`
	info          *binfmt.Info      `json:"-"`
}

var skipDirs = map[string]bool{
	".git": true, ".svn": true, ".hg": true, "node_modules": true, ".vs": true,
	".idea": true, "__pycache__": true, ".venv": true, "venv": true, "packages": true,
	".nuget": true, "obj": true, ".workbuddy": true, "$RECYCLE.BIN": true, "System Volume Information": true,
}

// binaryExts 只对可能是构件的扩展名做扫描（避免把源码/图片也读进内存）。
var binaryExts = map[string]bool{
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".node": true,
	".elf": true, ".bin": true, ".out": true, ".a": true, ".lib": true, ".sys": true,
	".ocx": true, ".cpl": true, ".scr": true, "": true,
}

func (d *Deps) scanProject(ctx context.Context, args map[string]any) (any, error) {
	maxFiles := mcp.ArgInt(args, "max_files", 200)
	if maxFiles <= 0 || maxFiles > 2000 {
		maxFiles = 200
	}
	previewAll := mcp.ArgBool(args, "include_functions", false)

	var roots []string
	if paths := mcp.ArgStrings(args, "paths"); len(paths) > 0 {
		for _, p := range paths {
			a, err := absPath(p, "paths")
			if err != nil {
				return nil, err
			}
			roots = append(roots, a)
		}
	} else {
		root := mcp.ArgStringDefault(args, "root", "")
		if root == "" {
			wd, err := os.Getwd()
			if err != nil {
				return nil, err
			}
			root = wd
		}
		a, err := absPath(root, "root")
		if err != nil {
			return nil, err
		}
		roots = append(roots, a)
	}

	depth := mcp.ArgInt(args, "depth", 4)
	if depth <= 0 {
		depth = 4
	}
	if depth > 8 {
		depth = 8
	}

	var entries []scanEntry
	var notes []string
	skippedTooBig, skippedUnreadable := 0, 0

	addFile := func(path string) {
		if len(entries) >= maxFiles {
			return
		}
		st, err := os.Stat(path)
		if err != nil || st.IsDir() {
			return
		}
		if st.Size() > 256<<20 {
			skippedTooBig++
			return
		}
		info, size, err := binfmt.ScanFile(path)
		if err != nil {
			skippedUnreadable++
			return
		}
		e := scanEntry{
			Path: path, Size: size, Format: info.Format, Arch: info.Arch, Is64: info.Is64,
			SymbolQuality: info.SymbolQuality, SymbolFile: info.SymbolFile,
			FunctionCount: len(info.Functions), info: info,
		}
		e.Notes = append(e.Notes, info.Notes...)
		if previewAll || len(info.Functions) <= 12 {
			e.Functions = info.Functions
		} else {
			e.Functions = info.Functions[:12]
			e.Notes = append(e.Notes, fmt.Sprintf("函数清单共 %d 个，此处只列前 12 个（include_functions=true 可看全部）", len(info.Functions)))
		}
		entries = append(entries, e)
	}

	for _, root := range roots {
		st, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			addFile(root)
			continue
		}
		base := root
		_ = filepath.WalkDir(root, func(path string, de fs.DirEntry, err error) error {
			if err != nil {
				skippedUnreadable++
				if de != nil && de.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if len(entries) >= maxFiles {
				return fs.SkipAll
			}
			name := de.Name()
			if de.IsDir() {
				if path == base {
					return nil
				}
				if skipDirs[name] {
					return fs.SkipDir
				}
				rel, rerr := filepath.Rel(base, path)
				if rerr == nil && strings.Count(rel, string(filepath.Separator)) >= depth-1 {
					return fs.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(name))
			if !binaryExts[ext] {
				return nil
			}
			addFile(path)
			return nil
		})
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	// 输出（用小写字段名，避免 Go 结构体字段名泄漏到协议里）
	files := make([]map[string]any, 0, len(entries))
	counts := map[string]int{}
	for _, e := range entries {
		counts[e.Format]++
		m := map[string]any{
			"path":           e.Path,
			"size":           e.Size,
			"format":         e.Format,
			"arch":           e.Arch,
			"is_64bit":       e.Is64,
			"symbol_quality": e.SymbolQuality,
			"function_count": e.FunctionCount,
		}
		if e.SymbolFile != "" {
			m["symbol_file"] = e.SymbolFile
		}
		if len(e.Functions) > 0 {
			m["functions"] = e.Functions
		}
		if len(e.Notes) > 0 {
			m["notes"] = e.Notes
		}
		files = append(files, m)
	}

	if skippedTooBig > 0 {
		notes = append(notes, fmt.Sprintf("%d 个文件超过 256MB 被跳过（服务端上传上限通常 50MB，需要拆分）", skippedTooBig))
	}
	if len(entries) == 0 {
		notes = append(notes, "没有找到可识别的构件：确认扫描根目录正确，且目标是构建产物（.exe/.dll/.so/.dylib）而不是源码")
	}
	if skippedUnreadable > 0 {
		notes = append(notes, fmt.Sprintf("%d 个条目无法读取或不是有效构件（已跳过）", skippedUnreadable))
	}
	notes = append(notes, "symbol_quality: full=.NET 全部 IL 方法 / exports=仅导出表 / symbols=符号表 / none=枚举不到")

	return map[string]any{
		"roots":     roots,
		"depth":     depth,
		"scanned":   len(entries),
		"by_format": counts,
		"files":     files,
		"notes":     notes,
		"next":      "用 sp_build_plan(paths=[...]) 生成方案；确认后 sp_upload → sp_protect",
	}, nil
}

// ---------- sp_build_plan ----------

func (d *Deps) buildPlan(ctx context.Context, args map[string]any) (any, error) {
	paths := mcp.ArgStrings(args, "paths")
	var files []plan.File

	if len(paths) > 0 {
		for _, p := range paths {
			abs, err := absPath(p, "paths")
			if err != nil {
				return nil, err
			}
			st, err := os.Stat(abs)
			if err != nil {
				return nil, err
			}
			if !st.IsDir() {
				info, size, err := binfmt.ScanFile(abs)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", filepath.Base(abs), err)
				}
				files = append(files, plan.File{Path: abs, Info: info, Size: size})
				continue
			}
			// 目录：只取有函数候选的文件，避免把依赖库全塞进方案
			_ = filepath.WalkDir(abs, func(path string, de fs.DirEntry, err error) error {
				if err != nil || de.IsDir() || len(files) >= 32 {
					return nil
				}
				if !binaryExts[strings.ToLower(filepath.Ext(de.Name()))] {
					return nil
				}
				info, size, err := binfmt.ScanFile(path)
				if err != nil || len(info.Functions) == 0 {
					return nil
				}
				files = append(files, plan.File{Path: path, Info: info, Size: size})
				return nil
			})
		}
	} else if scan := mcp.ArgMap(args, "scan"); scan != nil {
		// 从 sp_scan_project 的输出里取路径，重新扫描（避免信任模型回传的旧数据）
		for _, it := range mcp.AsSlice(scan["files"]) {
			fm, _ := it.(map[string]any)
			if fm == nil {
				continue
			}
			p, _ := fm["path"].(string)
			if p == "" {
				continue
			}
			info, size, err := binfmt.ScanFile(p)
			if err != nil {
				continue
			}
			files = append(files, plan.File{Path: p, Info: info, Size: size})
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("scan 里没有可用的 path（文件可能已移动）：请直接传 paths")
		}
	} else {
		return nil, fmt.Errorf("需要 paths（推荐）或 scan（sp_scan_project 的输出）")
	}

	goal := plan.Goal(mcp.ArgStringDefault(args, "goal", "balanced"))
	maxFn := mcp.ArgInt(args, "max_functions", 32)

	p := plan.Build(files, goal, maxFn)

	// 附上每个目标的摘要，便于人复核"给谁做的方案"
	targets := make([]map[string]any, 0, len(files))
	for _, f := range files {
		targets = append(targets, map[string]any{
			"path":       f.Path,
			"size":       f.Size,
			"format":     f.Info.Format,
			"arch":       f.Info.Arch,
			"candidates": len(f.Info.Functions),
		})
	}

	b, _ := json.Marshal(p)
	var pm map[string]any
	_ = json.Unmarshal(b, &pm)
	pm["targets"] = targets
	pm["next"] = "确认后：sp_upload(path=该文件) → sp_protect(upload_id=..., preset/functions 用本方案)"
	if p.Upload["symbol_path"] != nil {
		pm["next"] = "确认后：sp_upload(path=该文件, symbol_path=" + fmt.Sprint(p.Upload["symbol_path"]) +
			") → sp_protect(upload_id=..., preset/functions 用本方案)"
	}
	return pm, nil
}
