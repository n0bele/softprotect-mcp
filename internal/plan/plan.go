// Package plan 由扫描结果生成**可解释**的保护方案。
//
// 所有规则都对应服务端实测行为，不做猜测：
//   - preset 非 custom 时 options 一律被忽略（实测：balanced + options=[pack] 仍是 10 项）
//   - preset 留空 = 零保护（实测：7168 字节输入产出 10240 字节，等价"原样重排"）
//   - 函数级保护上限 64（服务端 project.MaxFunctions）
//   - 函数级虚拟化只支持 pe/elf/mach/dot（服务端 nativeKinds）
package plan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/n0bele/softprotect-mcp/internal/binfmt"
)

// MaxFunctions 服务端硬上限。
const MaxFunctions = 64

// Goal 保护目标。
type Goal string

const (
	GoalBalanced Goal = "balanced" // 默认：常规发布
	GoalSpeed    Goal = "speed"    // 性能敏感：少虚拟化
	GoalSize     Goal = "size"     // 体积敏感：只打包
	GoalSecurity Goal = "security" // 强度优先
)

// Sel 函数级选择（附名字与理由，便于人复核）。
type Sel struct {
	Address uint64 `json:"address"`
	Name    string `json:"name"`
	Type    string `json:"type"` // virtualization
	Reason  string `json:"reason"`
	Score   int    `json:"score"`
}

// Plan 方案输出。
type Plan struct {
	Preset    string         `json:"preset"`
	Options   []string       `json:"options,omitempty"` // 仅 preset=custom 生效
	Functions []Sel          `json:"functions"`
	Upload    map[string]any `json:"upload_hints"`
	Estimate  map[string]any `json:"estimate"`
	Notes     []string       `json:"notes"`
	Warnings  []string       `json:"warnings,omitempty"`
}

// File 一个待规划的目标（由 sp_scan_project 或即时扫描得到）。
type File struct {
	Path string       `json:"path"`
	Info *binfmt.Info `json:"info"`
	Size int64        `json:"size"`
}

// sensitive 语义敏感的命名片段（命中说明这段逻辑"值得被逆向"）。
var sensitive = []string{
	"encrypt", "decrypt", "crypt", "cipher", "aes", "rsa", "hash", "hmac",
	"sign", "verify", "validate", "check", "license", "licence", "serial",
	"auth", "login", "token", "password", "passwd", "key", "secret",
	"activate", "activation", "trial", "expire", "quota", "pay", "order",
	"integrity", "tamper", "guard", "protect",
}

// Build 生成方案。goal 为空按 balanced。
func Build(files []File, goal Goal, maxFunctions int) *Plan {
	if goal == "" {
		goal = GoalBalanced
	}
	if maxFunctions <= 0 {
		maxFunctions = 32
	}
	if maxFunctions > MaxFunctions {
		maxFunctions = MaxFunctions
	}

	p := &Plan{Upload: map[string]any{}, Estimate: map[string]any{}}

	// 1) 预设：security -> maximum，size -> fast，其余 balanced。
	//    注意 fast/balanced/maximum 下 options 无效，所以 options 只在 custom 场景输出。
	switch goal {
	case GoalSecurity:
		p.Preset = "maximum"
	case GoalSize:
		p.Preset = "fast"
	default:
		p.Preset = "balanced"
	}

	// 2) 目标数量：size 目标不虚拟化（单函数 6.6KB→251KB 的量级，实测），
	//    speed 目标只挑最关键的少量函数。
	budget := maxFunctions
	switch goal {
	case GoalSize:
		budget = 0
	case GoalSpeed:
		if budget > 8 {
			budget = 8
		}
	}

	var all []Sel
	var notes, warns []string
	totalFns := 0
	for _, f := range files {
		info := f.Info
		if info == nil {
			continue
		}
		if info.SymbolFile != "" {
			p.Upload["symbol_path"] = info.SymbolFile
		} else if info.Format == "pe" && info.SymbolQuality == "exports" {
			warns = append(warns, fmt.Sprintf(
				"%s：原生 PE 只看到导出表。若要保护内部函数，把同名 .pdb/.map 放到同目录后重扫（上传时会自动附带）", base(f.Path)))
		}
		sels := scoreFunctions(info, f.Path)
		totalFns += len(sels)
		all = append(all, sels...)
	}

	// 3) 全局排序取前 budget 个
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Score != all[j].Score {
			return all[i].Score > all[j].Score
		}
		return all[i].Address < all[j].Address
	})
	picked := all
	if budget <= 0 {
		picked = nil
	} else if len(all) > budget {
		picked = all[:budget]
		warns = append(warns, fmt.Sprintf("候选 %d 个，按预算只虚拟化前 %d 个（服务端上限 %d）",
			len(all), budget, MaxFunctions))
	}
	p.Functions = append([]Sel{}, picked...)

	// 4) 说明与风险
	switch goal {
	case GoalSize:
		notes = append(notes, "goal=size：只做打包（preset=fast），不做函数虚拟化——虚拟化会让产物数倍膨胀")
	case GoalSpeed:
		notes = append(notes, fmt.Sprintf("goal=speed：最多虚拟化 %d 个最关键函数，其余靠选项级保护", budget))
	case GoalSecurity:
		notes = append(notes, "goal=security：preset=maximum（.NET 下会自动排除仅原生可用的选项）")
	default:
		notes = append(notes, "goal=balanced：preset=balanced + 按语义重要性挑函数，兼顾强度与体积")
	}
	notes = append(notes, "选项语义（实测）：preset=fast/balanced/maximum 时 options 被忽略；只有 preset=custom 才按 options 精确生效")
	if len(picked) > 0 {
		notes = append(notes, "函数来自本地扫描；上传后服务端会重新枚举，若列表不一致以服务端 functions[] 为准")
	}
	if totalFns == 0 {
		warns = append(warns, "没有可虚拟化的函数候选：检查是否已 strip、是否为打包/单文件产物，或补充符号文件")
	}
	warns = append(warns, "含 Span/ref struct 局部、ref return、泛型方法的方法会被引擎安全回退（方法体保持原样）——用 sp_verify 才能确认实际效果")

	p.Notes = notes
	p.Warnings = warns
	p.Estimate["candidates"] = totalFns
	p.Estimate["functions_selected"] = len(picked)
	if p.Estimate["candidates"] == 0 {
		p.Upload["note"] = "无可选函数时也建议上传一次：服务端对 .NET 能直接枚举全部方法"
	}
	return p
}

// scoreFunctions 给单个文件的候选打分，返回带理由的选择项。
// 规则是启发式的，但**可复现**：同名同类型给同样的分。
func scoreFunctions(info *binfmt.Info, path string) []Sel {
	out := make([]Sel, 0, len(info.Functions))
	for _, f := range info.Functions {
		score, reason := 10, "普通方法"
		lname := strings.ToLower(f.Name)
		switch {
		case isEntryName(f.Name) || f.Source == "entry":
			score, reason = 100, "程序入口（逆向起点）"
		case f.Source == "export":
			score, reason = 50, "导出函数（对外 API，最易被调用/逆向）"
		case matchesSensitive(lname):
			score, reason = 80, "语义敏感（"+firstMatch(lname)+"）：最值得保护"
		case strings.HasPrefix(lname, ".ctor") || strings.HasPrefix(lname, ".cctor") || strings.HasPrefix(lname, "ctor"):
			score, reason = 40, "构造/静态构造（常含初始化与校验）"
		case strings.HasPrefix(lname, "get_") || strings.HasPrefix(lname, "set_"):
			score, reason = 5, "属性访问器（逻辑薄，收益低）"
		case strings.HasPrefix(f.Name, "<"):
			score, reason = 8, "编译器生成的闭包/状态机方法"
		}
		if info.Format == "dot" && f.Source == "method" && score < 50 && !matchesSensitive(lname) {
			// .NET 方法体普遍很薄，同等条件下更值得保护（体积代价也小）
			score += 5
		}
		out = append(out, Sel{Address: f.Address, Name: f.Name, Type: "virtualization", Reason: reason, Score: score})
	}
	return out
}

func isEntryName(n string) bool {
	switch strings.ToLower(n) {
	case "main", "_main", "wmain", "winmain", "wwinmain", "entry", "start", "_start", "dllmain",
		"tmain", "maincrtstartup", "wmaincrtstartup", "dllmaincrtstartup":
		return true
	}
	return false
}

func matchesSensitive(lname string) bool {
	return firstMatch(lname) != ""
}

func firstMatch(lname string) string {
	for _, s := range sensitive {
		if strings.Contains(lname, s) {
			return s
		}
	}
	return ""
}

func base(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
