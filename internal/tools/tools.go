// Package tools 实现暴露给 IDE/Agent 的 sp_* 工具。
//
// 约定（对模型友好）：
//   - 所有耗时操作立即返回 job_id，进度用 sp_job_status 单次查询（服务端不用 SSE）
//   - 工具参数里没有任何密钥字段；密钥只来自 MCP 进程配置
//   - 每个工具的 description 都写清"什么时候该用、什么时候不该用"和实测坑
package tools

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/n0bele/softprotect-mcp/internal/config"
	"github.com/n0bele/softprotect-mcp/internal/mcp"
	"github.com/n0bele/softprotect-mcp/internal/spapi"
	"github.com/n0bele/softprotect-mcp/internal/store"
)

// Version MCP 服务版本。
const Version = "0.1.0"

// Deps 工具依赖。
type Deps struct {
	Cfg   *config.Config
	API   *spapi.Client
	Store *store.Store
	Log   *log.Logger
}

func (d *Deps) logf(format string, args ...any) {
	if d.Log != nil {
		d.Log.Printf(format, args...)
	}
}

// All 返回全部工具的注册表（顺序即 tools/list 顺序）。
func All(d *Deps) []mcp.Tool {
	return []mcp.Tool{
		{
			Name:  "sp_ping",
			Title: "连通性与鉴权自检",
			Description: "检查服务端可达性、API 密钥是否有效、工作目录与版本。开工前或报 401 时先跑这个。" +
				"不消耗流量、不产生任务。",
			InputSchema: obj(nil),
			Handler:     d.ping,
		},
		{
			Name:  "sp_scan_project",
			Title: "本地扫描可加壳产物",
			Description: "在**本地**扫描目录或文件，识别 PE/.NET/ELF/Mach-O，并尽力枚举函数候选（.NET 直接解析元数据，不需要 pdb）。" +
				"不上传、不计费。返回每个文件的格式/架构/函数数量/符号质量（full=全部方法，exports=只有导出，none=枚举不了）。" +
				"这是规划的输入，下一步用 sp_build_plan。",
			InputSchema: obj(map[string]any{
				"root":              str("扫描根目录（绝对路径）。与 paths 二选一，默认当前工作目录"),
				"paths":             arrStr("直接指定文件或目录（绝对路径）列表，优先于 root"),
				"depth":             num("目录递归深度，默认 4，最大 8"),
				"max_files":         num("最多扫描多少个候选文件，默认 200"),
				"include_functions": boolp("是否返回每个文件的完整函数清单（默认只给前 12 个预览）"),
			}),
			Handler: d.scanProject,
		},
		{
			Name:  "sp_build_plan",
			Title: "生成保护方案",
			Description: "根据扫描结果给出可解释的方案：预设档、函数级虚拟化清单（每个函数带打分与理由）、风险提示。" +
				"规则全部对应服务端实测行为：函数上限 64；preset 非 custom 时 options 会被忽略；preset 留空等于零保护。" +
				"不会自动上传，确认后再调 sp_upload / sp_protect。",
			InputSchema: obj(map[string]any{
				"paths":         arrStr("要规划的文件或目录路径（内部会重新扫描，保证信息不过期）"),
				"scan":          objM("可选：sp_scan_project 的原始返回。给了 paths 就忽略它"),
				"goal":          enm("保护目标，默认 balanced", "balanced", "speed", "size", "security"),
				"max_functions": num("本次最多虚拟化多少个函数，默认 32，硬上限 64"),
			}),
			Handler: d.buildPlan,
		},
		{
			Name:  "sp_upload",
			Title: "上传构建产物",
			Description: "把构建产物（可附带 .pdb/.map）上传到服务端，返回 upload_id 与服务端枚举的 functions[]。" +
				"服务端的函数清单是**权威**的：.NET 无需 pdb 就能列出全部方法；原生 PE 没有符号时只有导出。" +
				"上传记录 1 小时有效。会计入账户上传流量。",
			InputSchema: obj(map[string]any{
				"path":        str("要上传的文件绝对路径（必需）"),
				"symbol_path": str("可选：符号文件 .pdb/.map 的路径，用于枚举原生内部函数"),
			}),
			Handler: d.upload,
		},
		{
			Name:  "sp_protect",
			Title: "开始加壳（立即返回）",
			Description: "创建加壳任务，**立即返回 job_id**，不等结果（服务端 202）。" +
				"preset 必填语义：fast/balanced/maximum 是整档方案；只有 custom 才按 options 精确生效；" +
				"留空等于零保护（实测：输出与输入几乎相同），本工具会拒绝空 preset 并默认 balanced。" +
				"functions 支持 [{address,type}]，type=virtualization|mutation|ultra，上限 64。",
			InputSchema: obj(map[string]any{
				"upload_id":       str("sp_upload 返回的 upload_id（必需）"),
				"preset":          enm("预设档，默认 balanced。需要精细控制时传 custom 并在 options 里列全部选项", "fast", "balanced", "maximum", "custom"),
				"options":         arrStr("仅 preset=custom 时生效：完整选项 key 列表（见 sp_upload 返回的 options）"),
				"functions":       arrAny("函数级保护：元素为 {address:整数, type:\"virtualization\"} 或直接给 address 整数"),
				"vm_section_name": str("可选：VM 节名，留空服务端随机生成（推荐留空）"),
				"messages":        arrStr("可选：最多 5 条运行时提示文案"),
				"wait_s":          num("可选：本次调用内最多轮询等待多少秒（0=立即返回，默认 0，上限 300）"),
			}),
			Handler: d.protect,
		},
		{
			Name:  "sp_job_status",
			Title: "查询任务状态",
			Description: "单次查询任务状态（HTTP 轮询，不使用 SSE）。返回 status/progress/stage/queue_pos/eta_seconds，" +
				"失败时带 error 与日志尾部。查得太频繁没意义：内部有节流建议，正常节奏是每 1–5 秒一次。" +
				"需要少一轮对话时可给 wait_s 让本次调用内部轮询到结束。",
			InputSchema: obj(map[string]any{
				"job_id":      str("任务 ID（必需）"),
				"include_log": boolp("是否附上服务端完整日志（失败排查时开，成功时关掉省上下文）"),
				"wait_s":      num("可选：本次调用内最多轮询等待秒数（默认 0，上限 300）"),
			}),
			Handler: d.jobStatus,
		},
		{
			Name:  "sp_fetch_result",
			Title: "下载受保护产物",
			Description: "把 done 状态的产物下载到本地并校验 sha256（流式落盘，完整传输才算成功——服务端只有完整下载才扣流量并清理）。" +
				"不指定 out_path 时落到 <work_dir>/outputs/<job_id>/<output_name>。任务仍在但产物已过期时返回明确错误。",
			InputSchema: obj(map[string]any{
				"job_id":    str("任务 ID（必需）"),
				"out_path":  str("可选：保存到指定绝对路径（目录会自动创建）"),
				"overwrite": boolp("目标已存在时是否覆盖，默认 false"),
			}),
			Handler: d.fetchResult,
		},
		{
			Name:  "sp_verify",
			Title: "加壳前后功能回测",
			Description: "**必做的最后一步**：先在原始产物上跑一遍采基线，再在受保护产物上跑同一动作，比较退出码/输出/期望正则。" +
				"profile=run 直接跑可执行文件（run.exe+run.args，支持 {file} 占位）；profile=tests 跑测试命令并把受保护产物临时替换到原路径（跑完还原）；" +
				"profile=smoke 只比退出码。verdict: pass=一致，degraded=退出码对但输出不同（可能只是耗时差异），fail=功能坏了。" +
				"只跑受保护产物而不采基线，判断是没有依据的。",
			InputSchema: obj(map[string]any{
				"original":  str("原始产物绝对路径（必需）"),
				"protected": str("受保护产物绝对路径（必需，必须与 original 不同）"),
				"profile":   enm("验证档位，默认 run", "run", "tests", "smoke"),
				"run":       objM("profile=run/smoke 时的跑法 {exe,args,cwd,expect_exit,expect_stdout_regex,env}；args 里用 {file} 代表产物路径"),
				"tests":     objM("profile=tests 时的测试命令 {cmd,cwd,timeout_s,env}，如 {\"cmd\":\"dotnet test -c Release\",\"cwd\":\"C:/proj\"}"),
				"timeout_s": num("单次运行超时秒数，默认 300"),
				"job_id":    str("可选：把结果回填到该任务的本地记录"),
			}),
			Handler: d.verify,
		},
		{
			Name:  "sp_history",
			Title: "本地任务记录",
			Description: "查询本机记录（JSONL 追加，同 job_id 以最后一条为准）：任务参数、服务端结果、产物路径与 sha256、验证结论。" +
				"断线/重启后可用它找回 job_id 继续 sp_job_status。",
			InputSchema: obj(map[string]any{
				"limit":  num("最多返回多少条，默认 20，上限 200"),
				"job_id": str("只看某个任务"),
				"status": enm("只看某个状态", "queued", "running", "done", "failed", "killed"),
				"since":  str("只要该日期之后更新的记录，格式 2026-10-01"),
			}),
			Handler: d.history,
		},
	}
}

// ---------- schema 小工具（避免每处手写 map 缩进出错） ----------

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": map[string]any{}}
	if props != nil {
		m["properties"] = props
	}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func objM(desc string) map[string]any {
	return map[string]any{"type": "object", "description": desc}
}

func str(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func num(desc string) map[string]any {
	return map[string]any{"type": "number", "description": desc}
}

func boolp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

func arrStr(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

func arrAny(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{}, "description": desc}
}

func enm(desc string, vals ...string) map[string]any {
	return map[string]any{"type": "string", "enum": vals, "description": desc}
}

// ---------- 公用 ----------

func (d *Deps) workDir() string {
	if d.Cfg.WorkDir != "" {
		return config.ExpandHome(d.Cfg.WorkDir)
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "SoftProtectMCP")
	}
	return "."
}

// absPath 把用户给的路径规整成绝对路径，并给出可执行的错误。
func absPath(p, field string) (string, error) {
	p = config.ExpandHome(strings.TrimSpace(p))
	if p == "" {
		return "", fmt.Errorf("%s 不能为空", field)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("%s 路径非法: %w", field, err)
	}
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("%s 不存在或不可读: %s", field, abs)
	}
	return abs, nil
}

// ctx 给所有 HTTP 调用加统一超时语义（长的自己再加）。
func ctxBackground() context.Context { return context.Background() }
