// softprotect-mcp 入口：stdio MCP 服务端。
//
// 生命周期：载入配置 → 打开本地记录 → 组装工具 → stdin/stdout 服务协议帧。
// 所有日志走 stderr，stdout 只允许协议帧。密钥只从配置/环境变量进来，
// 命令行参数里没有密钥字段。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/n0bele/softprotect-mcp/internal/config"
	"github.com/n0bele/softprotect-mcp/internal/mcp"
	"github.com/n0bele/softprotect-mcp/internal/selftest"
	"github.com/n0bele/softprotect-mcp/internal/spapi"
	"github.com/n0bele/softprotect-mcp/internal/store"
	"github.com/n0bele/softprotect-mcp/internal/tools"
)

func main() {
	var (
		cfgPath   = flag.String("config", "", "配置文件路径（默认依次尝试 ~/.config/softprotect-mcp/config.json 等处）")
		initCfg   = flag.String("init-config", "", "把配置模板写到指定路径并退出")
		printCfg  = flag.Bool("print-config", false, "打印解析后的配置（密钥脱敏）并退出")
		selfTest  = flag.Bool("self-test", false, "协议 + 连通性 + 鉴权自检后退出（不产生任务）")
		selfTestF = flag.String("self-test-file", "", "全链路自检：对样本文件真实走一遍 上传→加壳→下载→回测 后退出")
		verbose   = flag.Bool("verbose", false, "把每次工具调用的名字与参数打到 stderr")
		quiet     = flag.Bool("quiet", false, "关闭 stderr 日志")
		showVer   = flag.Bool("version", false, "打印版本并退出")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("softprotect-mcp", tools.Version)
		return
	}
	if *initCfg != "" {
		if err := writeTemplate(*initCfg); err != nil {
			fatal("生成配置模板失败: %v", err)
		}
		fmt.Printf("配置模板已写入 %s —— 编辑 base_url 与 api_key 后即可使用\n", *initCfg)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("%v", err)
	}
	if *printCfg {
		printResolved(cfg)
		return
	}
	if err := cfg.Validate(); err != nil {
		fatal("%v", err)
	}

	lg := log.New(os.Stderr, "sp-mcp ", log.LstdFlags)
	if *quiet {
		lg.SetOutput(io.Discard)
	}

	if err := os.MkdirAll(config.ExpandHome(cfg.WorkDir), 0o755); err != nil {
		fatal("工作目录创建失败(%s): %v", cfg.WorkDir, err)
	}
	st, err := store.Open(cfg.Record.Path)
	if err != nil {
		fatal("打开本地记录失败(%s): %v", cfg.Record.Path, err)
	}

	deps := &tools.Deps{
		Cfg:   cfg,
		API:   spapi.New(cfg.BaseURL, cfg.APIKey, cfg.EngineHint),
		Store: st,
		Log:   lg,
	}
	toolList := tools.All(deps)

	if *selfTest || *selfTestF != "" {
		lg.SetOutput(io.Discard) // 自检输出走 stdout 报告，进程日志保持安静
		os.Exit(selftest.Run(deps, toolList, *selfTestF, os.Stdout))
	}

	srv := mcp.New(mcp.ServerInfo{Name: "softprotect-mcp", Version: tools.Version}, toolList, os.Stdout, lg)
	srv.Verbose = *verbose

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	lg.Printf("serving stdio: base_url=%s key=%s work_dir=%s",
		cfg.BaseURL, config.MaskKey(cfg.APIKey), config.ExpandHome(cfg.WorkDir))
	if err := srv.Serve(ctx, os.Stdin); err != nil {
		fatal("stdio 服务退出: %v", err)
	}
}

// writeTemplate 落一份与 config.example.json 同构的模板。
func writeTemplate(path string) error {
	tpl := map[string]any{
		"base_url":    "https://softprotect.si",
		"api_key":     "sp_xxxxxxxxxxxxxxxx",
		"engine_hint": "",
		"work_dir":    "~/SoftProtectMCP",
		"poll": map[string]any{
			"initial_interval_ms": 800,
			"max_interval_ms":     5000,
			"max_wait_s":          1800,
		},
		"verify": map[string]any{
			"default_profile": "run",
			"timeout_s":       300,
		},
		"record": map[string]any{
			"path":      "data/history.jsonl",
			"keep_days": 180,
		},
	}
	b, err := json.MarshalIndent(tpl, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func printResolved(c *config.Config) {
	m := map[string]any{
		"base_url": c.BaseURL,
		"api_key":  config.MaskKey(c.APIKey),
		"work_dir": config.ExpandHome(c.WorkDir),
		"source":   c.Source,
		"config":   c.ConfigPath,
		"poll":     c.Poll,
		"verify":   c.Verify,
		"record":   c.Record,
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	fmt.Println(string(b))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "softprotect-mcp: "+format+"\n", args...)
	os.Exit(1)
}
