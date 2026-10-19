// Package config 载入 MCP 进程配置。
//
// 密钥只从这里进来（配置文件或环境变量），工具参数里永远没有 key 字段：
// 这样模型即使被诱导也拿不到密钥，日志里也只输出脱敏后的前 6 位。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config 与 config.example.json 一一对应。
type Config struct {
	BaseURL    string `json:"base_url"`
	APIKey     string `json:"api_key"`
	EngineHint string `json:"engine_hint"`
	WorkDir    string `json:"work_dir"`

	Poll struct {
		InitialIntervalMS int `json:"initial_interval_ms"`
		MaxIntervalMS     int `json:"max_interval_ms"`
		MaxWaitS          int `json:"max_wait_s"`
	} `json:"poll"`

	Verify struct {
		DefaultProfile string `json:"default_profile"`
		TimeoutS       int    `json:"timeout_s"`
		KeepArtifacts  bool   `json:"keep_artifacts"`
	} `json:"verify"`

	Record struct {
		Path     string `json:"path"`
		DB       string `json:"db,omitempty"` // 兼容旧样例字段（sqlite 命名），实际按 JSONL 落盘
		KeepDays int    `json:"keep_days"`
	} `json:"record"`

	// 载入来源，便于启动日志说明"密钥来自哪"，不打印密钥本身。
	Source string `json:"-"`
	// ConfigPath 实际使用的配置文件路径（可能为空：纯环境变量模式）。
	ConfigPath string `json:"-"`
}

// Default 返回不依赖配置文件的默认值。
func Default() *Config {
	c := &Config{}
	c.BaseURL = "https://softprotect.si"
	c.WorkDir = "~/SoftProtectMCP"
	c.Poll.InitialIntervalMS = 800
	c.Poll.MaxIntervalMS = 5000
	c.Poll.MaxWaitS = 1800
	c.Verify.DefaultProfile = "run"
	c.Verify.TimeoutS = 300
	c.Verify.KeepArtifacts = true
	c.Record.Path = "data/history.jsonl"
	c.Record.KeepDays = 180
	return c
}

// Load 依次尝试：显式路径 -> 环境变量 -> 默认路径。
// 显式路径不存在则直接报错（避免"配错了却静默用默认值"）。
func Load(explicit string) (*Config, error) {
	c := Default()

	path := explicit
	if path == "" {
		for _, cand := range defaultPaths() {
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				path = cand
				break
			}
		}
	} else if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("配置文件不存在: %s", path)
	}

	if path != "" {
		if err := c.mergeFile(path); err != nil {
			return nil, err
		}
		c.ConfigPath = path
		c.Source = path
	}

	// 环境变量优先级最高（便于 CI/临时切换，不必改文件）。
	if v := os.Getenv("SOFTPROTECT_BASE_URL"); v != "" {
		c.BaseURL = v
		c.Source = "env:SOFTPROTECT_BASE_URL"
	}
	if v := os.Getenv("SOFTPROTECT_API_KEY"); v != "" {
		c.APIKey = v
		c.Source = "env:SOFTPROTECT_API_KEY"
	}
	if v := os.Getenv("SOFTPROTECT_WORK_DIR"); v != "" {
		c.WorkDir = v
	}

	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	c.APIKey = strings.TrimSpace(c.APIKey)
	if c.WorkDir != "" {
		c.WorkDir = ExpandHome(c.WorkDir)
	}
	if c.Record.Path == "" {
		c.Record.Path = c.Record.DB
	}
	if c.Record.Path == "" {
		c.Record.Path = "data/history.jsonl"
	}
	if !filepath.IsAbs(c.Record.Path) {
		c.Record.Path = filepath.Join(c.WorkDir, c.Record.Path)
	}
	if c.Poll.InitialIntervalMS <= 0 {
		c.Poll.InitialIntervalMS = 800
	}
	if c.Poll.MaxIntervalMS < c.Poll.InitialIntervalMS {
		c.Poll.MaxIntervalMS = c.Poll.InitialIntervalMS
	}
	switch c.Verify.DefaultProfile {
	case "run", "tests", "smoke":
	default:
		c.Verify.DefaultProfile = "run"
	}
	if c.Verify.TimeoutS <= 0 {
		c.Verify.TimeoutS = 300
	}
	return c, nil
}

// mergeFile 读取 JSON 并覆盖默认值（未出现的字段保持默认）。
func (c *Config) mergeFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置失败: %w", err)
	}
	// 先解析到副本，避免半解析状态污染默认值。
	tmp := *c
	if err := json.Unmarshal(b, &tmp); err != nil {
		return fmt.Errorf("解析配置失败(%s): %w", path, err)
	}
	*c = tmp
	return nil
}

func defaultPaths() []string {
	var out []string
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out,
			filepath.Join(home, ".config", "softprotect-mcp", "config.json"),
			filepath.Join(home, ".softprotect-mcp.json"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		out = append(out, filepath.Join(wd, "softprotect-mcp.json"))
	}
	return out
}

// ExpandHome 展开前导 ~ 为用户主目录。
func ExpandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// Validate 检查必需项；返回的错误面向用户，直接给可执行的修复建议。
func (c *Config) Validate() error {
	if c.BaseURL == "" {
		return errors.New("base_url 为空：请在配置文件里设置服务端地址（如 https://softprotect.si）")
	}
	if c.APIKey == "" {
		return errors.New("未找到 API 密钥：二选一 —— ①配置文件填 api_key；②设置环境变量 SOFTPROTECT_API_KEY。密钥在 Web 后台「API 密钥」页生成（sp_ 开头）")
	}
	if !strings.HasPrefix(c.APIKey, "sp_") {
		return fmt.Errorf("API 密钥格式不对（%s）：应是 sp_ 开头的用户密钥；X-Api-Key 全局脚本密钥无法建任务（上传记录会丢）", MaskKey(c.APIKey))
	}
	return nil
}

// MaskKey 脱敏：只保留前缀与后 4 位。
func MaskKey(k string) string {
	if len(k) <= 10 {
		return "sp_…"
	}
	return k[:6] + "…" + k[len(k)-4:]
}
