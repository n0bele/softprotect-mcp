// Package spapi 是 SoftProtect 服务端 /api/v1 的最小客户端。
//
// 只实现 MCP 需要的 6 个调用，字段全部按服务端实际返回建模：
//   - 上传响应顶层 = {upload, options, presets[, job]}
//   - 建任务返回 202 + job（status 可能已是 running）
//   - 结果下载以 application/octet-stream 流式返回，文件名取 job.output_name
//
// 鉴权只用 Bearer 用户密钥（sp_ 开头）。实测：X-Api-Key 全局脚本通道
// 每次请求会生成新的匿名会话，上传记录随后找不到（400 err.upload_not_found），
// 因此这里不提供该通道。
package spapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Client 一个服务端连接。
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
	// EngineHint 仅用于报告；引擎由服务端调度，客户端不直连。
	EngineHint string
}

// New 构造客户端。超时按用途区分：普通 API 60s，上传/下载按文件大小另算。
func New(baseURL, apiKey, engineHint string) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		APIKey:     apiKey,
		EngineHint: engineHint,
		HTTP: &http.Client{
			// 不设全局 Timeout：上传/下载用 context 控制，避免大文件被误杀。
			Timeout: 0,
		},
	}
}

// ---------- 数据结构（与服务端 JSON 一一对应） ----------

// Function 服务端枚举出的函数候选（.NET 为 IL 方法，原生为导出/符号/入口）。
type Function struct {
	Address uint64 `json:"address"` // VA = image_base + RVA
	Size    uint32 `json:"size"`
	Name    string `json:"name"`
	Source  string `json:"source"` // export / symbol / entry / method
}

// OptionMeta 选项元数据。
type OptionMeta struct {
	Key        string `json:"key"`
	Group      string `json:"group"`
	Default    bool   `json:"default"`
	Advanced   bool   `json:"advanced"`
	DotNetOK   bool   `json:"dotnet_ok"`
	NativeOnly bool   `json:"native_only"`
	Heavy      bool   `json:"heavy"`
}

// Preset 预设档位。
type Preset struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// Upload 上传记录。
type Upload struct {
	ID            string     `json:"upload_id"`
	Name          string     `json:"name"`
	Size          int64      `json:"size"`
	Kind          string     `json:"kind"` // pe / dot / elf / mach
	Arch          string     `json:"arch"`
	Is64Bit       bool       `json:"is_64bit"`
	TypeName      string     `json:"type_name"`
	DotNetAnyCPU  bool       `json:"dotnet_anycpu"`
	DotNetCoreLib string     `json:"dotnet_corelib"`
	HasSymbolMap  bool       `json:"has_symbol_map"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresIn     int        `json:"expires_in"`
	Functions     []Function `json:"functions"`
}

// UploadResponse 上传接口响应。
type UploadResponse struct {
	Upload  *Upload      `json:"upload"`
	Options []OptionMeta `json:"options"`
	Presets []Preset     `json:"presets"`
	Job     *Job         `json:"job"` // 仅 auto_start=1 时出现
}

// FunctionSel 函数级保护选择。
type FunctionSel struct {
	Address uint64 `json:"address"`
	Type    string `json:"type"` // virtualization / mutation / ultra
}

// Job 任务视图。
type Job struct {
	ID         string        `json:"id"`
	Status     string        `json:"status"` // queued/running/done/failed/killed
	InputName  string        `json:"input_name"`
	FileKind   string        `json:"file_kind"`
	OutputName string        `json:"output_name"`
	Preset     string        `json:"preset"`
	Options    []string      `json:"options"`
	Functions  []FunctionSel `json:"functions"`
	CreatedAt  time.Time     `json:"created_at"`
	StartedAt  *time.Time    `json:"started_at"`
	FinishedAt *time.Time    `json:"finished_at"`
	DurationMS int64         `json:"duration_ms"`
	OutputSize int64         `json:"output_size"`
	Progress   int           `json:"progress"`
	Stage      string        `json:"stage"`
	StageName  string        `json:"stage_name"`
	QueuePos   int           `json:"queue_pos"`
	EtaSeconds int           `json:"eta_seconds"`
	WaitReason string        `json:"wait_reason"`
	ErrorMsg   string        `json:"error_msg"`
	LogTail    string        `json:"log_tail"`
	Downloaded bool          `json:"downloaded"`
	Pinned32   bool          `json:"dotnet_pinned_32bit"`
}

// Compact 返回适合塞进模型上下文的精简视图（去掉 log_tail 等大字段）。
func (j *Job) Compact() map[string]any {
	m := map[string]any{
		"job_id":     j.ID,
		"status":     j.Status,
		"progress":   j.Progress,
		"stage":      j.Stage,
		"stage_name": j.StageName,
		"input":      j.InputName,
		"output":     j.OutputName,
	}
	if j.Preset != "" {
		m["preset"] = j.Preset
	}
	if j.QueuePos > 0 {
		m["queue_pos"] = j.QueuePos
		m["eta_seconds"] = j.EtaSeconds
	}
	if j.WaitReason != "" {
		m["wait_reason"] = j.WaitReason
	}
	if j.ErrorMsg != "" {
		m["error"] = j.ErrorMsg
	}
	if j.OutputSize > 0 {
		m["output_size"] = j.OutputSize
	}
	if j.DurationMS > 0 {
		m["duration_ms"] = j.DurationMS
	}
	if j.Downloaded {
		m["downloaded"] = true
	}
	if j.Pinned32 {
		m["dotnet_pinned_32bit"] = true
	}
	if len(j.Options) > 0 {
		m["options"] = j.Options
	}
	if len(j.Functions) > 0 {
		m["functions"] = j.Functions
	}
	return m
}

// JobsResponse 任务列表。
type JobsResponse struct {
	Jobs    []*Job `json:"jobs"`
	Queue   int    `json:"queue"`
	Running int    `json:"running"`
}

// StartJobRequest 建任务请求体（字段名与服务端 handler 完全一致）。
type StartJobRequest struct {
	UploadID      string        `json:"upload_id"`
	Preset        string        `json:"preset,omitempty"`
	Options       []string      `json:"options,omitempty"`
	VMSectionName string        `json:"vm_section_name,omitempty"`
	Messages      []string      `json:"messages,omitempty"`
	Functions     []FunctionSel `json:"functions,omitempty"`
}

// ---------- 错误 ----------

// APIError 服务端返回的结构化错误（{error, message} 或 {error, message, detail}）。
type APIError struct {
	Status  int    `json:"-"`
	Code    string `json:"error"`
	Message string `json:"message"`
	Detail  string `json:"detail"`
	// Hint 面向用户的修复建议（按错误码映射，已在实测中逐个遇到）。
	Hint string `json:"-"`
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("HTTP %d %s", e.Status, e.Code)
	if e.Message != "" {
		s += ": " + e.Message
	}
	if e.Detail != "" {
		s += "（" + e.Detail + "）"
	}
	if e.Hint != "" {
		s += " → " + e.Hint
	}
	return s
}

// hintFor 把实测到的错误码翻成可执行建议。未列出的返回空串（不编造）。
func hintFor(code string, status int) string {
	switch code {
	case "err.api_key_invalid":
		return "API 密钥无效或已失效：到 Web 后台「API 密钥」重新生成，更新配置文件后重启 MCP"
	case "err.login_required":
		return "服务端已开启强制登录，且当前请求未带有效会话/密钥"
	case "err.quota_exceeded":
		return "流量额度不足：上传与下载按文件大小计量，请到后台购买流量包或清理额度"
	case "err.file_too_large":
		return "超过服务端单文件上传上限：改用目录分卷任务，或让管理员调整 max-upload"
	case "err.unsupported_type":
		return "该文件类型不受支持：只接受 PE/.NET/ELF/Mach-O 构建产物（源码、脚本、压缩包不行）"
	case "err.zip_format":
		return "这是 ZIP 容器（APK/JAR 等）：先解包，对容器内的 .so/.dll/可执行文件分别加壳"
	case "err.queue_full":
		return "服务端任务队列已满：稍等 Retry-After 秒后重试"
	case "err.upload_not_found":
		return "上传记录不存在或已过期（有效期 1 小时）：重新执行 sp_upload；同时确认用的是 sp_ 用户密钥而非 X-Api-Key"
	case "err.job_not_found":
		return "任务不存在，或不属于当前密钥账号"
	case "err.result_missing":
		return "产物尚未就绪或已被清理：任务需为 done，且产物 TTL 内（默认 1 小时）"
	case "err.file_empty":
		return "上传文件为空"
	case "err.file_required":
		return "缺少文件字段：sp_upload 需要可读的本地文件路径"
	case "err.options_invalid":
		return "选项或参数不合法：先用 sp_upload 返回的 options/presets 校验键名"
	case "err.queue_timeout":
		return "排队超时（默认 30 分钟）：避开高峰或减少并发任务"
	}
	switch status {
	case http.StatusUnauthorized:
		return "鉴权失败：检查配置文件里的 api_key"
	case http.StatusForbidden:
		return "服务端拒绝：多为额度/权限问题，检查账户状态"
	case http.StatusTooManyRequests:
		return "限流：降低请求频率后重试"
	}
	return ""
}

// ---------- 基础请求 ----------

func (c *Client) do(ctx context.Context, method, path string, body []byte, contentType string) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, wrapNetErr(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, nil, wrapNetErr(err)
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, data, decodeAPIError(resp.StatusCode, data)
	}
	return resp.StatusCode, data, nil
}

func decodeAPIError(status int, data []byte) error {
	e := &APIError{Status: status}
	if err := json.Unmarshal(data, e); err != nil || e.Code == "" {
		e.Code = "http_" + strconv.Itoa(status)
		if len(data) > 0 && len(data) < 400 {
			e.Message = strings.TrimSpace(string(data))
		}
	}
	e.Hint = hintFor(e.Code, status)
	// 有些拒绝原因藏在 detail 里（服务端的格式探测细节），按实测文案细化提示。
	if e.Hint != "" && e.Detail != "" {
		low := strings.ToLower(e.Detail)
		switch {
		case strings.Contains(low, "bind info"), strings.Contains(low, "chained fixups"):
			e.Hint = "该 Mach-O 的绑定信息格式不受支持（chained fixups / 新版 bind info 流）：换用未启用 chained fixups 的构建，或改用其它平台产物"
		case strings.Contains(low, "single file"), strings.Contains(low, "bundle"):
			e.Hint = "这是 .NET 单文件（PublishSingleFile）产物：原生路径会破坏 bundle 清单，请改为普通发布方式后再加壳"
		}
	}
	return e
}

func wrapNetErr(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("请求超时：%w（可用 sp_job_status 继续查询，不必重跑）", err)
	}
	if errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("连接服务端失败：%w", err)
}

// ---------- 具体接口 ----------

// Health 探测 /healthz（不需要鉴权）。
func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/healthz", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, wrapNetErr(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("解析 /healthz 失败: %w", err)
	}
	return m, nil
}

// CheckAuth 用一次轻量 API 调用验证密钥是否可用（GET /api/v1/jobs）。
func (c *Client) CheckAuth(ctx context.Context) error {
	_, _, err := c.do(ctx, http.MethodGet, "/api/v1/jobs", nil, "")
	// 只区分鉴权失败，其它错误（如服务端 500）不阻塞使用。
	if ae, ok := err.(*APIError); ok && ae.Status == http.StatusUnauthorized {
		return ae
	}
	return nil
}

// Upload 上传构建产物（可选符号文件）。
func (c *Client) Upload(ctx context.Context, filePath, symbolPath string) (*UploadResponse, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开待上传文件失败: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		defer pw.Close()
		if err := writeMultipart(mw, "file", filepath.Base(filePath), f, st.Size()); err != nil {
			pw.CloseWithError(err)
			return
		}
		if symbolPath != "" {
			sf, err := os.Open(symbolPath)
			if err != nil {
				pw.CloseWithError(fmt.Errorf("打开符号文件失败: %w", err))
				return
			}
			defer sf.Close()
			sst, err := sf.Stat()
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			if err := writeMultipart(mw, "symbol", filepath.Base(symbolPath), sf, sst.Size()); err != nil {
				pw.CloseWithError(err)
				return
			}
		}
		pw.CloseWithError(mw.Close())
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v1/uploads", pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.ContentLength = -1
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, wrapNetErr(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, wrapNetErr(err)
	}
	if resp.StatusCode >= 400 {
		return nil, decodeAPIError(resp.StatusCode, data)
	}
	var out UploadResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("解析上传响应失败: %w", err)
	}
	if out.Upload == nil {
		return nil, errors.New("上传响应缺少 upload 字段")
	}
	return &out, nil
}

func writeMultipart(mw *multipart.Writer, field, name string, r io.Reader, size int64) error {
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{fmt.Sprintf(`form-data; name=%q; filename=%q`, field, name)}
	h["Content-Type"] = []string{"application/octet-stream"}
	w, err := mw.CreatePart(h)
	if err != nil {
		return err
	}
	n, err := io.Copy(w, r)
	if err != nil {
		return err
	}
	_ = size
	_ = n
	return nil
}

// StartJob 建任务，返回 202 语义的初始视图。
func (c *Client) StartJob(ctx context.Context, reqBody StartJobRequest) (*Job, error) {
	b, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	code, data, err := c.do(ctx, http.MethodPost, "/api/v1/jobs", b, "application/json")
	if err != nil {
		return nil, err
	}
	if code != http.StatusAccepted && code != http.StatusOK {
		return nil, fmt.Errorf("建任务返回非预期状态码 %d", code)
	}
	var j Job
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("解析任务响应失败: %w", err)
	}
	return &j, nil
}

// GetJob 查询单任务（轮询用）。
func (c *Client) GetJob(ctx context.Context, id string) (*Job, error) {
	_, data, err := c.do(ctx, http.MethodGet, "/api/v1/jobs/"+id, nil, "")
	if err != nil {
		return nil, err
	}
	var j Job
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("解析任务失败: %w", err)
	}
	return &j, nil
}

// ListJobs 当前密钥账号的任务列表。
func (c *Client) ListJobs(ctx context.Context) (*JobsResponse, error) {
	_, data, err := c.do(ctx, http.MethodGet, "/api/v1/jobs", nil, "")
	if err != nil {
		return nil, err
	}
	var out JobsResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("解析任务列表失败: %w", err)
	}
	return &out, nil
}

// JobLog 取任务完整日志（失败排查用；服务端最多返回 4MB）。
func (c *Client) JobLog(ctx context.Context, id string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/v1/jobs/"+id+"/log", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", wrapNetErr(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", wrapNetErr(err)
	}
	if resp.StatusCode >= 400 {
		return "", decodeAPIError(resp.StatusCode, data)
	}
	return string(data), nil
}

// CancelJob 删除/取消任务。
func (c *Client) CancelJob(ctx context.Context, id string) error {
	_, _, err := c.do(ctx, http.MethodDelete, "/api/v1/jobs/"+id, nil, "")
	return err
}

// DownloadResult 下载产物到 destPath（流式落盘并同时算 sha256）。
// 服务端只有"完整传输"才扣流量并清理产物，因此这里必须读到 EOF 并校验字节数。
type DownloadResult struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func (c *Client) DownloadResult(ctx context.Context, jobID, destPath string) (*DownloadResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/v1/jobs/"+jobID+"/result", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, wrapNetErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, decodeAPIError(resp.StatusCode, data)
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return nil, err
	}
	// 先写临时文件，成功后 rename：中断不会留下半个"看起来正常"的产物。
	tmp := destPath + ".part"
	out, err := os.Create(tmp)
	if err != nil {
		return nil, err
	}
	defer func() { _ = out.Close() }()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), resp.Body)
	if err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("下载中断（%d 字节后）：%w；可重试 sp_fetch_result，任务仍在", n, err)
	}
	if resp.ContentLength > 0 && n != resp.ContentLength {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("下载不完整：期望 %d 字节，实际 %d 字节", resp.ContentLength, n)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	if err := os.Rename(tmp, destPath); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	return &DownloadResult{Path: destPath, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}
