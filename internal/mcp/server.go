// Package mcp 实现 MCP（Model Context Protocol）的 stdio 服务端子集。
//
// 传输：stdin/stdout 上的 NDJSON —— 一行一条 JSON-RPC 2.0 消息，
// 没有 SSE、没有端口、没有握手以外的状态。stdout 只允许出现协议帧，
// 所有日志走 stderr（否则会把客户端解析器打挂）。
//
// 支持的 method：initialize、notifications/initialized、ping、tools/list、
// tools/call；其余能力（resources/prompts/logging）声明为空实现。
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"reflect"
	"runtime/debug"
	"strings"
	"sync"
)

// ProtocolVersion 我们实现的协议版本（协商时优先回显客户端版本）。
const ProtocolVersion = "2025-06-18"

// supportedVersions 已知版本，客户端请求其中之一就原样回显（兼容老客户端）。
var supportedVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
}

// HandlerFunc 工具实现：返回任意可 JSON 序列化的结果。
type HandlerFunc func(ctx context.Context, args map[string]any) (any, error)

// Tool 一个可调用工具。
type Tool struct {
	Name        string
	Title       string
	Description string
	InputSchema map[string]any
	Handler     HandlerFunc
}

// ServerInfo 暴露给客户端的自我描述。
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Server 协议处理核心。
type Server struct {
	Info  ServerInfo
	Tools []Tool
	Log   *log.Logger
	// Verbose 为真时把每次工具调用的名字与参数打到 stderr（排障用，默认关）。
	Verbose bool

	mu      sync.Mutex
	out     *bufio.Writer
	toolMap map[string]*Tool
}

// New 构造服务端；tools 顺序即 tools/list 顺序。
func New(info ServerInfo, tools []Tool, out io.Writer, lg *log.Logger) *Server {
	s := &Server{Info: info, Tools: tools, Log: lg, out: bufio.NewWriter(out), toolMap: map[string]*Tool{}}
	for i := range tools {
		s.toolMap[tools[i].Name] = &tools[i]
	}
	return s
}

// ToolNames 便于自检与文档生成。
func (s *Server) ToolNames() []string {
	names := make([]string, 0, len(s.Tools))
	for _, t := range s.Tools {
		names = append(names, t.Name)
	}
	return names
}

// ---------- JSON-RPC 帧 ----------

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// JSON-RPC 标准错误码。
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// Serve 读取 stdin 直到 EOF。返回的 error 只表示读流出错（协议错误会回帧，不中断）。
func (s *Server) Serve(ctx context.Context, in io.Reader) error {
	r := bufio.NewReaderSize(in, 64<<10)
	for {
		line, err := readMessage(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		line = trimSpace(line)
		if len(line) == 0 {
			continue
		}
		if out := s.Handle(ctx, line); len(out) > 0 {
			if err := s.write(out); err != nil {
				return err
			}
		}
	}
}

// readMessage 读一条消息：MCP 用 NDJSON（一行一帧）。
// 同时兼容 LSP 风格的 Content-Length 头（少数老客户端/中间层会这么发）。
func readMessage(r *bufio.Reader) ([]byte, error) {
	peek, _ := r.Peek(15)
	if len(peek) >= 15 && strings.EqualFold(string(peek), "content-length:") {
		var length int
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return nil, err
			}
			line = strings.TrimSpace(line)
			if len(line) == 0 {
				break
			}
			if n, ok := parseContentLength(string(line)); ok {
				length = n
			}
		}
		if length <= 0 {
			return nil, nil
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	line, err := r.ReadBytes('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && len(trimSpace(line)) > 0 {
			return line, nil
		}
		return nil, err
	}
	return line, nil
}

func parseContentLength(h string) (int, bool) {
	parts := strings.SplitN(h, ":", 2)
	if len(parts) != 2 {
		return 0, false
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &n); err != nil {
		return 0, false
	}
	return n, true
}

func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\t' || b[start] == '\r' || b[start] == '\n') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\r' || b[end-1] == '\n') {
		end--
	}
	return b[start:end]
}

func (s *Server) write(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.out.Write(b); err != nil {
		return err
	}
	if err := s.out.WriteByte('\n'); err != nil {
		return err
	}
	return s.out.Flush()
}

// Handle 处理一条消息，返回要写回的帧（通知类返回 nil）。
func (s *Server) Handle(ctx context.Context, raw []byte) []byte {
	defer func() {
		if r := recover(); r != nil {
			s.logf("panic in handler: %v\n%s", r, debug.Stack())
		}
	}()

	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return s.encode(nil, nil, &rpcError{Code: codeParseError, Message: "JSON 解析失败: " + err.Error()})
	}
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"
	if req.Method == "" {
		if isNotification {
			return nil
		}
		return s.encode(req.ID, nil, &rpcError{Code: codeInvalidRequest, Message: "缺少 method"})
	}

	switch req.Method {
	case "initialize":
		return s.reply(req.ID, s.initializeResult(req.Params))
	case "notifications/initialized", "notifications/cancelled", "initialized":
		return nil // 通知无需响应
	case "ping":
		return s.reply(req.ID, map[string]any{})
	case "tools/list":
		return s.reply(req.ID, map[string]any{"tools": s.toolList()})
	case "tools/call":
		return s.callTool(ctx, req)
	case "resources/list":
		return s.reply(req.ID, map[string]any{"resources": []any{}})
	case "resources/templates/list":
		return s.reply(req.ID, map[string]any{"resourceTemplates": []any{}})
	case "prompts/list":
		return s.reply(req.ID, map[string]any{"prompts": []any{}})
	case "logging/setLevel":
		return s.reply(req.ID, map[string]any{})
	default:
		if isNotification {
			return nil
		}
		return s.encode(req.ID, nil, &rpcError{Code: codeMethodNotFound, Message: "不支持的 method: " + req.Method})
	}
}

func (s *Server) initializeResult(params json.RawMessage) map[string]any {
	version := ProtocolVersion
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len(params) > 0 && json.Unmarshal(params, &p) == nil && p.ProtocolVersion != "" {
		if supportedVersions[p.ProtocolVersion] {
			version = p.ProtocolVersion
		}
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": s.Info,
		"instructions": "SoftProtect 加壳服务。推荐流程：sp_scan_project → sp_build_plan → sp_upload → " +
			"sp_protect → sp_job_status（单次轮询，不要循环刷）→ sp_fetch_result → sp_verify。\n" +
			"耗时操作立即返回 job_id，绝不阻塞等待；本服务不使用 SSE。\n" +
			"API 密钥只在进程配置里，工具参数中不存在密钥字段。",
	}
}

func (s *Server) toolList() []map[string]any {
	out := make([]map[string]any, 0, len(s.Tools))
	for _, t := range s.Tools {
		m := map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		}
		if t.Title != "" {
			m["title"] = t.Title
		}
		out = append(out, m)
	}
	return out
}

func (s *Server) callTool(ctx context.Context, req request) []byte {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return s.encode(req.ID, nil, &rpcError{Code: codeInvalidParams, Message: "params 解析失败: " + err.Error()})
	}
	tool, ok := s.toolMap[p.Name]
	if !ok {
		return s.encode(req.ID, nil, &rpcError{Code: codeInvalidParams,
			Message: fmt.Sprintf("未知工具 %q（可用：%s）", p.Name, strings.Join(s.ToolNames(), ", "))})
	}
	args := map[string]any{}
	if len(p.Arguments) > 0 && string(p.Arguments) != "null" {
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return s.encode(req.ID, nil, &rpcError{Code: codeInvalidParams, Message: "arguments 解析失败: " + err.Error()})
		}
	}

	result, err := s.invoke(ctx, tool, args)
	if err != nil {
		// 工具级失败按 MCP 约定放在 result.isError，让模型能读到原因并自我修复。
		return s.reply(req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": err.Error()}},
			"isError": true,
		})
	}
	return s.reply(req.ID, map[string]any{
		"content": []map[string]any{{"type": "text", "text": renderText(result)}},
	})
}

func (s *Server) invoke(ctx context.Context, t *Tool, args map[string]any) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			s.logf("panic in %s: %v\n%s", t.Name, r, debug.Stack())
			err = fmt.Errorf("工具 %s 内部错误: %v", t.Name, r)
		}
	}()
	if s.Verbose {
		s.logf("call %s args=%s", t.Name, compactJSON(args))
	}
	return t.Handler(ctx, args)
}

// renderText 结构化结果统一渲染成"人类可读 JSON"，模型和人都能直接读懂。
func renderText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func (s *Server) reply(id json.RawMessage, result any) []byte {
	return s.encode(id, result, nil)
}

func (s *Server) encode(id json.RawMessage, result any, rerr *rpcError) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	// 手工拼帧：result 与 error 互斥且必须出现其一，用 struct+omitempty 会
	// 在"空对象结果"（如 ping）时把 result 整条丢掉，客户端判定为非法帧。
	m := map[string]any{"jsonrpc": "2.0", "id": id}
	if rerr != nil {
		m["error"] = rerr
	} else {
		if result == nil {
			result = map[string]any{}
		}
		m["result"] = result
	}
	b, err := json.Marshal(m)
	if err != nil {
		b, _ = json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id,
			"error": &rpcError{Code: codeInternalError, Message: "结果序列化失败: " + err.Error()}})
	}
	return b
}

func (s *Server) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log.Printf(format, args...)
	}
}

func compactJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "?"
	}
	if len(b) > 800 {
		return string(b[:800]) + "…"
	}
	return string(b)
}

// ---------- 参数提取（带类型校验，绝不静默取零值） ----------

// 供其它 package 复用的导出包装（保持内部实现单一）。
func ArgString(args map[string]any, key string) (string, bool) { return argString(args, key) }
func ArgStringDefault(args map[string]any, key, def string) string {
	return argStringDefault(args, key, def)
}
func ArgBool(args map[string]any, key string, def bool) bool { return argBool(args, key, def) }
func ArgInt(args map[string]any, key string, def int) int    { return argInt(args, key, def) }
func ArgFloat(args map[string]any, key string, def float64) float64 {
	return argFloat(args, key, def)
}
func ArgStrings(args map[string]any, key string) []string   { return argStrings(args, key) }
func ArgMap(args map[string]any, key string) map[string]any { return argMap(args, key) }
func AsSlice(v any) []any                                   { return asSlice(v) }

func argString(args map[string]any, key string) (string, bool) {
	v, ok := args[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return strings.TrimSpace(s), ok
}

func argStringDefault(args map[string]any, key, def string) string {
	if s, ok := argString(args, key); ok && s != "" {
		return s
	}
	return def
}

func argBool(args map[string]any, key string, def bool) bool {
	v, ok := args[key]
	if !ok {
		return def
	}
	b, ok := v.(bool)
	if !ok {
		return def
	}
	return b
}

func argInt(args map[string]any, key string, def int) int {
	v, ok := args[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return def
		}
		return int(i)
	}
	return def
}

func argFloat(args map[string]any, key string, def float64) float64 {
	v, ok := args[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	}
	return def
}

func argStrings(args map[string]any, key string) []string {
	v, ok := args[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		if s, ok := it.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func argMap(args map[string]any, key string) map[string]any {
	v, ok := args[key]
	if !ok {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

// asSlice 把任意值规整成 []any（兼容 JSON 数组以外的 Go 类型）。
func asSlice(v any) []any {
	if v == nil {
		return nil
	}
	if s, ok := v.([]any); ok {
		return s
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice {
		out := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out[i] = rv.Index(i).Interface()
		}
		return out
	}
	return nil
}
