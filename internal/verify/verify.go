// Package verify 做"保护前后功能一致性"回测：先在**原始产物**上采基线，
// 再在**受保护产物**上跑同一套动作，比较退出码 / 标准输出 / 期望正则。
//
// 为什么必须采基线：本仓库历史上多次出现"能加壳、能启动、但功能已被破坏"的
// 情况（Span/ref struct 回退、异常帧穿透、方法体令牌错位）。只跑受保护产物
// 得到"看起来正常"的结果没有意义，必须两跑对比。
package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Profile 验证档位。
type Profile string

const (
	// ProfileRun 跑一次可执行文件（默认）。
	ProfileRun Profile = "run"
	// ProfileTests 跑项目自带测试；会把受保护产物临时替换到原路径，
	// 跑完必定还原（有备份 + defer 双保险）。
	ProfileTests Profile = "tests"
	// ProfileSmoke 只比退出码，容忍输出差异。
	ProfileSmoke Profile = "smoke"
)

// RunSpec 可执行文件跑法。
type RunSpec struct {
	Exe               string   `json:"exe"`  // 留空=直接执行目标文件
	Args              []string `json:"args"` // 支持 {file} 占位符
	Cwd               string   `json:"cwd"`
	ExpectExit        *int     `json:"expect_exit"`         // 期望退出码（对两侧都校验）
	ExpectStdoutRegex string   `json:"expect_stdout_regex"` // 期望 stdout 命中（对两侧都校验）
	Env               []string `json:"env"`                 // KEY=VALUE
}

// TestsSpec 测试命令跑法。
type TestsSpec struct {
	Cmd      string   `json:"cmd"` // 必填：如 "dotnet test -c Release"
	Cwd      string   `json:"cwd"`
	TimeoutS int      `json:"timeout_s"`
	Env      []string `json:"env"`
}

// Request 验证请求。
type Request struct {
	Original  string     `json:"original"`
	Protected string     `json:"protected"`
	Profile   Profile    `json:"profile"`
	Run       *RunSpec   `json:"run"`
	Tests     *TestsSpec `json:"tests"`
	TimeoutS  int        `json:"timeout_s"`
}

// RunOutcome 单次运行的结果。
type RunOutcome struct {
	ExitCode    int    `json:"exit_code"`
	Started     bool   `json:"started"`
	Error       string `json:"error,omitempty"`
	DurationMS  int64  `json:"duration_ms"`
	StdoutBytes int    `json:"stdout_bytes"`
	StderrBytes int    `json:"stderr_bytes"`
	StdoutHash  string `json:"stdout_sha256"`
	StdoutTail  string `json:"stdout_tail,omitempty"`
	StderrTail  string `json:"stderr_tail,omitempty"`
	stdoutNorm  string
	stderrNorm  string
}

// Check 逐项判定。
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Result 验证结论。
type Result struct {
	Verdict           string         `json:"verdict"` // pass / degraded / fail / error
	Profile           string         `json:"profile"`
	Baseline          *RunOutcome    `json:"baseline,omitempty"`
	Protected         *RunOutcome    `json:"protected_run,omitempty"`
	Checks            []Check        `json:"checks"`
	Diffs             []string       `json:"diffs,omitempty"`
	Artifacts         map[string]any `json:"artifacts"`
	ProtectionApplied bool           `json:"protection_applied"`
	Notes             []string       `json:"notes,omitempty"`
}

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")

// Run 执行验证。
func Run(ctx context.Context, req *Request) (*Result, error) {
	if req.Original == "" || req.Protected == "" {
		return nil, errors.New("original 与 protected 都必须给出绝对路径")
	}
	if sameFile(req.Original, req.Protected) {
		return nil, errors.New("original 与 protected 指向同一个文件：请把产物下载到另一个路径再验证")
	}
	for _, p := range []string{req.Original, req.Protected} {
		if st, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("产物不可读 %s: %w", p, err)
		} else if st.IsDir() {
			return nil, fmt.Errorf("%s 是目录，需要具体文件", p)
		}
	}
	if req.Profile == "" {
		req.Profile = ProfileRun
	}
	if req.TimeoutS <= 0 {
		req.TimeoutS = 300
	}

	res := &Result{Profile: string(req.Profile), Artifacts: map[string]any{}}
	origHash, origSize := hashFile(req.Original)
	protHash, protSize := hashFile(req.Protected)
	res.Artifacts["original"] = map[string]any{"path": req.Original, "size": origSize, "sha256": origHash}
	res.Artifacts["protected"] = map[string]any{"path": req.Protected, "size": protSize, "sha256": protHash}
	if origSize > 0 {
		res.Artifacts["size_delta"] = protSize - origSize
		res.Artifacts["size_ratio"] = float64(protSize) / float64(origSize)
	}
	res.ProtectionApplied = origHash != protHash
	if !res.ProtectionApplied {
		res.Checks = append(res.Checks, Check{Name: "protection_applied", OK: false,
			Detail: "受保护产物与原始文件字节完全相同：加壳没有生效（检查预设是否为 custom 且选项为空）"})
		res.Verdict = "fail"
		res.Notes = append(res.Notes, "字节相同说明这次没有保护动作，功能一致也不能算通过")
		return res, nil
	}

	var base, cand *RunOutcome
	var err error
	switch req.Profile {
	case ProfileTests:
		if req.Tests == nil || strings.TrimSpace(req.Tests.Cmd) == "" {
			return nil, errors.New("profile=tests 需要 tests.cmd（例如 \"dotnet test -c Release\"）")
		}
		base, cand, err = runWithSwap(ctx, req)
	case ProfileRun, ProfileSmoke:
		base, err = runOnce(ctx, req.Original, req.Run, req)
		if err == nil {
			cand, err = runOnce(ctx, req.Protected, req.Run, req)
		}
	default:
		return nil, fmt.Errorf("未知 profile %q（可用 run / tests / smoke）", req.Profile)
	}
	if err != nil {
		res.Verdict = "error"
		res.Checks = append(res.Checks, Check{Name: "exec", OK: false, Detail: err.Error()})
		if base != nil {
			res.Baseline = base
		}
		if cand != nil {
			res.Protected = cand
		}
		return res, nil
	}
	res.Baseline, res.Protected = base, cand

	verdict := "pass"

	// 1) 基线本身必须成功，否则这套动作不能用来判定（先修验证用例）
	if !base.Started {
		res.Checks = append(res.Checks, Check{Name: "baseline_started", OK: false,
			Detail: "原始产物都跑不起来：" + base.Error + "（验证用例本身有问题）"})
		verdict = "fail"
	} else if base.ExitCode != 0 && (req.Run == nil || req.Run.ExpectExit == nil) {
		res.Checks = append(res.Checks, Check{Name: "baseline_ok", OK: false,
			Detail: fmt.Sprintf("原始产物退出码 %d（非 0），基线不干净；请用 run.args/expect_exit 指定正确用法", base.ExitCode)})
		verdict = "fail"
	}

	// 2) 受保护产物能不能跑
	if !cand.Started {
		res.Checks = append(res.Checks, Check{Name: "protected_started", OK: false,
			Detail: "受保护产物无法启动：" + cand.Error})
		res.Verdict = "fail"
		return res, nil
	}

	// 3) 退出码
	if base.Started && base.ExitCode == cand.ExitCode {
		res.Checks = append(res.Checks, Check{Name: "exit_code", OK: true,
			Detail: fmt.Sprintf("两侧均为 %d", cand.ExitCode)})
	} else if base.Started {
		res.Checks = append(res.Checks, Check{Name: "exit_code", OK: false,
			Detail: fmt.Sprintf("基线 %d → 受保护 %d", base.ExitCode, cand.ExitCode)})
		res.Diffs = append(res.Diffs, fmt.Sprintf("exit_code: %d → %d", base.ExitCode, cand.ExitCode))
		verdict = "fail"
	}

	// 4) 期望正则（两侧都要命中，否则说明用例写错了）
	if req.Run != nil && req.Run.ExpectStdoutRegex != "" {
		re, rerr := regexp.Compile(req.Run.ExpectStdoutRegex)
		if rerr != nil {
			res.Checks = append(res.Checks, Check{Name: "expect_stdout_regex", OK: false,
				Detail: "正则非法: " + rerr.Error()})
			verdict = "fail"
		} else {
			okBase := re.MatchString(base.stdoutNorm + "\n" + base.stderrNorm)
			okCand := re.MatchString(cand.stdoutNorm + "\n" + cand.stderrNorm)
			switch {
			case okBase && okCand:
				res.Checks = append(res.Checks, Check{Name: "expect_stdout_regex", OK: true,
					Detail: "两侧都命中 /" + req.Run.ExpectStdoutRegex + "/"})
			case okBase && !okCand:
				res.Checks = append(res.Checks, Check{Name: "expect_stdout_regex", OK: false,
					Detail: "受保护产物不再命中 /" + req.Run.ExpectStdoutRegex + "/"})
				verdict = "fail"
			default:
				res.Checks = append(res.Checks, Check{Name: "expect_stdout_regex", OK: false,
					Detail: "基线就没命中，说明用例写错了（换一个真的会出现的输出）"})
				verdict = "fail"
			}
		}
	}

	// 5) 标准输出一致性
	if req.Profile == ProfileSmoke {
		res.Checks = append(res.Checks, Check{Name: "stdout", OK: true,
			Detail: "smoke 档只比退出码，输出差异不判失败"})
	} else if base.stdoutNorm == cand.stdoutNorm {
		res.Checks = append(res.Checks, Check{Name: "stdout", OK: true,
			Detail: "规范化输出完全一致（sha256 " + short(cand.StdoutHash) + "）"})
	} else {
		res.Checks = append(res.Checks, Check{Name: "stdout", OK: false,
			Detail: "退出码相同但输出不同（可能只是耗时/路径差异，也可能是功能弱化）"})
		res.Diffs = append(res.Diffs, diffLines(base.stdoutNorm, cand.stdoutNorm, 20)...)
		if verdict == "pass" {
			verdict = "degraded"
		}
	}

	// 6) stderr 只提示不判死：加壳后加载器警告、调试输出都可能出现在 stderr
	if base.stderrNorm != cand.stderrNorm && req.Profile != ProfileSmoke {
		res.Notes = append(res.Notes,
			"stderr 内容有差异（不作为失败判据）："+firstLine(cand.stderrNorm))
	}

	res.Verdict = verdict
	if verdict == "degraded" {
		res.Notes = append(res.Notes,
			"degraded = 退出码正确但输出有差异：若业务依赖这些输出，请判为失败并调整方案")
	}
	if req.Profile == ProfileTests {
		res.Notes = append(res.Notes,
			"tests 档在两次运行之间把受保护产物临时替换到 original 路径，运行结束后已还原原始字节")
	}
	return res, nil
}

// runOnce 用同一套参数跑一个产物。
func runOnce(ctx context.Context, file string, spec *RunSpec, req *Request) (*RunOutcome, error) {
	timeout := time.Duration(req.TimeoutS) * time.Second
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	exe, args, cwd, envs, err := buildCmd(file, spec, req)
	if err != nil {
		return &RunOutcome{Error: err.Error()}, nil
	}
	cmd := exec.CommandContext(cctx, exe, args...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	cmd.Env = append(os.Environ(), envs...)
	cmd.Env = append(cmd.Env, "SP_PROTECT_ARTIFACT="+file)

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	t0 := time.Now()
	runErr := cmd.Run()
	out := &RunOutcome{DurationMS: time.Since(t0).Milliseconds()}

	rawOut, rawErr := stdout.String(), stderr.String()
	out.StdoutBytes, out.StderrBytes = len(rawOut), len(rawErr)
	out.stdoutNorm = normalize(rawOut, req.Original, req.Protected)
	out.stderrNorm = normalize(rawErr, req.Original, req.Protected)
	out.StdoutHash = sha256Hex(out.stdoutNorm)
	out.StdoutTail = tail(out.stdoutNorm, 2000)
	out.StderrTail = tail(out.stderrNorm, 2000)
	out.Started = true

	switch {
	case runErr == nil:
		out.ExitCode = 0
	case cctx.Err() == context.DeadlineExceeded:
		out.Started = false
		out.Error = fmt.Sprintf("%d 秒超时；加壳后可能初始化变慢，可调大 timeout_s，或改用 profile=smoke", req.TimeoutS)
		return out, nil
	default:
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			out.ExitCode = ee.ExitCode()
		} else {
			out.Started = false
			out.Error = runErr.Error()
		}
	}
	return out, nil
}

func buildCmd(file string, spec *RunSpec, _ *Request) (exe string, args []string, cwd string, env []string, err error) {
	if spec == nil {
		spec = &RunSpec{}
	}
	exe = spec.Exe
	if exe == "" {
		ext := strings.ToLower(filepath.Ext(file))
		switch ext {
		case ".exe", ".dll", ".so", ".dylib", "":
			if runtime.GOOS == "windows" && ext == ".dll" {
				return "", nil, "", nil, fmt.Errorf(
					"%s 是 DLL，不能直接执行：在 run.exe 里指定宿主（如 \"dotnet\"）并在 run.args 用 {file}", filepath.Base(file))
			}
			exe = file
		default:
			return "", nil, "", nil, fmt.Errorf("不认识的产物类型 %q：请在 run.exe 指定如何运行", ext)
		}
	}
	for _, a := range spec.Args {
		args = append(args, strings.ReplaceAll(a, "{file}", file))
	}
	if spec.Exe != "" && len(spec.Args) == 0 && strings.EqualFold(spec.Exe, "dotnet") {
		args = []string{file}
	}
	return exe, args, spec.Cwd, spec.Env, nil
}

// runWithSwap 把受保护产物临时替换到原路径后跑测试，跑完还原。
func runWithSwap(ctx context.Context, req *Request) (*RunOutcome, *RunOutcome, error) {
	backup := req.Original + ".sp-orig-backup"
	origBytes, err := os.ReadFile(req.Original)
	if err != nil {
		return nil, nil, fmt.Errorf("备份原始产物失败: %w", err)
	}
	if err := os.WriteFile(backup, origBytes, 0o644); err != nil {
		return nil, nil, fmt.Errorf("写入备份失败: %w", err)
	}
	defer func() {
		// 双保险：defer 还原 + 备份文件保留（还原失败时用户手里还有原始字节）
		_ = os.WriteFile(req.Original, origBytes, 0o644)
	}()

	timeout := time.Duration(req.Tests.TimeoutS) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(req.TimeoutS) * time.Second
	}
	run := func() (*RunOutcome, error) {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		exe, args := shellCmd(req.Tests.Cmd)
		cmd := exec.CommandContext(cctx, exe, args...)
		if req.Tests.Cwd != "" {
			cmd.Dir = req.Tests.Cwd
		}
		cmd.Env = append(os.Environ(), req.Tests.Env...)
		var so, se strings.Builder
		cmd.Stdout, cmd.Stderr = &so, &se
		t0 := time.Now()
		runErr := cmd.Run()
		o := &RunOutcome{DurationMS: time.Since(t0).Milliseconds(), Started: true}
		o.stdoutNorm = normalize(so.String(), req.Original, req.Protected)
		o.stderrNorm = normalize(se.String(), req.Original, req.Protected)
		o.StdoutBytes, o.StderrBytes = len(so.String()), len(se.String())
		o.StdoutHash = sha256Hex(o.stdoutNorm)
		o.StdoutTail = tail(o.stdoutNorm, 2000)
		o.StderrTail = tail(o.stderrNorm, 2000)
		switch {
		case runErr == nil:
			o.ExitCode = 0
		case cctx.Err() == context.DeadlineExceeded:
			o.Started = false
			o.Error = "测试命令超时：" + req.Tests.Cmd
		default:
			var ee *exec.ExitError
			if errors.As(runErr, &ee) {
				o.ExitCode = ee.ExitCode()
			} else {
				o.Started = false
				o.Error = runErr.Error()
			}
		}
		return o, nil
	}

	base, err := run()
	if err != nil {
		return base, nil, err
	}
	// 替换为受保护产物
	protBytes, err := os.ReadFile(req.Protected)
	if err != nil {
		return base, nil, fmt.Errorf("读取受保护产物失败: %w", err)
	}
	if err := os.WriteFile(req.Original, protBytes, 0o644); err != nil {
		return base, nil, fmt.Errorf("替换产物失败: %w", err)
	}
	cand, err := run()
	return base, cand, err
}

func shellCmd(cmd string) (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/c", cmd}
	}
	return "sh", []string{"-c", cmd}
}

// normalize 规范化输出：去 ANSI、统一换行、去行尾空白、路径归一、去首尾空行。
func normalize(s, orig, prot string) string {
	if s == "" {
		return ""
	}
	s = ansiRe.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = strings.TrimRight(ln, " \t")
	}
	s = strings.Join(lines, "\n")
	// 路径归一：栈回溯里带绝对路径，两侧必然不同
	if orig != "" {
		s = strings.ReplaceAll(s, filepath.ToSlash(orig), "<artifact>")
		s = strings.ReplaceAll(s, orig, "<artifact>")
	}
	if prot != "" {
		s = strings.ReplaceAll(s, filepath.ToSlash(prot), "<artifact>")
		s = strings.ReplaceAll(s, prot, "<artifact>")
	}
	return strings.Trim(s, "\n")
}

// diffLines 给出行级差异（限定条数，避免把上下文灌爆）。
func diffLines(a, b string, max int) []string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	var out []string
	n := len(al)
	if len(bl) > n {
		n = len(bl)
	}
	for i := 0; i < n && len(out) < max; i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			if x != "" {
				out = append(out, fmt.Sprintf("基线第 %d 行: %s", i+1, clamp(x, 200)))
			}
			if y != "" {
				out = append(out, fmt.Sprintf("受保护第 %d 行: %s", i+1, clamp(y, 200)))
			}
		}
	}
	if len(out) >= max {
		out = append(out, "…（差异过多已截断，完整输出见 artifacts/stdout_tail）")
	}
	return out
}

func clamp(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return clamp(s, 300)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hashFile(p string) (string, int64) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", 0
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), int64(len(b))
}

func sameFile(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(aa, bb)
	}
	return aa == bb
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
