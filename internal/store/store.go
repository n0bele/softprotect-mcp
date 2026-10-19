// Package store 记录每次加壳任务，供 sp_history 查询。
//
// 存储格式：append-only JSONL（一行一条完整快照），同一 job_id 多条时"最后一条生效"。
// 为什么不用 SQLite：MCP 需要单文件静态二进制、无 CGO、零外部依赖；
// 任务量级是每天几十到几百条，JSONL 的查询成本可以忽略，且人能直接读/删。
package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Record 一条任务记录（每次状态更新追加一条完整快照）。
type Record struct {
	JobID       string         `json:"job_id"`
	UploadID    string         `json:"upload_id,omitempty"`
	Input       string         `json:"input"`
	InputSHA256 string         `json:"input_sha256,omitempty"`
	InputSize   int64          `json:"input_size,omitempty"`
	Kind        string         `json:"kind,omitempty"`
	Preset      string         `json:"preset,omitempty"`
	Options     []string       `json:"options,omitempty"`
	Functions   []any          `json:"functions,omitempty"`
	Status      string         `json:"status"`
	Error       string         `json:"error,omitempty"`
	Server      map[string]any `json:"server,omitempty"`
	Artifact    map[string]any `json:"artifact,omitempty"`
	Verify      map[string]any `json:"verify,omitempty"`
	StartedAt   time.Time      `json:"started_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// Store JSONL 存储。
type Store struct {
	path string
	mu   sync.Mutex
}

// Open 打开（不存在则创建目录）。
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("记录文件路径为空")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	return &Store{path: path}, nil
}

// Append 追加一条快照。
func (s *Store) Append(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.UpdatedAt.IsZero() {
		r.UpdatedAt = time.Now()
	}
	if r.StartedAt.IsZero() {
		r.StartedAt = r.UpdatedAt
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// List 读全部快照，按 job_id 折叠（最后一条生效），按 UpdatedAt 倒序返回。
func (s *Store) List(limit int, jobID, status string, since time.Time) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Record{}, nil
		}
		return nil, err
	}
	defer f.Close()

	latest := map[string]Record{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue // 跳过损坏行（进程被杀时可能留下半行）
		}
		if r.JobID == "" {
			continue
		}
		if !since.IsZero() && r.UpdatedAt.Before(since) {
			continue
		}
		if prev, ok := latest[r.JobID]; !ok || r.UpdatedAt.After(prev.UpdatedAt) {
			latest[r.JobID] = r
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(latest))
	for _, r := range latest {
		if jobID != "" && r.JobID != jobID {
			continue
		}
		if status != "" && r.Status != status {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Path 记录文件路径（给用户看）。
func (s *Store) Path() string { return s.path }
