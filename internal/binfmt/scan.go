// Package binfmt 本地识别构件的格式并尽力枚举可保护函数。
//
// 定位：sp_scan_project 在**上传之前**给出可解释的方案，因此不能依赖服务端。
// 每种格式能拿到的信息强度不同，实现里如实标注，不虚构：
//   - .NET 程序集：解析 CLI 元数据 MethodDef 表 → 全部 IL 方法（无需 pdb）
//   - 原生 PE：导出表 + 入口点（无 pdb 时这就是全部；有 .pdb/.map 时随上传附带，
//     由服务端枚举出更多）
//   - ELF：.symtab/.dynsym 的 FUNC 符号
//   - Mach-O：LC_SYMTAB 符号表
package binfmt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Function 与服务端 spapi.Function 字段一致（address/name/source）。
type Function struct {
	Address uint64 `json:"address"`
	Size    uint32 `json:"size"`
	Name    string `json:"name"`
	Source  string `json:"source"` // method / export / entry / symbol
}

// Info 一个文件的识别结果。
type Info struct {
	Format string `json:"format"` // dot / pe / elf / mach
	Arch   string `json:"arch"`   // x86 / x64 / arm64 / arm / unknown
	Is64   bool   `json:"is_64bit"`

	ImageBase uint64     `json:"image_base,omitempty"`
	Functions []Function `json:"functions,omitempty"`

	// SymbolQuality 说明 Functions 的来源强度，供 plan 阶段给出诚实结论：
	// full（.NET 全方法）/ exports（仅导出）/ symbols（符号表）/ none（枚举失败）。
	SymbolQuality string `json:"symbol_quality"`
	// Notes 给人看的说明（为什么只有这么几个函数、缺什么）。
	Notes []string `json:"notes,omitempty"`

	// SymbolFile 同目录自动发现的符号文件（.pdb/.map），上传时优先附带。
	SymbolFile string `json:"symbol_file,omitempty"`
}

// Errors
var (
	ErrUnsupported = errors.New("无法识别的文件格式")
)

// ScanBytes 识别内存中的文件内容。
func ScanBytes(data []byte) (*Info, error) {
	if len(data) < 4 {
		return nil, ErrUnsupported
	}
	switch {
	case len(data) >= 0x40 && data[0] == 'M' && data[1] == 'Z':
		return scanPE(data)
	case len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F':
		return scanELF(data)
	case len(data) >= 4 && isMachMagic(binary.BigEndian.Uint32(data[0:4])):
		return scanMachO(data)
	case len(data) >= 4 && isMachMagic(binary.LittleEndian.Uint32(data[0:4])):
		return scanMachO(data)
	}
	return nil, ErrUnsupported
}

// ScanFile 读文件并识别；同时探测同目录的 pdb/map 符号文件。
func ScanFile(path string) (*Info, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	// 上限 256MB：再大也不该作为单个 MCP 扫描对象（服务端 max-upload 通常 50MB）。
	data, err := io.ReadAll(io.LimitReader(f, 256<<20))
	if err != nil {
		return nil, 0, err
	}
	info, err := ScanBytes(data)
	if err != nil {
		return nil, st.Size(), err
	}
	if sym := FindSymbolFile(path); sym != "" {
		info.SymbolFile = sym
		info.Notes = append(info.Notes, fmt.Sprintf("发现符号文件 %s，上传时会自动附带（可枚举更多函数）", filepath.Base(sym)))
	}
	return info, st.Size(), nil
}

// FindSymbolFile 在同目录找与主文件同名的 .pdb/.map（大小写不敏感）。
func FindSymbolFile(binPath string) string {
	dir := filepath.Dir(binPath)
	base := strings.TrimSuffix(filepath.Base(binPath), filepath.Ext(binPath))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	// pdb 优先级高于 map（pdb 有函数名+RVA+大小）
	for _, want := range []string{".pdb", ".map"} {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			if strings.EqualFold(strings.TrimSuffix(n, filepath.Ext(n)), base) &&
				strings.EqualFold(filepath.Ext(n), want) {
				return filepath.Join(dir, n)
			}
		}
	}
	return ""
}

// ---------- PE ----------

type peLayout struct {
	imageBase  uint64
	is64       bool
	machine    uint16
	entryRVA   uint32
	sections   []peSection
	exportRVA  uint32
	exportSize uint32
	corRVA     uint32
	dotNet     bool
}

type peSection struct {
	name    string
	rva     uint32
	vsize   uint32
	rawOff  uint32
	rawSize uint32
}

func (l *peLayout) rva2off(rva uint32) (int, bool) {
	for _, s := range l.sections {
		if rva >= s.rva && rva < s.rva+max32(s.vsize, s.rawSize) {
			return int(s.rawOff + (rva - s.rva)), true
		}
	}
	return 0, false
}

func scanPE(data []byte) (*Info, error) {
	l, err := parsePE(data)
	if err != nil {
		return nil, err
	}
	info := &Info{Format: "pe", Is64: l.is64, ImageBase: l.imageBase,
		Arch: map[uint16]string{0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64", 0x1c4: "arm"}[l.machine]}
	if info.Arch == "" {
		info.Arch = "unknown"
	}

	// .NET：先用元数据枚举 IL 方法，这是最强信号。
	if l.corRVA != 0 {
		if fns, err := enumerateDotNet(data, l, 400); err == nil && len(fns) > 0 {
			info.Format = "dot"
			info.Functions = fns
			info.SymbolQuality = "full"
			info.Notes = append(info.Notes,
				fmt.Sprintf(".NET 程序集：本地解析元数据得到 %d 个 IL 方法（无需 pdb）", len(fns)))
			if len(fns) >= 400 {
				info.Notes = append(info.Notes, "已达 400 条枚举上限（与服务端同一上限），更多方法不会出现在清单里")
			}
			return info, nil
		}
		info.Format = "dot"
		info.Notes = append(info.Notes, ".NET 程序集，但元数据解析失败：函数清单以上传后服务端返回为准")
	}

	var fns []Function
	seen := map[uint64]bool{}
	add := func(f Function) {
		if f.Address == 0 || seen[f.Address] {
			return
		}
		seen[f.Address] = true
		fns = append(fns, f)
	}
	if l.exportRVA != 0 {
		for _, f := range parseExports(data, l) {
			add(f)
		}
	}
	if l.entryRVA != 0 {
		add(Function{Address: l.imageBase + uint64(l.entryRVA), Name: "entry", Source: "entry"})
	}
	sort.SliceStable(fns, func(i, j int) bool { return fns[i].Address < fns[j].Address })
	info.Functions = fns

	switch {
	case len(fns) == 0:
		info.SymbolQuality = "none"
		info.Notes = append(info.Notes, "无导出表且无入口点：本地无法枚举函数，需 .pdb/.map 或上传后看服务端结果")
	case l.exportRVA != 0:
		info.SymbolQuality = "exports"
		info.Notes = append(info.Notes, fmt.Sprintf("原生 PE：仅导出表可见（%d 个），未含内部函数", len(fns)))
	default:
		info.SymbolQuality = "exports"
	}
	return info, nil
}

func parsePE(data []byte) (*peLayout, error) {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return nil, ErrUnsupported
	}
	e := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if e <= 0 || e+24 > len(data) || string(data[e:e+4]) != "PE\x00\x00" {
		return nil, errors.New("PE 头损坏")
	}
	l := &peLayout{}
	l.machine = binary.LittleEndian.Uint16(data[e+4:])
	nsec := int(binary.LittleEndian.Uint16(data[e+6:]))
	szopt := int(binary.LittleEndian.Uint16(data[e+20:]))
	opt := e + 24
	if opt+2 > len(data) {
		return nil, errors.New("可选头越界")
	}
	magic := binary.LittleEndian.Uint16(data[opt:])
	ddOff := 0
	switch magic {
	case 0x10b:
		l.is64 = false
		l.imageBase = uint64(binary.LittleEndian.Uint32(data[opt+28:]))
		ddOff = opt + 96
	case 0x20b:
		l.is64 = true
		l.imageBase = binary.LittleEndian.Uint64(data[opt+24:])
		ddOff = opt + 112
	default:
		return nil, errors.New("非标准 PE 可选头")
	}
	if opt+16+4 <= len(data) {
		l.entryRVA = binary.LittleEndian.Uint32(data[opt+16:])
	}
	sectab := opt + szopt
	l.sections = make([]peSection, 0, nsec)
	for i := 0; i < nsec; i++ {
		b := sectab + i*40
		if b+40 > len(data) {
			break
		}
		l.sections = append(l.sections, peSection{
			name:    strings.TrimRight(string(data[b:b+8]), "\x00"),
			vsize:   binary.LittleEndian.Uint32(data[b+8:]),
			rva:     binary.LittleEndian.Uint32(data[b+12:]),
			rawSize: binary.LittleEndian.Uint32(data[b+16:]),
			rawOff:  binary.LittleEndian.Uint32(data[b+20:]),
		})
	}
	if ddOff+16*8 <= len(data) {
		l.exportRVA = binary.LittleEndian.Uint32(data[ddOff:])
		l.exportSize = binary.LittleEndian.Uint32(data[ddOff+4:])
		l.corRVA = binary.LittleEndian.Uint32(data[ddOff+14*8:])
		l.dotNet = l.corRVA != 0
	}
	return l, nil
}

func parseExports(data []byte, l *peLayout) []Function {
	off, ok := l.rva2off(l.exportRVA)
	if !ok || off <= 0 || off+40 > len(data) {
		return nil
	}
	nNames := binary.LittleEndian.Uint32(data[off+24:])
	funcsRVA := binary.LittleEndian.Uint32(data[off+28:])
	namesRVA := binary.LittleEndian.Uint32(data[off+32:])
	ordRVA := binary.LittleEndian.Uint32(data[off+36:])
	funcsOff, ok1 := l.rva2off(funcsRVA)
	namesOff, ok2 := l.rva2off(namesRVA)
	ordOff, ok3 := l.rva2off(ordRVA)
	if !ok1 || !ok2 || !ok3 {
		return nil
	}
	var out []Function
	for i := uint32(0); i < nNames && i < 10000; i++ {
		if namesOff+int(i)*4+4 > len(data) || ordOff+int(i)*2+2 > len(data) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(data[namesOff+int(i)*4:])
		ord := binary.LittleEndian.Uint16(data[ordOff+int(i)*2:])
		if funcsOff+int(ord)*4+4 > len(data) {
			continue
		}
		funcRVA := binary.LittleEndian.Uint32(data[funcsOff+int(ord)*4:])
		if funcRVA == 0 {
			continue
		}
		// 转发导出（RVA 落在导出目录内）指向外部 DLL，没有本地代码可保护。
		if funcRVA >= l.exportRVA && funcRVA < l.exportRVA+max32(l.exportSize, 1) {
			continue
		}
		nOff, ok := l.rva2off(nameRVA)
		if !ok || nOff >= len(data) {
			continue
		}
		end := indexByte(data, nOff, 0)
		if end <= nOff {
			continue
		}
		out = append(out, Function{
			Address: l.imageBase + uint64(funcRVA),
			Name:    string(data[nOff:end]),
			Source:  "export",
		})
	}
	return out
}

// ---------- .NET 元数据 ----------

// enumerateDotNet 解析 CLI 元数据 MethodDef 表，返回全部托管 IL 方法。
// 地址语义与服务端/引擎一致：VA = imageBase + RVA。
// 只收录 impl_flags.CodeTypeMask == miIL 的方法（native/abstract/runtime 跳过），
// 与服务端 petype.EnumerateDotNet 的判定完全一致，便于用服务端结果做对拍。
func enumerateDotNet(data []byte, l *peLayout, max int) ([]Function, error) {
	corOff, ok := l.rva2off(l.corRVA)
	if !ok || corOff+16 > len(data) {
		return nil, errors.New("CLR 头不可达")
	}
	mdRVA := binary.LittleEndian.Uint32(data[corOff+8:])
	md, ok := l.rva2off(mdRVA)
	if !ok || md+16 > len(data) || string(data[md:md+4]) != "BSJB" {
		return nil, errors.New("元数据签名不是 BSJB")
	}
	verLen := binary.LittleEndian.Uint32(data[md+12:])
	p := md + 16 + int(verLen) + 2
	if p+2 > len(data) {
		return nil, errors.New("元数据流头越界")
	}
	nStreams := int(binary.LittleEndian.Uint16(data[p:]))
	p += 2
	tilde, strHeap := -1, -1
	for i := 0; i < nStreams; i++ {
		if p+8 > len(data) {
			return nil, errors.New("流表越界")
		}
		off := binary.LittleEndian.Uint32(data[p:])
		p += 8
		end := indexByte(data, p, 0)
		if end < 0 {
			return nil, errors.New("流名未终止")
		}
		name := string(data[p:end])
		p = align4(end + 1)
		switch name {
		case "#~", "#-":
			tilde = md + int(off)
		case "#Strings":
			strHeap = md + int(off)
		}
	}
	if tilde < 0 || strHeap < 0 || tilde+24 > len(data) {
		return nil, errors.New("缺少 #~ 或 #Strings 流")
	}
	heapSizes := data[tilde+6]
	valid := binary.LittleEndian.Uint64(data[tilde+8:])
	strSz, blobSz := 2, 2
	if heapSizes&0x01 != 0 {
		strSz = 4
	}
	if heapSizes&0x04 != 0 {
		blobSz = 4
	}
	q := tilde + 24
	counts := map[uint32]uint32{}
	for t := uint32(0); t < 64; t++ {
		if valid&(uint64(1)<<t) == 0 {
			continue
		}
		if q+4 > len(data) {
			return nil, errors.New("行数表越界")
		}
		counts[t] = binary.LittleEndian.Uint32(data[q:])
		q += 4
	}
	idxSz := func(t uint32) int {
		if counts[t] > 0xFFFF {
			return 4
		}
		return 2
	}
	codedSz := func(tables ...uint32) int {
		for _, t := range tables {
			if counts[t] > 0xFFFF {
				return 4
			}
		}
		return 2
	}
	// ECMA-335 II.22：定位 MethodDef(0x06) 前必须先跨过 0x00..0x05 全部行。
	rowSz := map[uint32]int{
		0x00: 2 + strSz + idxSz(0x26) + idxSz(0x26) + idxSz(0x26),                             // Module
		0x01: codedSz(0x00, 0x1A, 0x23, 0x27) + strSz + strSz,                                 // TypeRef
		0x02: 4 + strSz + strSz + codedSz(0x01, 0x02, 0x1B, 0x20) + idxSz(0x04) + idxSz(0x06), // TypeDef
		0x03: idxSz(0x04),                                                                     // FieldPtr
		0x04: 2 + strSz + blobSz,                                                              // Field
		0x05: idxSz(0x06),                                                                     // MethodPtr
	}
	off := q
	for t := uint32(0); t < 0x06; t++ {
		if _, ok := counts[t]; !ok {
			continue
		}
		w, ok := rowSz[t]
		if !ok {
			return nil, fmt.Errorf("未预期的元数据表布局（表 0x%02x）", t)
		}
		off += w * int(counts[t])
	}
	n := int(counts[0x06])
	mdRow := 4 + 2 + 2 + strSz + blobSz + idxSz(0x06)

	var out []Function
	seen := map[uint64]bool{}
	for i := 0; i < n; i++ {
		b := off + i*mdRow
		if b+4+2+2+strSz > len(data) {
			break
		}
		rva := binary.LittleEndian.Uint32(data[b:])
		implFlags := binary.LittleEndian.Uint16(data[b+4:])
		var nameIdx uint32
		if strSz == 4 {
			nameIdx = binary.LittleEndian.Uint32(data[b+8:])
		} else {
			nameIdx = uint32(binary.LittleEndian.Uint16(data[b+8:]))
		}
		// rva==0 = abstract/pinvoke；implFlags&3 != 0 = native/runtime（非 IL）
		if rva == 0 || implFlags&3 != 0 || len(out) >= max {
			continue
		}
		sOff := strHeap + int(nameIdx)
		if sOff >= len(data) {
			continue
		}
		end := indexByte(data, sOff, 0)
		if end <= sOff {
			continue
		}
		addr := l.imageBase + uint64(rva)
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, Function{Address: addr, Name: string(data[sOff:end]), Source: "method"})
	}
	return out, nil
}

// ---------- ELF ----------

func scanELF(data []byte) (*Info, error) {
	if len(data) < 52 || data[4] != 1 && data[4] != 2 {
		return nil, errors.New("ELF 头不完整")
	}
	is64 := data[4] == 2
	le := data[5] == 1
	bo := binary.ByteOrder(binary.LittleEndian)
	if !le {
		bo = binary.BigEndian
	}
	machine := bo.Uint16(data[18:])
	info := &Info{Format: "elf", Is64: is64, Arch: map[uint16]string{
		3: "x86", 62: "x64", 183: "arm64", 40: "arm", 243: "riscv64", 8: "mips",
	}[machine]}
	if info.Arch == "" {
		info.Arch = "unknown"
	}

	var shoff uint64
	var shentsize, shnum uint16
	if is64 {
		if len(data) < 64 {
			return nil, errors.New("ELF64 头不完整")
		}
		shoff = bo.Uint64(data[40:])
		shentsize = bo.Uint16(data[58:])
		shnum = bo.Uint16(data[60:])
	} else {
		shoff = uint64(bo.Uint32(data[32:]))
		shentsize = bo.Uint16(data[46:])
		shnum = bo.Uint16(data[48:])
	}
	if shoff == 0 || shentsize < 40 || int(shoff)+int(shnum)*int(shentsize) > len(data) {
		info.SymbolQuality = "none"
		info.Notes = append(info.Notes, "ELF 无节头表（已 strip 或压缩）：本地无法枚举函数")
		return info, nil
	}
	type shdr struct {
		name, typ     uint32
		offset, size  uint64
		link, entsize uint64
	}
	secs := make([]shdr, 0, shnum)
	for i := 0; i < int(shnum); i++ {
		b := int(shoff) + i*int(shentsize)
		var s shdr
		s.name = bo.Uint32(data[b:])
		s.typ = bo.Uint32(data[b+4:])
		if is64 {
			s.offset = bo.Uint64(data[b+24:])
			s.size = bo.Uint64(data[b+32:])
			s.link = uint64(bo.Uint32(data[b+40:]))
			s.entsize = bo.Uint64(data[b+56:])
		} else {
			s.offset = uint64(bo.Uint32(data[b+16:]))
			s.size = uint64(bo.Uint32(data[b+20:]))
			s.link = uint64(bo.Uint32(data[b+24:]))
			s.entsize = uint64(bo.Uint32(data[b+36:]))
		}
		secs = append(secs, s)
	}
	seen := map[uint64]bool{}
	var out []Function
	// SHT_SYMTAB=2（含本地符号）优先，SHT_DYNSYM=11（动态导出）次之。
	for _, want := range []uint32{2, 11} {
		for _, s := range secs {
			if s.typ != want || s.entsize == 0 || s.link >= uint64(len(secs)) {
				continue
			}
			strSec := secs[s.link]
			n := int(s.size / s.entsize)
			for i := 0; i < n; i++ {
				b := int(s.offset) + i*int(s.entsize)
				if b+int(s.entsize) > len(data) {
					break
				}
				var nameOff uint32
				var value uint64
				var shndx uint16
				var stInfo byte
				if is64 {
					nameOff = bo.Uint32(data[b:])
					stInfo = data[b+4]
					shndx = bo.Uint16(data[b+6:])
					value = bo.Uint64(data[b+8:])
				} else {
					nameOff = bo.Uint32(data[b:])
					value = uint64(bo.Uint32(data[b+4:]))
					stInfo = data[b+12]
					shndx = bo.Uint16(data[b+14:])
				}
				// STT_FUNC == 2；SHN_UNDEF == 0（外部符号没有本地代码）
				if stInfo&0xf != 2 || value == 0 || shndx == 0 || seen[value] {
					continue
				}
				so := int(strSec.offset) + int(nameOff)
				if so >= len(data) {
					continue
				}
				end := indexByte(data, so, 0)
				if end <= so {
					continue
				}
				seen[value] = true
				out = append(out, Function{Address: value, Name: string(data[so:end]), Source: "symbol"})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	info.Functions = out
	if len(out) > 0 {
		info.SymbolQuality = "symbols"
		info.Notes = append(info.Notes, fmt.Sprintf("ELF 符号表可读：%d 个 FUNC 符号（地址为文件内虚拟地址，上传后以服务端为准）", len(out)))
	} else {
		info.SymbolQuality = "none"
		info.Notes = append(info.Notes, "ELF 符号表为空（可能已 strip）：需上传后看服务端枚举结果")
	}
	return info, nil
}

// ---------- Mach-O ----------

func isMachMagic(m uint32) bool {
	switch m {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca:
		return true
	}
	return false
}

func scanMachO(data []byte) (*Info, error) {
	if len(data) < 28 {
		return nil, errors.New("Mach-O 头不完整")
	}
	le := binary.LittleEndian
	be := binary.BigEndian
	magicBE := be.Uint32(data[0:])
	var bo binary.ByteOrder
	var is64 bool
	switch magicBE {
	case 0xfeedface, 0xfeedfacf:
		bo = be
		is64 = magicBE == 0xfeedfacf
	case 0xcefaedfe, 0xcffaedfe:
		bo = le
		is64 = magicBE == 0xcffaedfe
	case 0xcafebabe, 0xbebafeca:
		return &Info{Format: "mach", Arch: "fat", SymbolQuality: "none",
			Notes: []string{"Mach-O 通用二进制（fat）：本地只识别容器，请对具体架构切片加壳"}}, nil
	default:
		return nil, ErrUnsupported
	}
	cputype := bo.Uint32(data[4:])
	arch := "unknown"
	if is64 {
		switch cputype {
		case 0x01000007:
			arch = "x64"
		case 0x0100000c:
			arch = "arm64"
		}
	} else {
		switch cputype {
		case 7:
			arch = "x86"
		case 12:
			arch = "arm"
		}
	}
	ncmds := bo.Uint32(data[16:])
	sizeofcmds := bo.Uint32(data[20:])
	hdr := 28
	if is64 {
		hdr = 32
	}
	info := &Info{Format: "mach", Is64: is64, Arch: arch}
	if len(data) < hdr+int(sizeofcmds) {
		info.SymbolQuality = "none"
		info.Notes = append(info.Notes, "Mach-O 加载命令区被截断")
		return info, nil
	}
	var symoff, nsyms, stroff uint32
	p := hdr
	for i := uint32(0); i < ncmds && p+8 <= len(data); i++ {
		cmd := bo.Uint32(data[p:])
		size := bo.Uint32(data[p+4:])
		if size < 8 || p+int(size) > len(data) {
			break
		}
		if cmd == 0x2 { // LC_SYMTAB
			symoff = bo.Uint32(data[p+8:])
			nsyms = bo.Uint32(data[p+12:])
			stroff = bo.Uint32(data[p+16:])
		}
		p += int(size)
	}
	if symoff == 0 || nsyms == 0 || int(symoff) >= len(data) {
		info.SymbolQuality = "none"
		info.Notes = append(info.Notes, "无 LC_SYMTAB 或符号表为空（已 strip）")
		return info, nil
	}
	entsz := 12
	if is64 {
		entsz = 16
	}
	seen := map[uint64]bool{}
	var out []Function
	for i := uint32(0); i < nsyms; i++ {
		b := int(symoff) + int(i)*entsz
		if b+entsz > len(data) {
			break
		}
		nameOff := bo.Uint32(data[b:])
		var nType byte
		var nSect byte
		var nDesc uint16
		var value uint64
		if is64 {
			nType = data[b+4]
			nSect = data[b+5]
			nDesc = bo.Uint16(data[b+6:])
			value = bo.Uint64(data[b+8:])
		} else {
			nType = data[b+4]
			nSect = data[b+5]
			nDesc = bo.Uint16(data[b+6:])
			value = uint64(bo.Uint32(data[b+8:]))
		}
		// N_STAB=0xe0 调试符号；N_TYPE&0x0e：0x0e = N_SECT 且有节号 → 函数代码
		if nType&0xe0 != 0 || nType&0x0e != 0x0e || nSect == 0 || value == 0 {
			continue
		}
		if nDesc&0x0001 != 0 { // N_ARM_THUMB_DEF 等标记不影响，保留
		}
		so := int(stroff) + int(nameOff)
		if so >= len(data) {
			continue
		}
		end := indexByte(data, so, 0)
		if end <= so {
			continue
		}
		name := string(data[so:end])
		// 只保留看起来像函数的名字（避免把全局数据算进来：以 _ 开头的符号太多了，
		// 这里按"非 . 开头的本地符号"过滤，并在说明里写明这是启发式）。
		if strings.HasPrefix(name, "ltmp") || strings.HasPrefix(name, "l_") {
			continue
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, Function{Address: value, Name: name, Source: "symbol"})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	info.Functions = out
	if len(out) > 0 {
		info.SymbolQuality = "symbols"
		info.Notes = append(info.Notes, fmt.Sprintf("Mach-O 符号表可读：%d 个 N_SECT 符号（启发式，含少量非函数符号）", len(out)))
	} else {
		info.SymbolQuality = "none"
		info.Notes = append(info.Notes, "Mach-O 符号表无可用的 N_SECT 代码符号")
	}
	return info, nil
}

// ---------- 小工具 ----------

func max32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func align4(n int) int { return (n + 3) &^ 3 }

func indexByte(data []byte, from int, b byte) int {
	for i := from; i < len(data); i++ {
		if data[i] == b {
			return i
		}
	}
	return -1
}
