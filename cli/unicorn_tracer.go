package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

const (
	TraceResultSuccess  = 114514
	TraceResultRestart  = 1
	TraceResultReDump   = 2
	TraceResultError    = 0
	TraceResultSameAddr = 5
	TraceResultMRSTpidr = 3
)

// UnicornTracer wraps the Unicorn engine for ARM64 trace emulation.
// Mirrors IDAArm64Emulator from dyn_trace_ida.py.
type UnicornTracer struct {
	uc           *UcEngine
	lastRegs     map[string]uint64
	traceLog     *os.File
	userLog      *os.File
	runRange     [2]uint64
	mapRange     [][2]uint64
	loadedFiles  map[string]bool
	heapBase     uint64
	heapSize     uint64
	heapPtr      uint64
	lastRegDump  string
	hookAdded    bool

	// HaltReason is set by the code hook when it needs to stop emulation.
	haltReason string

	// TPIDR support
	tpidrValue       uint64
	tpidrDetected    bool
	tpidrMRSDestReg  int // destination register index for MRS tpidr_el0
}

func NewUnicornTracer() (*UnicornTracer, error) {
	uc, err := NewUcEngine()
	if err != nil {
		return nil, fmt.Errorf("failed to create unicorn engine: %v", err)
	}
	return &UnicornTracer{
		uc:          uc,
		lastRegs:    make(map[string]uint64),
		loadedFiles: make(map[string]bool),
		heapBase:    0x1000000,
		heapSize:    0x90000,
		heapPtr:     0x1000000,
	}, nil
}

func (t *UnicornTracer) Close() {
	if t.userLog != nil {
		t.userLog.Close()
		t.userLog = nil
	}
	if t.traceLog != nil {
		t.traceLog.Close()
		t.traceLog = nil
	}
	if t.uc != nil {
		t.uc.Close()
		t.uc = nil
	}
}

func (t *UnicornTracer) readReg(name string) uint64 {
	regID, ok := UcRegMap[name]
	if !ok {
		return 0
	}
	val, err := t.uc.RegRead(regID)
	if err != nil {
		return 0
	}
	return val
}

func (t *UnicornTracer) writeReg(name string, val uint64) {
	regID, ok := UcRegMap[name]
	if !ok {
		return
	}
	t.uc.RegWrite(regID, val)
}

// LoadRegisters loads register state from a JSON file (regs.json).
func (t *UnicornTracer) LoadRegisters(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var regs map[string]interface{}
	if err := json.Unmarshal(data, &regs); err != nil {
		return err
	}
	for name, val := range regs {
		regID, ok := UcRegMap[name]
		if !ok {
			continue
		}
		var intVal uint64
		switch v := val.(type) {
		case string:
			fmt.Sscanf(v, "0x%x", &intVal)
			if intVal == 0 {
				fmt.Sscanf(v, "%d", &intVal)
			}
		case float64:
			intVal = uint64(v)
		default:
			continue
		}
		fmt.Printf("Setting %s to 0x%x\n", name, intVal)
		t.uc.RegWrite(regID, intVal)
		if name == "tpidr" && intVal != 0 {
			t.tpidrValue = intVal
			t.tpidrDetected = true
		}
	}
	return nil
}

// LoadMemoryMappings loads dump files into Unicorn memory.
// File naming: *0xBASE_0xEND_0xSIZE.bin
func (t *UnicornTracer) LoadMemoryMappings(dumpPath string) error {
	entries, err := os.ReadDir(dumpPath)
	if err != nil {
		return err
	}

	pattern := regexp.MustCompile(`0x([0-9a-fA-F]+)_0x([0-9a-fA-F]+)_0x([0-9a-fA-F]+)\.bin$`)

	type mapEntry struct {
		base, end, size uint64
		filename        string
	}
	var mapList []mapEntry

	for _, entry := range entries {
		name := entry.Name()
		match := pattern.FindStringSubmatch(name)
		if match == nil {
			continue
		}
		var base, end, size uint64
		fmt.Sscanf(match[1], "%x", &base)
		fmt.Sscanf(match[2], "%x", &end)
		fmt.Sscanf(match[3], "%x", &size)
		mapList = append(mapList, mapEntry{base, end, size, name})
	}

	sort.Slice(mapList, func(i, j int) bool { return mapList[i].base < mapList[j].base })

	// Merge existing map ranges
	sort.Slice(t.mapRange, func(i, j int) bool { return t.mapRange[i][0] < t.mapRange[j][0] })
	var merged [][2]uint64
	for _, r := range t.mapRange {
		if len(merged) > 0 && merged[len(merged)-1][1] == r[0] {
			merged[len(merged)-1][1] = r[1]
		} else {
			merged = append(merged, r)
		}
	}
	t.mapRange = merged

	// Map memory regions (avoid overlap with existing mappings)
	for _, m := range mapList {
		if t.loadedFiles[m.filename] {
			continue
		}

		memBase := m.base
		memEnd := m.end

		// Adjust for existing mappings
		upperBound := memBase
		lowerBound := memEnd
		for _, r := range t.mapRange {
			if upperBound >= r[0] && upperBound <= r[1] && upperBound < r[1] {
				upperBound = r[1]
			}
			if lowerBound >= r[0] && lowerBound <= r[1] && lowerBound > r[0] {
				lowerBound = r[0]
			}
		}

		if memBase < upperBound {
			memBase = upperBound
		}
		if memBase&0xfff != 0 {
			memBase = memBase & 0xfffffffffffff000
		}
		if memEnd > lowerBound {
			memEnd = lowerBound
		}

		memSize := memEnd - memBase
		if memSize <= 0 {
			fmt.Printf("continue: map file %s 0x%x 0x%x 0x%x, bound (0x%x - 0x%x)\n",
				m.filename, memBase, memEnd, memSize, upperBound, lowerBound)
			continue
		}
		if memSize&0xfff != 0 {
			memSize = (memSize & 0xfffffffffffff000) + 0x1000
		}
		memEnd = memBase + memSize

		fmt.Printf("map file %s 0x%x 0x%x 0x%x, bound (0x%x - 0x%x)\n",
			m.filename, memBase, memEnd, memSize, upperBound, lowerBound)

		if err := t.uc.MemMap(memBase, memSize); err != nil {
			fmt.Printf("[!] mem_map failed for 0x%x size 0x%x: %v\n", memBase, memSize, err)
			continue
		}
		t.mapRange = append(t.mapRange, [2]uint64{memBase, memEnd})
	}

	// Write memory data
	for _, m := range mapList {
		if t.loadedFiles[m.filename] {
			continue
		}
		filePath := filepath.Join(dumpPath, m.filename)
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("[!] Failed to read %s: %v\n", m.filename, err)
			continue
		}
		fmt.Printf("write file %s 0x%x 0x%x 0x%x\n", m.filename, m.base, m.end, m.size)
		if err := t.uc.MemWrite(m.base, data); err != nil {
			fmt.Printf("[!] mem_write failed for %s: %v\n", m.filename, err)
		}
		t.loadedFiles[m.filename] = true
	}

	return nil
}

// initLogFiles opens tenet and uc log files.
func (t *UnicornTracer) initLogFiles(tenetPath, ucPath string) {
	if tenetPath != "" {
		f, err := os.OpenFile(tenetPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			t.traceLog = f
		}
	}
	if ucPath != "" {
		f, err := os.OpenFile(ucPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			t.userLog = f
		}
	}
}

// initTraceLog writes the initial register state to the tenet log.
func (t *UnicornTracer) initTraceLog(dumpDir string) {
	if t.traceLog == nil {
		return
	}
	if dumpDir != "" {
		absPath, _ := filepath.Abs(dumpDir)
		fmt.Fprintf(t.traceLog, "# DUMP_DIR: %s\n", absPath)
	}

	var parts []string
	for _, reg := range TrackedRegs {
		val := t.readReg(reg)
		parts = append(parts, fmt.Sprintf("%s=0x%x", strings.ToUpper(reg), val))
		t.lastRegs[reg] = val
	}
	fmt.Fprintf(t.traceLog, "%s\n", strings.Join(parts, ","))
}

// writeFinalRegisters writes the final register state.
func (t *UnicornTracer) writeFinalRegisters() {
	if t.traceLog == nil {
		return
	}
	var parts []string
	for _, reg := range TrackedRegs {
		val := t.readReg(reg)
		parts = append(parts, fmt.Sprintf("%s=0x%x", strings.ToUpper(reg), val))
	}
	fmt.Fprintf(t.traceLog, "%s\n", strings.Join(parts, ","))
}

// logChangedRegisters returns a comma-separated string of changed registers.
func (t *UnicornTracer) logChangedRegisters() string {
	var changed []string
	for _, reg := range TrackedRegs {
		val := t.readReg(reg)
		if prev, ok := t.lastRegs[reg]; !ok || prev != val {
			changed = append(changed, fmt.Sprintf("%s=0x%x", strings.ToUpper(reg), val))
		}
		t.lastRegs[reg] = val
	}
	if len(changed) == 0 {
		return ""
	}
	return strings.Join(changed, ",")
}

// fixRegisterValues strips MTE tags from pointer registers (matching Unicorn-Trace).
func (t *UnicornTracer) fixRegisterValues() {
	for i := 0; i < 31; i++ {
		name := fmt.Sprintf("x%d", i)
		val := t.readReg(name)
		if val&0xb4ff000000000000 == 0xb400000000000000 {
			t.writeReg(name, val&0xffffffffffffff)
		}
	}
}

// tenetTraceLog logs one instruction to the tenet trace log.
func (t *UnicornTracer) tenetTraceLog(address uint64) {
	code, err := t.uc.MemRead(address, 4)
	if err != nil {
		return
	}
	inst, err := arm64asm.Decode(code)
	if err != nil {
		return
	}

	memAccesses := analyzeMemoryAccessUc(inst, t.readReg, func(addr uint64, size int) ([]byte, error) {
		return t.uc.MemRead(addr, size)
	})

	regLine := t.logChangedRegisters()

	var line strings.Builder
	if regLine != "" {
		line.WriteString(regLine)
	}
	if len(memAccesses) > 0 {
		if line.Len() > 0 {
			line.WriteString(",")
		}
		line.WriteString(strings.Join(memAccesses, ","))
	}
	if !strings.Contains(line.String(), "PC=") {
		if line.Len() > 0 {
			line.WriteString(",")
		}
		fmt.Fprintf(&line, "PC=0x%x", address)
	}

	if t.traceLog != nil {
		fmt.Fprintf(t.traceLog, "%s\n", line.String())
	}
}

// printUserLog logs one instruction to the uc.log.
func (t *UnicornTracer) printUserLog(address uint64) {
	if t.userLog == nil {
		return
	}
	code, err := t.uc.MemRead(address, 4)
	if err != nil {
		fmt.Fprintf(t.userLog, "0x%x    : <Read Error>\n", address)
		return
	}
	inst, err := arm64asm.Decode(code)
	if err != nil {
		fmt.Fprintf(t.userLog, "0x%x    : <Unknown Coding>\n", address)
		return
	}
	line := formatUserLogLine(address, inst, t.readReg)
	fmt.Fprintf(t.userLog, "%s\n", line)
}

// debugHookCode is the per-instruction callback during emulation.
func (t *UnicornTracer) debugHookCode(addr uint64, size uint32) {
	// Range check
	if addr <= t.runRange[0] || addr >= t.runRange[1] {
		t.haltReason = fmt.Sprintf("Code Run out of range (0x%x, 0x%x)", t.runRange[0], t.runRange[1])
		t.uc.EmuStop()
		return
	}

	// Check for special instructions (AUTIASP, SVC, MRS TPIDR)
	code, err := t.uc.MemRead(addr, 4)
	if err == nil {
		if code[0] == 0xBF && code[1] == 0x23 && code[2] == 0x03 && code[3] == 0xD5 {
			t.haltReason = "Except AUTIASP"
			t.uc.EmuStop()
			return
		}
		if code[0] == 0x01 && code[1] == 0x00 && code[2] == 0x00 && code[3] == 0xD4 {
			t.haltReason = "Except SVC"
			t.uc.EmuStop()
			return
		}
		// MRS Xn, TPIDR_EL0: [0x40|Rn, 0xD0, 0x3B, 0xD5]
		if code[1] == 0xD0 && code[2] == 0x3B && code[3] == 0xD5 && (code[0]&0xE0) == 0x40 {
			destReg := int(code[0] & 0x1F)
			if !t.tpidrDetected && t.tpidrValue == 0 {
				t.tpidrMRSDestReg = destReg
				t.haltReason = fmt.Sprintf("MRS_TPIDR x%d", destReg)
				t.uc.EmuStop()
				return
			}
			// Already have TPIDR — TPIDR_EL0 is set in Unicorn,
			// let the MRS execute normally so it gets logged.
		}
	}

	// Fix MTE-tagged pointers
	t.fixRegisterValues()

	// Log tenet trace
	if t.traceLog != nil {
		t.tenetTraceLog(addr)
	}

	// Log user log
	t.printUserLog(addr)
}

// dumpAllRegisters returns a string summary of all registers (for comparison).
func (t *UnicornTracer) dumpAllRegisters() string {
	var parts []string
	for _, reg := range TrackedRegs {
		val := t.readReg(reg)
		parts = append(parts, fmt.Sprintf("%s=0x%x", reg, val))
	}
	return strings.Join(parts, ",")
}

// printRegisters prints the current register state.
func (t *UnicornTracer) printRegisters() {
	pc := t.readReg("pc")
	sp := t.readReg("sp")
	fmt.Printf("PC : 0x%x\n", pc)
	fmt.Printf("SP : 0x%x\n", sp)
	for i := 0; i < 31; i += 4 {
		for j := i; j < i+4 && j < 31; j++ {
			name := fmt.Sprintf("x%d", j)
			val := t.readReg(name)
			fmt.Printf("%-3s: 0x%-16x ", name, val)
		}
		fmt.Println()
	}
}

// MainTrace runs one round of emulation. Returns a status code.
// Mirrors IDAArm64Emulator.main_trace() from dyn_trace_ida.py.
func (t *UnicornTracer) MainTrace(endAddr uint64, tenetPath, ucPath, dumpPath string) int {
	// Init log files
	t.initLogFiles(tenetPath, ucPath)

	firstRun := len(t.loadedFiles) == 0
	if firstRun {
		// Load registers
		regsPath := filepath.Join(dumpPath, "regs.json")
		if err := t.LoadRegisters(regsPath); err != nil {
			fmt.Printf("[!] Failed to load registers: %v\n", err)
			return TraceResultError
		}
		fmt.Println("Registers loaded.")
		t.lastRegs = make(map[string]uint64)

		// Init trace log
		if t.traceLog != nil {
			t.initTraceLog(dumpPath)
		}

		// Add code hook
		if !t.hookAdded {
			err := t.uc.HookAddCode(t.debugHookCode, 0, 0xFFFFFFFFFFFFFFFF)
			if err != nil {
				fmt.Printf("[!] Failed to add code hook: %v\n", err)
				return TraceResultError
			}
			t.hookAdded = true
		}
	}

	// Load memory
	if err := t.LoadMemoryMappings(dumpPath); err != nil {
		fmt.Printf("[!] Failed to load memory: %v\n", err)
		return TraceResultError
	}

	startAddr := t.readReg("pc")
	if startAddr == endAddr {
		return TraceResultSameAddr
	}

	// Clear halt reason
	t.haltReason = ""

	// Run emulation
	fmt.Printf("[+] Emulating from 0x%x to 0x%x\n", startAddr, endAddr)
	err := t.uc.EmuStart(startAddr, endAddr)

	// Close log files for this round
	if t.userLog != nil {
		t.userLog.Close()
		t.userLog = nil
	}
	if t.traceLog != nil {
		t.traceLog.Close()
		t.traceLog = nil
	}

	if err != nil {
		return t.handleUcError(err)
	}

	// EmuStop() called from hook returns nil error — check haltReason
	if t.haltReason != "" {
		return t.handleHaltReason()
	}

	fmt.Println("Trace END!")
	return TraceResultSuccess
}

func (t *UnicornTracer) handleHaltReason() int {
	fmt.Printf("[+] Halted: %s\n", t.haltReason)
	if strings.Contains(t.haltReason, "Code Run out of range") {
		return TraceResultRestart
	}
	if strings.Contains(t.haltReason, "Except AUTIASP") || strings.Contains(t.haltReason, "Except SVC") {
		return TraceResultRestart
	}
	if strings.Contains(t.haltReason, "MRS_TPIDR") {
		return TraceResultMRSTpidr
	}
	return TraceResultError
}

func (t *UnicornTracer) handleUcError(err error) int {
	fmt.Printf("ERROR: %v\n", err)
	t.printRegisters()

	errStr := err.Error()

	// Check our custom halt reasons
	if t.haltReason != "" {
		if strings.Contains(t.haltReason, "Code Run out of range") {
			return TraceResultRestart
		}
		if strings.Contains(t.haltReason, "Except AUTIASP") || strings.Contains(t.haltReason, "Except SVC") {
			return TraceResultRestart
		}
		if strings.Contains(t.haltReason, "MRS_TPIDR") {
			return TraceResultMRSTpidr
		}
	}

	if strings.Contains(errStr, "UC_ERR_EXCEPTION") {
		return TraceResultRestart
	}

	currentDump := t.dumpAllRegisters()
	if t.lastRegDump == currentDump {
		fmt.Println("[!] Stop at the same location. Jump out. Maybe Check MRS opcode and TPIDR regs")
		return TraceResultError
	}

	pc := t.readReg("pc")

	// FETCH_UNMAPPED with PC outside bound range = out-of-range call (BLR/BR to external)
	if strings.Contains(errStr, "UC_ERR_FETCH_UNMAPPED") {
		if pc < t.runRange[0] || pc >= t.runRange[1] {
			t.haltReason = fmt.Sprintf("BLR/BR to out-of-range 0x%x", pc)
			return TraceResultRestart
		}
		t.lastRegDump = currentDump
		return TraceResultReDump
	}

	if strings.Contains(errStr, "UC_ERR_READ_UNMAPPED") ||
		strings.Contains(errStr, "UC_ERR_WRITE_UNMAPPED") {
		t.lastRegDump = currentDump
		return TraceResultReDump
	}

	return TraceResultError
}

// GetPC returns the current PC register value.
func (t *UnicornTracer) GetPC() uint64 {
	return t.readReg("pc")
}

// GetLR returns the current LR register value.
func (t *UnicornTracer) GetLR() uint64 {
	return t.readReg("x30")
}
