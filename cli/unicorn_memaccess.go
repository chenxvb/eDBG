package cli

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/arch/arm64/arm64asm"
)

// Memory access instruction categories (matching Unicorn-Trace).
var readOps = map[arm64asm.Op]bool{
	arm64asm.LDR: true, arm64asm.LDRB: true, arm64asm.LDRH: true,
	arm64asm.LDP: true, arm64asm.LDUR: true,
	arm64asm.LDARB: true, arm64asm.LDARH: true, arm64asm.LDAR: true,
	arm64asm.LDXR: true, arm64asm.LDXRB: true, arm64asm.LDXRH: true,
	arm64asm.LDAXR: true, arm64asm.LDAXRB: true, arm64asm.LDAXRH: true,
	arm64asm.LDRSB: true, arm64asm.LDRSH: true, arm64asm.LDRSW: true,
	arm64asm.LDURB: true, arm64asm.LDURH: true, arm64asm.LDURSB: true,
	arm64asm.LDURSH: true, arm64asm.LDURSW: true,
	arm64asm.LDNP: true, arm64asm.LDPSW: true,
}

var writeOps = map[arm64asm.Op]bool{
	arm64asm.STR: true, arm64asm.STRB: true, arm64asm.STRH: true,
	arm64asm.STP: true, arm64asm.STUR: true,
	arm64asm.STLR: true, arm64asm.STLRB: true, arm64asm.STLRH: true,
	arm64asm.STXR: true, arm64asm.STXRB: true, arm64asm.STXRH: true,
	arm64asm.STLXR: true, arm64asm.STLXRB: true, arm64asm.STLXRH: true,
	arm64asm.STURB: true, arm64asm.STURH: true,
	arm64asm.STNP: true,
}

// regReader reads a register value from the Unicorn engine.
type regReader func(regName string) uint64

// getMemImmediateImm extracts the unexported imm field from MemImmediate.
// MemImmediate layout: Base(RegSP=uint16), Mode(AddrMode=uint8), padding, imm(int32)
func getMemImmediateImm(m arm64asm.MemImmediate) int64 {
	type memImm struct {
		Base uint16
		Mode uint8
		_    uint8
		Imm  int32
	}
	p := (*memImm)(unsafe.Pointer(&m))
	return int64(p.Imm)
}

// getAccessSize returns the memory access size in bytes for a load/store instruction.
func getAccessSize(inst arm64asm.Inst) int {
	op := inst.Op
	opStr := strings.ToLower(op.String())

	if strings.HasSuffix(opStr, "b") || strings.Contains(opStr, "rb") || strings.Contains(opStr, "sb") {
		return 1
	}
	if strings.HasSuffix(opStr, "h") || strings.Contains(opStr, "rh") || strings.Contains(opStr, "sh") {
		return 2
	}

	// For pair instructions (LDP/STP), size depends on the register width
	isPair := op == arm64asm.LDP || op == arm64asm.STP ||
		op == arm64asm.LDNP || op == arm64asm.STNP || op == arm64asm.LDPSW

	if isPair {
		if isWReg(inst.Args[0]) {
			return 8 // 2x4 bytes
		}
		return 16 // 2x8 bytes
	}

	// LDRSW always loads 4 bytes
	if op == arm64asm.LDRSW || op == arm64asm.LDURSW {
		return 4
	}

	// For single-register ops, check register width
	if len(inst.Args) > 0 && isWReg(inst.Args[0]) {
		return 4
	}
	return 8
}

func isWReg(arg arm64asm.Arg) bool {
	if arg == nil {
		return false
	}
	s := arg.String()
	return len(s) > 0 && (s[0] == 'W' || s[0] == 'w')
}

// regSPString converts an arm64asm.RegSP to the lowercase register name used in UcRegMap.
func regSPString(r arm64asm.RegSP) string {
	s := strings.ToLower(arm64asm.Reg(r).String())
	if s == "xzr" || s == "wzr" {
		return "sp"
	}
	return s
}

// regString converts an arm64asm.Reg to the lowercase register name used in UcRegMap.
func regString(r arm64asm.Reg) string {
	s := strings.ToLower(r.String())
	if s == "xzr" || s == "wzr" {
		return s
	}
	return s
}

// resolveMemAddr finds the MemImmediate / MemExtend argument and computes effective address.
func resolveMemAddr(inst arm64asm.Inst, readReg regReader) (uint64, bool) {
	for _, arg := range inst.Args {
		if arg == nil {
			continue
		}
		switch m := arg.(type) {
		case arm64asm.MemImmediate:
			base := readReg(regSPString(m.Base))
			imm := getMemImmediateImm(m)
			addr := base + uint64(imm)
			return addr, true
		case arm64asm.MemExtend:
			base := readReg(regSPString(m.Base))
			index := readReg(regString(m.Index))
			shift := uint64(m.Amount)
			if m.ShiftMustBeZero {
				shift = 0
			}
			addr := base + (index << shift)
			return addr, true
		}
	}
	return 0, false
}

// analyzeMemoryAccessUc analyzes an ARM64 instruction and returns memory access log entries.
// Format: "mr=0xADDR:HEXDATA" for reads, "mw=0xADDR:HEXDATA" for writes.
func analyzeMemoryAccessUc(inst arm64asm.Inst, readReg regReader, memReader func(uint64, int) ([]byte, error)) []string {
	var accesses []string
	op := inst.Op
	isRead := readOps[op]
	isWrite := writeOps[op]

	if !isRead && !isWrite {
		return nil
	}

	addr, ok := resolveMemAddr(inst, readReg)
	if !ok {
		return nil
	}

	size := getAccessSize(inst)

	if isRead {
		data, err := memReader(addr, size)
		if err != nil {
			return nil
		}
		accesses = append(accesses, fmt.Sprintf("mr=0x%x:%s", addr, hex.EncodeToString(data)))
	}

	if isWrite {
		data := resolveWriteData(inst, readReg, size)
		if data != nil {
			accesses = append(accesses, fmt.Sprintf("mw=0x%x:%s", addr, hex.EncodeToString(data)))
		}
	}

	return accesses
}

// resolveWriteData extracts the data about to be written by a store instruction.
func resolveWriteData(inst arm64asm.Inst, readReg regReader, size int) []byte {
	if len(inst.Args) < 1 {
		return nil
	}

	isPair := inst.Op == arm64asm.STP || inst.Op == arm64asm.STNP

	if isPair && len(inst.Args) >= 2 {
		val1 := readRegArg(inst.Args[0], readReg)
		val2 := readRegArg(inst.Args[1], readReg)
		halfSize := size / 2
		buf := make([]byte, size)
		putLE(buf[:halfSize], val1, halfSize)
		putLE(buf[halfSize:], val2, halfSize)
		return buf
	}

	val := readRegArg(inst.Args[0], readReg)
	buf := make([]byte, size)
	putLE(buf, val, size)
	return buf
}

func readRegArg(arg arm64asm.Arg, readReg regReader) uint64 {
	if arg == nil {
		return 0
	}
	s := strings.ToLower(arg.String())
	if s == "xzr" || s == "wzr" {
		return 0
	}
	return readReg(s)
}

func putLE(buf []byte, val uint64, size int) {
	for i := 0; i < size && i < 8; i++ {
		buf[i] = byte(val >> (8 * i))
	}
}

// formatUserLogLine formats one uc.log line (matches Unicorn-Trace print_user_log).
func formatUserLogLine(addr uint64, inst arm64asm.Inst, readReg regReader) string {
	mnemonic := inst.Op.String()
	var opParts []string
	for _, arg := range inst.Args {
		if arg == nil {
			break
		}
		switch a := arg.(type) {
		case arm64asm.PCRel:
			opParts = append(opParts, fmt.Sprintf("0x%x", addr+uint64(int64(a))))
		default:
			opParts = append(opParts, arg.String())
		}
	}
	opStr := strings.Join(opParts, ", ")

	// Resolve operand values
	var valParts []string
	for _, arg := range inst.Args {
		if arg == nil {
			break
		}
		switch a := arg.(type) {
		case arm64asm.Reg:
			s := strings.ToLower(a.String())
			if s == "xzr" || s == "wzr" {
				valParts = append(valParts, "0x0")
			} else {
				valParts = append(valParts, fmt.Sprintf("0x%x", readReg(s)))
			}
		case arm64asm.RegSP:
			s := regSPString(a)
			valParts = append(valParts, fmt.Sprintf("0x%x", readReg(s)))
		case arm64asm.Imm:
			valParts = append(valParts, fmt.Sprintf("0x%x", a.Imm))
		case arm64asm.Imm64:
			valParts = append(valParts, fmt.Sprintf("0x%x", a.Imm))
		case arm64asm.MemImmediate:
			base := readReg(regSPString(a.Base))
			valParts = append(valParts, fmt.Sprintf("0x%x", base))
			imm := getMemImmediateImm(a)
			if imm != 0 {
				valParts = append(valParts, fmt.Sprintf("0x%x", imm))
			}
		case arm64asm.MemExtend:
			base := readReg(regSPString(a.Base))
			index := readReg(regString(a.Index))
			valParts = append(valParts, fmt.Sprintf("0x%x", base))
			valParts = append(valParts, fmt.Sprintf("0x%x", index))
		case arm64asm.PCRel:
			valParts = append(valParts, fmt.Sprintf("0x%x", addr+uint64(int64(a))))
		default:
			valParts = append(valParts, arg.String())
		}
	}
	content := strings.Join(valParts, " ")

	return fmt.Sprintf("0x%x    : %-8s %-24s %s", addr, mnemonic, opStr, content)
}
