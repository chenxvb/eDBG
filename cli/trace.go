package cli

import (
	"eDBG/utils"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/arch/arm64/arm64asm"
)

const (
	DumpSingleSegSize = 0x4000
	RoundMax          = 1000
)

func (this *Client) HandleTrace(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: trace <end_addr> [output_path] [--tenet]")
		fmt.Println("       trace <end_addr> [output_path] [--tenet] [--bound <start> <end>]")
		fmt.Println("  end_addr: absolute address to trace to")
		fmt.Println("  --tenet : enable tenet trace log output")
		fmt.Println("  --bound : set custom execution bound range")
		return
	}

	endAddr, err := this.ParseUserAddressToAbsolute(args[0])
	if err != nil {
		fmt.Printf("Failed to parse end address: %v\n", err)
		return
	}

	outputPath := "."
	enableTenet := false
	var boundStart, boundEnd uint64
	hasBound := false

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--tenet":
			enableTenet = true
		case "--bound":
			if i+2 >= len(args) {
				fmt.Println("--bound requires <start> <end>")
				return
			}
			boundStart, err = strconv.ParseUint(args[i+1], 0, 64)
			if err != nil {
				fmt.Printf("Bad bound start: %v\n", err)
				return
			}
			boundEnd, err = strconv.ParseUint(args[i+2], 0, 64)
			if err != nil {
				fmt.Printf("Bad bound end: %v\n", err)
				return
			}
			hasBound = true
			i += 2
		default:
			if !strings.HasPrefix(args[i], "-") {
				outputPath = args[i]
			}
		}
	}

	if !hasBound {
		boundStart, boundEnd = this.collectAutoRange()
		if boundStart >= boundEnd {
			fmt.Println("[!] Cannot determine execution bound range. Use --bound <start> <end>")
			return
		}
	}

	fmt.Printf("[+] Trace target: 0x%x\n", endAddr)
	fmt.Printf("[+] Bound range : 0x%x - 0x%x\n", boundStart, boundEnd)
	fmt.Printf("[+] Output path : %s\n", outputPath)
	fmt.Printf("[+] Tenet       : %v\n", enableTenet)

	this.runTrace(endAddr, outputPath, enableTenet, boundStart, boundEnd)
}

func (this *Client) runTrace(endAddr uint64, outputPath string, enableTenet bool, boundStart, boundEnd uint64) {
	os.MkdirAll(outputPath, 0755)

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	totalLogPath := filepath.Join(outputPath, fmt.Sprintf("uc_combine_%s.log", ts))
	totalLog, err := os.Create(totalLogPath)
	if err != nil {
		fmt.Printf("[!] Failed to create combined log: %v\n", err)
		return
	}
	defer totalLog.Close()

	var tenetCombinePath string
	var tenetTotalLog *os.File
	if enableTenet {
		tenetCombinePath = filepath.Join(outputPath, fmt.Sprintf("tenet_combine_%s.log", ts))
		tenetTotalLog, err = os.Create(tenetCombinePath)
		if err != nil {
			fmt.Printf("[!] Failed to create tenet combined log: %v\n", err)
			return
		}
		defer tenetTotalLog.Close()
	}

	for dumpRound := 0; dumpRound < RoundMax; dumpRound++ {
		fmt.Printf("\n[+] ===== Round %d =====\n", dumpRound)

		roundTS := strconv.FormatInt(time.Now().Unix(), 10)
		dumpPath := filepath.Join(outputPath, fmt.Sprintf("dump_%s", roundTS))
		os.MkdirAll(dumpPath, 0755)

		registers := this.collectRegisterState()

		fmt.Println("[+] DUMPING memory")
		var dumpedRanges []dumpedRange
		// Always dump the entire bound range (code segment) first
		this.dumpFullRange(boundStart, boundEnd, dumpPath, &dumpedRanges)
		// Then dump memory regions pointed to by registers
		this.dumpRegistersMemory(registers, dumpPath, &dumpedRanges)

		registers["run_start"] = fmt.Sprintf("0x%x", boundStart)
		registers["run_end"] = fmt.Sprintf("0x%x", boundEnd)
		registers["resolved_end_addr"] = fmt.Sprintf("0x%x", endAddr)

		regsPath := filepath.Join(dumpPath, "regs.json")
		regsData, _ := json.MarshalIndent(registers, "", "  ")
		os.WriteFile(regsPath, regsData, 0644)
		fmt.Println("[+] Registers saved to", regsPath)

		tracer, err := NewUnicornTracer()
		if err != nil {
			fmt.Printf("[!] Failed to create tracer: %v\n", err)
			return
		}

		tracer.runRange = [2]uint64{boundStart, boundEnd}

		var tenetLogPath string
		if enableTenet {
			tenetLogPath = filepath.Join(dumpPath, "tenet.log")
		}
		ucLogPath := filepath.Join(dumpPath, "uc.log")

		resultCode := 11400
		for resultCode != TraceResultSuccess {
			resultCode = tracer.MainTrace(endAddr, tenetLogPath, ucLogPath, dumpPath)
			if resultCode == TraceResultReDump {
				fmt.Println("[+] Update Memory (re-dump)")
				this.dumpMemoryForTracer(tracer, dumpPath, &dumpedRanges)
			} else if resultCode == TraceResultMRSTpidr {
				fmt.Printf("[+] Detected MRS x%d, TPIDR_EL0 — syncing with debugger\n", tracer.tpidrMRSDestReg)
				tpidrVal := this.autoGetTpidr(tracer)
				if tpidrVal != 0 {
					tracer.tpidrValue = tpidrVal
					tracer.tpidrDetected = true
					tracer.uc.RegWrite(UC_ARM64_REG_TPIDR_EL0, tpidrVal)
					this.saveTpidrToRegs(regsPath, tpidrVal)
					fmt.Printf("[+] TPIDR_EL0 = 0x%x (re-emulating MRS to log it)\n", tpidrVal)
					// Don't advance PC — let Unicorn re-execute the MRS with correct TPIDR_EL0
				} else {
					fmt.Println("[!] Failed to get TPIDR, skipping MRS")
					tracer.writeReg("pc", tracer.GetPC()+4)
				}
			} else {
				break
			}
		}

		// Capture tracer state before closing
		finalPC := tracer.GetPC()
		haltReason := tracer.haltReason
		finalLR := tracer.GetLR()

		// Append round logs to combined logs
		appendFileContents(totalLog, filepath.Join(dumpPath, "uc.log"))
		if enableTenet && tenetTotalLog != nil {
			appendFileContents(tenetTotalLog, filepath.Join(dumpPath, "tenet.log"))
		}

		tracer.Close()

		switch resultCode {
		case TraceResultRestart:
			fmt.Println("[+] Out-of-range, syncing with live debugger...")
			if !this.traceSyncAndContinue(finalPC, finalLR, haltReason) {
				fmt.Println("[!] Failed to sync with debugger, stopping trace")
				return
			}
			continue

		case TraceResultError:
			fmt.Println("[!] Trace error, stopping")
			break

		case TraceResultSameAddr:
			fmt.Println("[!] Start address == End address, nothing to trace")
			break

		case TraceResultSuccess:
			if finalPC == endAddr {
				fmt.Println("[+] Trace completed successfully!")
			} else {
				fmt.Printf("[!] Trace ended at unexpected PC 0x%x\n", finalPC)
			}
		}

		break
	}

	fmt.Printf("\n[+] Combined UC log  : %s\n", totalLogPath)
	if tenetCombinePath != "" {
		fmt.Printf("[+] Combined Tenet log: %s\n", tenetCombinePath)
	}
}

func (this *Client) collectRegisterState() map[string]string {
	registers := make(map[string]string)
	ctx := this.Process.Context

	for i := 0; i < 30; i++ {
		val := ctx.Regs[i]
		if val&0xb4ff000000000000 == 0xb400000000000000 {
			val = val & 0x00ffffffffffffff
		}
		registers[fmt.Sprintf("x%d", i)] = fmt.Sprintf("0x%x", val)
	}

	registers["x30"] = fmt.Sprintf("0x%x", ctx.LR)
	registers["sp"] = fmt.Sprintf("0x%x", ctx.SP)
	registers["pc"] = fmt.Sprintf("0x%x", ctx.PC)

	return registers
}

func (this *Client) collectAutoRange() (uint64, uint64) {
	pc := this.Process.Context.PC
	mapsContent, err := utils.ReadMapsByPid(this.Process.WorkPid)
	if err != nil {
		return 0, 0
	}

	lines := strings.Split(mapsContent, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addrParts := strings.Split(fields[0], "-")
		if len(addrParts) != 2 {
			continue
		}
		start, _ := strconv.ParseUint(addrParts[0], 16, 64)
		end, _ := strconv.ParseUint(addrParts[1], 16, 64)
		perm := fields[1]

		if start <= pc && pc < end && strings.Contains(perm, "x") {
			return start, end
		}
	}

	return 0, 0
}

type dumpedRange struct {
	start, end uint64
}

func (this *Client) dumpRegistersMemory(registers map[string]string, dumpPath string, dumped *[]dumpedRange) {
	for _, valStr := range registers {
		val, err := strconv.ParseUint(strings.TrimPrefix(valStr, "0x"), 16, 64)
		if err != nil {
			continue
		}
		if val < 0x1000 {
			continue
		}
		this.dumpSegmentForAddress(val, DumpSingleSegSize, dumpPath, dumped, true)
	}
}

func (this *Client) dumpFullRange(start, end uint64, dumpPath string, dumped *[]dumpedRange) {
	size := end - start
	if size == 0 {
		return
	}

	for _, d := range *dumped {
		if d.start <= start && d.end >= end {
			return
		}
	}

	data, err := utils.ReadProcessMemoryRobust(this.Process.WorkPid, uintptr(start), int(size))
	if err != nil {
		fmt.Printf("[!] Failed to read full range 0x%x-0x%x: %v\n", start, end, err)
		return
	}

	filename := fmt.Sprintf("segment_0x%x_0x%x_0x%x.bin", start, end, size)
	filePath := filepath.Join(dumpPath, filename)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		fmt.Printf("[!] Failed to write dump file: %v\n", err)
		return
	}

	*dumped = append(*dumped, dumpedRange{start, end})
	fmt.Printf("[+] Dumped 0x%x - 0x%x (0x%x bytes) → %s\n", start, end, size, filename)
}

func (this *Client) dumpSegmentForAddress(addr uint64, rangeSize uint64, dumpPath string, dumped *[]dumpedRange, followNext bool) {
	if addr&0xb4ff000000000000 == 0xb400000000000000 {
		addr = addr & 0x00ffffffffffffff
	}

	mapsContent, err := utils.ReadMapsByPid(this.Process.WorkPid)
	if err != nil {
		return
	}

	var segStart, segEnd uint64
	found := false
	lines := strings.Split(mapsContent, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addrParts := strings.Split(fields[0], "-")
		if len(addrParts) != 2 {
			continue
		}
		start, _ := strconv.ParseUint(addrParts[0], 16, 64)
		end, _ := strconv.ParseUint(addrParts[1], 16, 64)
		if start <= addr && addr < end {
			segStart = start
			segEnd = end
			found = true
			break
		}
	}

	if !found {
		return
	}

	var dumpBase uint64
	if rangeSize < 0x10000 {
		dumpBase = addr & ^uint64(0xfff)
	} else {
		dumpBase = addr & ^(rangeSize - 1)
	}

	dumpEnd := dumpBase + rangeSize
	if dumpEnd > segEnd {
		dumpEnd = segEnd
	}
	if dumpBase < segStart {
		dumpBase = segStart
	}

	for _, d := range *dumped {
		if dumpBase >= d.start && dumpBase < d.end {
			dumpBase = d.end
		}
		if dumpEnd > d.start && dumpEnd <= d.end {
			dumpEnd = d.start
		}
	}

	if dumpBase >= dumpEnd {
		return
	}

	*dumped = append(*dumped, dumpedRange{dumpBase, dumpEnd})

	size := dumpEnd - dumpBase
	data, err := utils.ReadProcessMemoryRobust(this.Process.WorkPid, uintptr(dumpBase), int(size))
	if err != nil {
		fmt.Printf("[!] Failed to read memory at 0x%x: %v\n", dumpBase, err)
		return
	}

	filename := fmt.Sprintf("segment_0x%x_0x%x_0x%x.bin", dumpBase, dumpEnd, size)
	filePath := filepath.Join(dumpPath, filename)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		fmt.Printf("[!] Failed to write dump file: %v\n", err)
		return
	}

	fmt.Printf("[+] Dumped 0x%x - 0x%x (0x%x bytes) → %s\n", dumpBase, dumpEnd, size, filename)

	if followNext && dumpBase+rangeSize > segEnd {
		nextAddr := segEnd + 1
		this.dumpSegmentForAddress(nextAddr, rangeSize, dumpPath, dumped, false)
	}
}

func (this *Client) dumpMemoryForTracer(tracer *UnicornTracer, dumpPath string, dumped *[]dumpedRange) {
	pc := tracer.GetPC()

	// Try reading instruction at PC. If this fails, PC itself is unmapped (FETCH error).
	code, err := tracer.uc.MemRead(pc, 4)
	if err != nil {
		// PC is unmapped — dump the region containing PC
		fmt.Printf("[+] Dump memory for address 0x%x\n", pc)
		this.dumpSegmentForAddress(pc, DumpSingleSegSize, dumpPath, dumped, true)
		tracer.LoadMemoryMappings(dumpPath)
		return
	}

	// PC is mapped — analyze the instruction to find the data address that caused the fault
	memAddrs := this.analyzeMemoryAddrsForDump(code, tracer)
	for _, addr := range memAddrs {
		fmt.Printf("[+] Dump memory for address 0x%x\n", addr)
		this.dumpSegmentForAddress(addr, DumpSingleSegSize, dumpPath, dumped, true)
	}
	if len(memAddrs) > 0 {
		tracer.LoadMemoryMappings(dumpPath)
		return
	}

	// Fallback: dump all register-pointed addresses
	for i := 0; i < 31; i++ {
		regName := fmt.Sprintf("x%d", i)
		val := tracer.readReg(regName)
		if val > 0x1000 {
			this.dumpSegmentForAddress(val, DumpSingleSegSize, dumpPath, dumped, true)
		}
	}
	sp := tracer.readReg("sp")
	if sp > 0x1000 {
		this.dumpSegmentForAddress(sp, DumpSingleSegSize, dumpPath, dumped, true)
	}
	tracer.LoadMemoryMappings(dumpPath)
}

func (this *Client) analyzeMemoryAddrsForDump(code []byte, tracer *UnicornTracer) []uint64 {
	inst, err := arm64asm.Decode(code)
	if err != nil {
		return nil
	}

	if !readOps[inst.Op] && !writeOps[inst.Op] {
		return nil
	}

	addr, ok := resolveMemAddr(inst, tracer.readReg)
	if !ok {
		return nil
	}

	return []uint64{addr}
}

func (this *Client) autoGetTpidr(tracer *UnicornTracer) uint64 {
	mrsPC := tracer.GetPC()
	targetAddr := mrsPC + 4

	address, err := this.Process.ParseAddress(targetAddr)
	if err != nil {
		fmt.Printf("[!] Failed to parse address 0x%x: %v\n", targetAddr, err)
		return 0
	}

	if err = this.BrkManager.SetTempBreak(address, this.Process.WorkTid); err != nil {
		fmt.Printf("[!] Failed to set temp breakpoint: %v\n", err)
		return 0
	}

	seq := this.CurrentStopSequence()
	if !this.HandleContinue() {
		return 0
	}

	_, err = this.WaitForStopAfter(seq, 120*time.Second)
	if err != nil {
		fmt.Printf("[!] Timeout waiting for debugger: %v\n", err)
		return 0
	}

	// After MRS executes, read the destination register from the real context
	destReg := tracer.tpidrMRSDestReg
	var tpidrVal uint64
	if destReg < 30 {
		tpidrVal = this.Process.Context.Regs[destReg]
	} else if destReg == 30 {
		tpidrVal = this.Process.Context.LR
	}

	fmt.Printf("[+] Debugger executed MRS at 0x%x, x%d = 0x%x\n", mrsPC, destReg, tpidrVal)
	return tpidrVal
}

func (this *Client) saveTpidrToRegs(regsPath string, tpidrVal uint64) {
	data, err := os.ReadFile(regsPath)
	if err != nil {
		return
	}
	var regs map[string]interface{}
	if err := json.Unmarshal(data, &regs); err != nil {
		return
	}
	regs["tpidr"] = fmt.Sprintf("0x%x", tpidrVal)
	newData, _ := json.MarshalIndent(regs, "", "  ")
	os.WriteFile(regsPath, newData, 0644)
}

func (this *Client) traceSyncAndContinue(ucPC, ucLR uint64, haltReason string) bool {
	var targetAddr uint64
	if haltReason != "" && strings.Contains(haltReason, "Except AUTIASP") {
		targetAddr = ucPC + 4
	} else if haltReason != "" && strings.Contains(haltReason, "Except SVC") {
		targetAddr = ucPC + 4
	} else {
		targetAddr = ucLR
	}

	fmt.Printf("[+] Running debugger to 0x%x (PC=0x%x, LR=0x%x)\n", targetAddr, ucPC, ucLR)

	address, err := this.Process.ParseAddress(targetAddr)
	if err != nil {
		fmt.Printf("[!] Failed to parse target address 0x%x: %v\n", targetAddr, err)
		return false
	}

	if err = this.BrkManager.SetTempBreak(address, this.Process.WorkTid); err != nil {
		fmt.Printf("[!] Failed to set temp breakpoint: %v\n", err)
		return false
	}

	seq := this.CurrentStopSequence()

	if !this.HandleContinue() {
		return false
	}

	_, err = this.WaitForStopAfter(seq, 120*time.Second)
	if err != nil {
		fmt.Printf("[!] Timeout waiting for debugger: %v\n", err)
		return false
	}

	fmt.Printf("[+] Debugger stopped at 0x%x\n", this.Process.Context.PC)
	return true
}

func appendFileContents(dst *os.File, srcPath string) {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return
	}
	dst.Write(data)
}
