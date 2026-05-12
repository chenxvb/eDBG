package cli

/*
#cgo CFLAGS: -I${SRCDIR}/../unicorn_include
#cgo LDFLAGS: -L${SRCDIR}/../unicorn_lib -lunicorn -lm

#include <unicorn/unicorn.h>
#include <stdlib.h>

// Hook callback trampoline — called from C, dispatches to Go via a global map.
extern void goCodeHookTrampoline(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

static uc_err uc_hook_add_code_wrapper(uc_engine *uc, uc_hook *hh, uint64_t begin, uint64_t end, void *user_data) {
    return uc_hook_add(uc, hh, UC_HOOK_CODE, (void *)goCodeHookTrampoline, user_data, begin, end);
}
*/
import "C"
import (
	"fmt"
	"sync"
	"unsafe"
)

// ARM64 register constants (matching unicorn/arm64.h)
const (
	UC_ARCH_ARM64 = C.UC_ARCH_ARM64
	UC_MODE_ARM   = C.UC_MODE_ARM

	UC_ARM64_REG_X0  = C.UC_ARM64_REG_X0
	UC_ARM64_REG_X1  = C.UC_ARM64_REG_X1
	UC_ARM64_REG_X2  = C.UC_ARM64_REG_X2
	UC_ARM64_REG_X3  = C.UC_ARM64_REG_X3
	UC_ARM64_REG_X4  = C.UC_ARM64_REG_X4
	UC_ARM64_REG_X5  = C.UC_ARM64_REG_X5
	UC_ARM64_REG_X6  = C.UC_ARM64_REG_X6
	UC_ARM64_REG_X7  = C.UC_ARM64_REG_X7
	UC_ARM64_REG_X8  = C.UC_ARM64_REG_X8
	UC_ARM64_REG_X9  = C.UC_ARM64_REG_X9
	UC_ARM64_REG_X10 = C.UC_ARM64_REG_X10
	UC_ARM64_REG_X11 = C.UC_ARM64_REG_X11
	UC_ARM64_REG_X12 = C.UC_ARM64_REG_X12
	UC_ARM64_REG_X13 = C.UC_ARM64_REG_X13
	UC_ARM64_REG_X14 = C.UC_ARM64_REG_X14
	UC_ARM64_REG_X15 = C.UC_ARM64_REG_X15
	UC_ARM64_REG_X16 = C.UC_ARM64_REG_X16
	UC_ARM64_REG_X17 = C.UC_ARM64_REG_X17
	UC_ARM64_REG_X18 = C.UC_ARM64_REG_X18
	UC_ARM64_REG_X19 = C.UC_ARM64_REG_X19
	UC_ARM64_REG_X20 = C.UC_ARM64_REG_X20
	UC_ARM64_REG_X21 = C.UC_ARM64_REG_X21
	UC_ARM64_REG_X22 = C.UC_ARM64_REG_X22
	UC_ARM64_REG_X23 = C.UC_ARM64_REG_X23
	UC_ARM64_REG_X24 = C.UC_ARM64_REG_X24
	UC_ARM64_REG_X25 = C.UC_ARM64_REG_X25
	UC_ARM64_REG_X26 = C.UC_ARM64_REG_X26
	UC_ARM64_REG_X27 = C.UC_ARM64_REG_X27
	UC_ARM64_REG_X28 = C.UC_ARM64_REG_X28
	UC_ARM64_REG_X29 = C.UC_ARM64_REG_X29
	UC_ARM64_REG_X30 = C.UC_ARM64_REG_X30
	UC_ARM64_REG_SP  = C.UC_ARM64_REG_SP
	UC_ARM64_REG_PC  = C.UC_ARM64_REG_PC

	UC_ARM64_REG_TPIDR_EL0 = C.UC_ARM64_REG_TPIDR_EL0
	UC_ARM64_REG_NZCV      = C.UC_ARM64_REG_NZCV
)

// UcEngine wraps the Unicorn engine handle.
type UcEngine struct {
	handle *C.uc_engine
	hooks  []C.uc_hook
	hookID uint64
}

// UcError wraps Unicorn error codes.
type UcError struct {
	Code    int
	Message string
}

func (e *UcError) Error() string {
	return fmt.Sprintf("unicorn error %d: %s", e.Code, e.Message)
}

func ucError(err C.uc_err) error {
	if err == C.UC_ERR_OK {
		return nil
	}
	msg := C.GoString(C.uc_strerror(err))
	return &UcError{Code: int(err), Message: msg}
}

// NewUcEngine creates a new Unicorn engine for ARM64.
func NewUcEngine() (*UcEngine, error) {
	var handle *C.uc_engine
	err := C.uc_open(C.UC_ARCH_ARM64, C.UC_MODE_ARM, &handle)
	if err != C.UC_ERR_OK {
		return nil, ucError(err)
	}
	return &UcEngine{handle: handle}, nil
}

func (uc *UcEngine) Close() {
	if uc.handle != nil {
		for _, h := range uc.hooks {
			C.uc_hook_del(uc.handle, h)
		}
		C.uc_close(uc.handle)
		uc.handle = nil
	}
}

func (uc *UcEngine) MemMap(address, size uint64) error {
	err := C.uc_mem_map(uc.handle, C.uint64_t(address), C.size_t(size), C.UC_PROT_ALL)
	return ucError(err)
}

func (uc *UcEngine) MemWrite(address uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	err := C.uc_mem_write(uc.handle, C.uint64_t(address), unsafe.Pointer(&data[0]), C.size_t(len(data)))
	return ucError(err)
}

func (uc *UcEngine) MemRead(address uint64, size int) ([]byte, error) {
	buf := make([]byte, size)
	err := C.uc_mem_read(uc.handle, C.uint64_t(address), unsafe.Pointer(&buf[0]), C.size_t(size))
	if err != C.UC_ERR_OK {
		return nil, ucError(err)
	}
	return buf, nil
}

func (uc *UcEngine) RegRead(regID int) (uint64, error) {
	var val C.uint64_t
	err := C.uc_reg_read(uc.handle, C.int(regID), unsafe.Pointer(&val))
	if err != C.UC_ERR_OK {
		return 0, ucError(err)
	}
	return uint64(val), nil
}

func (uc *UcEngine) RegWrite(regID int, value uint64) error {
	val := C.uint64_t(value)
	err := C.uc_reg_write(uc.handle, C.int(regID), unsafe.Pointer(&val))
	return ucError(err)
}

func (uc *UcEngine) EmuStart(begin, until uint64) error {
	err := C.uc_emu_start(uc.handle, C.uint64_t(begin), C.uint64_t(until), 0, 0)
	return ucError(err)
}

func (uc *UcEngine) EmuStop() error {
	err := C.uc_emu_stop(uc.handle)
	return ucError(err)
}

// CodeHookFunc is the Go signature for code hooks.
type CodeHookFunc func(addr uint64, size uint32)

var (
	hookMu    sync.Mutex
	hookMap   = make(map[uint64]CodeHookFunc)
	hookIDSeq uint64
)

//export goCodeHookTrampoline
func goCodeHookTrampoline(uc *C.uc_engine, address C.uint64_t, size C.uint32_t, userData unsafe.Pointer) {
	id := uint64(uintptr(userData))
	hookMu.Lock()
	fn, ok := hookMap[id]
	hookMu.Unlock()
	if ok {
		fn(uint64(address), uint32(size))
	}
}

func (uc *UcEngine) HookAddCode(fn CodeHookFunc, begin, end uint64) error {
	hookMu.Lock()
	hookIDSeq++
	id := hookIDSeq
	hookMap[id] = fn
	hookMu.Unlock()

	var hh C.uc_hook
	err := C.uc_hook_add_code_wrapper(uc.handle, &hh, C.uint64_t(begin), C.uint64_t(end), unsafe.Pointer(uintptr(id)))
	if err != C.UC_ERR_OK {
		hookMu.Lock()
		delete(hookMap, id)
		hookMu.Unlock()
		return ucError(err)
	}
	uc.hooks = append(uc.hooks, hh)
	return nil
}

// Register name to Unicorn constant mapping (matching Unicorn-Trace REG_MAP).
var UcRegMap = map[string]int{
	"x0": UC_ARM64_REG_X0, "x1": UC_ARM64_REG_X1, "x2": UC_ARM64_REG_X2, "x3": UC_ARM64_REG_X3,
	"x4": UC_ARM64_REG_X4, "x5": UC_ARM64_REG_X5, "x6": UC_ARM64_REG_X6, "x7": UC_ARM64_REG_X7,
	"x8": UC_ARM64_REG_X8, "x9": UC_ARM64_REG_X9, "x10": UC_ARM64_REG_X10, "x11": UC_ARM64_REG_X11,
	"x12": UC_ARM64_REG_X12, "x13": UC_ARM64_REG_X13, "x14": UC_ARM64_REG_X14, "x15": UC_ARM64_REG_X15,
	"x16": UC_ARM64_REG_X16, "x17": UC_ARM64_REG_X17, "x18": UC_ARM64_REG_X18, "x19": UC_ARM64_REG_X19,
	"x20": UC_ARM64_REG_X20, "x21": UC_ARM64_REG_X21, "x22": UC_ARM64_REG_X22, "x23": UC_ARM64_REG_X23,
	"x24": UC_ARM64_REG_X24, "x25": UC_ARM64_REG_X25, "x26": UC_ARM64_REG_X26, "x27": UC_ARM64_REG_X27,
	"x28": UC_ARM64_REG_X28, "x29": UC_ARM64_REG_X29, "x30": UC_ARM64_REG_X30,
	"sp": UC_ARM64_REG_SP, "pc": UC_ARM64_REG_PC,
	"lr": UC_ARM64_REG_X30, "fp": UC_ARM64_REG_X29,
	"tpidr": UC_ARM64_REG_TPIDR_EL0,
}

// Tracked registers in trace order (matching Unicorn-Trace TRACKED_REGS).
var TrackedRegs = []string{
	"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
	"x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
	"x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
	"x30", "sp", "pc",
}
