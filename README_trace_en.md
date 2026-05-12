# eDBG Unicorn Trace Guide

## Overview

eDBG includes built-in Unicorn Trace support. During debugging, it can emulate ARM64 code execution with the Unicorn engine and automatically generate execution trace logs. The output format is fully compatible with [Unicorn-Trace](https://github.com/chenxvb/Unicorn-Trace) and can be loaded by the Tenet plugin in IDA. For better dump-based replay, we recommend using the [custom Tenet build](https://github.com/chenxvb/Tenet-IDA9.0).

### How It Works

1. Read registers and memory state at the current breakpoint.
2. Load the state into Unicorn and start emulation.
3. Record register changes and memory accesses for each instruction (`tenet.log` + `uc.log`).
4. If an external call or out-of-range jump is hit, switch back to live debugger execution for that part.
5. Re-capture state and continue emulation in the next round until the target address is reached.

## Command Format

```text
trace <end_addr> [output_path] [--tenet] [--bound <start> <end>]
```

**Alias:** `tr`

### Parameters

| Parameter | Description |
|------|------|
| `end_addr` | Target end address (required). Supports absolute address, relative offset, and register expressions. |
| `output_path` | Output directory (optional, default: current directory `.`). |
| `--tenet` | Enable Tenet-format trace output (optional). |
| `--bound <start> <end>` | Set legal emulation address range (optional, default: auto-detect executable segment containing current PC). |

### Address Formats

`end_addr` follows the same address syntax as other eDBG commands:

- Absolute address: `0x7abc1234`
- Library offset: `libxxx.so+0x1234`
- Register expression: `x0`, `x0+0x10`
- Relative offset (based on primary library): `0x1234`

## Usage Examples

### Basic Usage

```text
(eDBG) b libxxx.so+0x1234        # Break at target function entry
(eDBG) c                         # Continue until breakpoint is hit
(eDBG) trace 0x7abc5678          # Trace until target address
```

### Enable Tenet Output

```text
(eDBG) trace 0x7abc5678 ./trace_out --tenet
```

### Specify Execution Bound

When auto-detected bound is not accurate, specify it manually:

```text
(eDBG) trace 0x7abc5678 ./trace_out --tenet --bound 0x7abc0000 0x7abcf000
```

### Use Register Expressions

```text
(eDBG) trace x30               # Trace until LR (function return)
(eDBG) trace x0+0x100 /data/local/tmp/trace_out --tenet
```

## Output Files

After trace completes, output directory contains files like:

```text
trace_out/
├── uc_combine_1234567890.log         # Merged UC log (all rounds)
├── tenet_combine_1234567890.log      # Merged Tenet log (when --tenet is enabled)
├── dump_1234567890/                  # Round 0 dump directory
│   ├── regs.json                     # Register snapshot
│   ├── uc.log                        # UC log for this round
│   ├── tenet.log                     # Tenet log for this round
│   ├── segment_0x7abc0000_0x7abc4000_0x4000.bin   # Memory dump
│   ├── segment_0x7fff0000_0x7fff4000_0x4000.bin
│   └── ...
├── dump_1234567891/                  # Round 1 (if external-call sync occurs)
│   └── ...
└── ...
```

### File Formats

#### `uc.log` (Disassembly Log)

One instruction per line: address, mnemonic, operands, and parsed operand values:

```text
0x7abc1234    : LDR      X0, [X1, #0x10]          0x7abc5678 0x10
0x7abc1238    : ADD      X2, X0, X1               0x1234 0x5678
0x7abc123c    : STR      X2, [SP, #0x20]          0x7fff1000 0x20
```

#### `tenet.log` (Tenet Format)

First line is initial register state. Following lines contain changed registers and memory accesses:

```text
# DUMP_DIR: /data/local/tmp/trace_out/dump_1234567890
X0=0x1234,X1=0x5678,...,SP=0xffff,PC=0x7abc1234
X0=0x9999,PC=0x7abc1238,mr=0x7abc5688:deadbeefdeadbeef
X1=0xaaaa,PC=0x7abc123c,mw=0x7fff1020:1234567812345678
```

- `mr=addr:hexdata` — memory read
- `mw=addr:hexdata` — memory write

#### Load in Tenet

1. Install [Tenet](https://github.com/gaasedelen/tenet) plugin in IDA.
2. `File -> Load file -> Tenet trace file`
3. Select `tenet_combine_*.log`

#### `regs.json` + dump `.bin`

Dump files are compatible with Unicorn-Trace `local_emu.py` and can be replayed directly:

```python
# Use eDBG dump in Unicorn-Trace
emulator = Arm64Emulator()
emulator.load_registers("dump_xxx/regs.json")
emulator.load_memory_mappings("dump_xxx/")
```

## Execution Flow

### Normal Completion

```text
[+] ===== Round 0 =====
[+] DUMPING memory
[+] Dumped 0x7abc0000 - 0x7abc4000 (0x4000 bytes) -> segment_0x7abc0000_...
[+] Registers saved to ./trace_out/dump_.../regs.json
[+] Emulating from 0x7abc1234 to 0x7abc5678
Trace END!
[+] Trace completed successfully!
[+] Combined UC log  : ./trace_out/uc_combine_xxx.log
[+] Combined Tenet log: ./trace_out/tenet_combine_xxx.log
```

### External Call Encountered (Multiple Rounds)

When emulation hits an out-of-range branch (for example, external library call), trace will:

1. Set a temporary breakpoint at LR.
2. Run the real debugger through the external call.
3. Re-capture registers and memory.
4. Start a new emulation round.

```text
[+] ===== Round 0 =====
...
[+] Out-of-range, syncing with live debugger...
[+] Running debugger to 0x7abc1240 (PC=0x7abc1234, LR=0x7abc1240)
[+] Debugger stopped at 0x7abc1240
[+] ===== Round 1 =====
...
```

### Unmapped Memory Encountered

When Unicorn accesses memory that was not dumped, trace automatically dumps that region from the process and retries:

```text
[+] Update Memory (re-dump)
[+] Dump memory for address 0x7def0000
[+] Dumped 0x7def0000 - 0x7def4000 (0x4000 bytes)
```

## Bound Range Notes

`--bound` defines the legal address range for emulation. If PC goes out of range, it is treated as an external call and sync flow is triggered.

- **Not specified**: automatically use the executable memory segment containing current PC (from `/proc/pid/maps`)
- **Specified manually**: useful when auto-detection is not accurate (for example, multiple executable code segments)

Typical setup: set bound to the target library `.text` range.

## Build Notes

### Dependencies

- Android NDK (`aarch64-linux-android29` toolchain)
- Unicorn static library: `unicorn_lib/libunicorn.a` (required)

### Download and Prepare `libunicorn.a`

`trace` links against `unicorn_lib/libunicorn.a` through cgo.  
This file is large (over GitHub's 100MB single-file limit), so it is not shipped directly in the repository and must be prepared manually before build.

#### Method 1: Download from Release (Recommended)

1. Open the latest release page
2. Download the ARM64 Unicorn static library artifact (`libunicorn.a`)
3. Put it at: `unicorn_lib/libunicorn.a`

#### Method 2: Build Unicorn and Copy

```bash
export NDK_ROOT=/path/to/android-ndk
git clone https://github.com/unicorn-engine/unicorn.git
cd unicorn
mkdir build && cd build
cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=$NDK_ROOT/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-29 \
  -DUNICORN_BUILD_SHARED=OFF
make -j8
cp libunicorn.a /path/to/eDBG/unicorn_lib/libunicorn.a
```

Verify file placement:

```bash
ls -lh unicorn_lib/libunicorn.a
```

### Build

```bash
export NDK_ROOT=/path/to/android-ndk
make build
```

Build output: `bin/eDBG_arm64`

### Deploy

```bash
adb push bin/eDBG_arm64 /data/local/tmp/
adb shell chmod +x /data/local/tmp/eDBG_arm64
```
