# eDBG Unicorn Trace 使用指南

## 功能说明

eDBG 内置了 Unicorn-Trace 功能，可以在调试过程中使用 Unicorn 引擎模拟 ARM64 代码执行，自动生成执行 trace 日志。输出格式与 [Unicorn-Trace](https://github.com/chenxvb/Unicorn-Trace) 完全兼容，支持 Tenet IDA 插件加载。推荐使用[特化版 Tenet](https://github.com/chenxvb/Tenet-IDA9.0), 支持 dump 内存加载，在 ida 中还原完整动调

### 工作原理

1. 从当前断点位置读取寄存器和内存状态
2. 将状态加载到 Unicorn 引擎中进行模拟执行
3. 每条指令记录寄存器变化和内存访问（tenet.log + uc.log）
4. 遇到外部调用/越界时，自动切回真实调试器执行过外部函数
5. 重新采集状态后继续模拟，循环直到到达目标地址

## 命令格式

```
trace <end_addr> [output_path] [--tenet] [--bound <start> <end>]
```

**简写：** `tr`

### 参数说明

| 参数 | 说明 |
|------|------|
| `end_addr` | 目标结束地址（必填），支持绝对地址、相对偏移、寄存器表达式 |
| `output_path` | 输出目录路径（可选，默认当前目录 `.`） |
| `--tenet` | 启用 Tenet 格式 trace 日志输出（可选） |
| `--bound <start> <end>` | 设置模拟执行的合法地址范围（可选，默认自动检测 PC 所在可执行段） |

### 地址格式

`end_addr` 支持与 eDBG 其他命令一致的地址格式：

- 绝对地址：`0x7abc1234`
- 库偏移：`libxxx.so+0x1234`
- 寄存器表达式：`x0`、`x0+0x10`
- 相对偏移（基于主库）：`0x1234`

## 使用示例

### 基本用法

```
(eDBG) b libxxx.so+0x1234        # 在目标函数入口下断点
(eDBG) c                          # 继续运行直到断点
(eDBG) trace 0x7abc5678           # trace 到指定地址
```

### 启用 Tenet 输出

```
(eDBG) trace 0x7abc5678 ./trace_out --tenet
```

### 指定执行范围

当自动检测的范围不准确时，手动指定 bound：

```
(eDBG) trace 0x7abc5678 ./trace_out --tenet --bound 0x7abc0000 0x7abcf000
```

### 使用寄存器表达式

```
(eDBG) trace x30               # trace 到 LR（函数返回）
(eDBG) trace x0+0x100 /data/local/tmp/trace_out --tenet
```

## 输出文件

trace 完成后在输出目录中产生以下文件：

```
trace_out/
├── uc_combine_1234567890.log         # 合并的 UC 日志（所有 round）
├── tenet_combine_1234567890.log      # 合并的 Tenet 日志（--tenet 时）
├── dump_1234567890/                  # Round 0 的 dump 目录
│   ├── regs.json                     # 寄存器快照
│   ├── uc.log                        # 本轮 UC 日志
│   ├── tenet.log                     # 本轮 Tenet 日志
│   ├── segment_0x7abc0000_0x7abc4000_0x4000.bin   # 内存 dump
│   ├── segment_0x7fff0000_0x7fff4000_0x4000.bin
│   └── ...
├── dump_1234567891/                  # Round 1（如果有外部调用重启）
│   └── ...
└── ...
```

### 文件格式

#### uc.log（反汇编日志）

每行一条指令，包含地址、指令助记符、操作数和解析后的寄存器值：

```
0x7abc1234    : LDR      X0, [X1, #0x10]          0x7abc5678 0x10
0x7abc1238    : ADD      X2, X0, X1               0x1234 0x5678
0x7abc123c    : STR      X2, [SP, #0x20]          0x7fff1000 0x20
```

#### tenet.log（Tenet 格式）

首行为初始寄存器状态，后续每行记录变化的寄存器和内存访问：

```
# DUMP_DIR: /data/local/tmp/trace_out/dump_1234567890
X0=0x1234,X1=0x5678,...,SP=0xffff,PC=0x7abc1234
X0=0x9999,PC=0x7abc1238,mr=0x7abc5688:deadbeefdeadbeef
X1=0xaaaa,PC=0x7abc123c,mw=0x7fff1020:1234567812345678
```

- `mr=地址:十六进制数据` — 内存读取
- `mw=地址:十六进制数据` — 内存写入

#### 在 Tenet 中加载

1. IDA 中安装 [Tenet](https://github.com/gaasedelen/tenet) 插件
2. `File → Load file → Tenet trace file`
3. 选择 `tenet_combine_*.log`

#### regs.json + dump bin

dump 文件与 Unicorn-Trace 的 `local_emu.py` 兼容，可以直接用 Unicorn-Trace 加载回放：

```python
# 在 Unicorn-Trace 中使用 eDBG 的 dump
emulator = Arm64Emulator()
emulator.load_registers("dump_xxx/regs.json")
emulator.load_memory_mappings("dump_xxx/")
```

## 执行流程说明

### 正常完成

```
[+] ===== Round 0 =====
[+] DUMPING memory
[+] Dumped 0x7abc0000 - 0x7abc4000 (0x4000 bytes) → segment_0x7abc0000_...
[+] Registers saved to ./trace_out/dump_.../regs.json
[+] Emulating from 0x7abc1234 to 0x7abc5678
Trace END!
[+] Trace completed successfully!
[+] Combined UC log  : ./trace_out/uc_combine_xxx.log
[+] Combined Tenet log: ./trace_out/tenet_combine_xxx.log
```

### 遇到外部调用（多 round）

当模拟执行遇到超出范围的跳转（例如调用外部库函数），trace 会：

1. 自动在 LR 处设置临时断点
2. 使用真实调试器执行过外部调用
3. 重新采集寄存器和内存
4. 启动新一轮模拟

```
[+] ===== Round 0 =====
...
[+] Out-of-range, syncing with live debugger...
[+] Running debugger to 0x7abc1240 (PC=0x7abc1234, LR=0x7abc1240)
[+] Debugger stopped at 0x7abc1240
[+] ===== Round 1 =====
...
```

### 遇到未映射内存

当 Unicorn 访问到未 dump 的内存地址，trace 会自动从进程中读取该区域并重试：

```
[+] Update Memory (re-dump)
[+] Dump memory for address 0x7def0000
[+] Dumped 0x7def0000 - 0x7def4000 (0x4000 bytes)
```

## Bound 范围说明

`--bound` 定义了模拟执行的合法地址范围。PC 超出此范围时会被视为"外部调用"并触发同步机制。

- **不指定**：自动使用当前 PC 所在的可执行内存段（从 `/proc/pid/maps` 读取）
- **手动指定**：适用于自动检测不准确的场景，例如多段可执行代码

典型设置：将 bound 设为目标库的 `.text` 段范围。

## 编译说明

### 依赖

- Android NDK（aarch64-linux-android29 toolchain）
- Unicorn 静态库：`unicorn_lib/libunicorn.a`（必需）

### `libunicorn.a` 下载与准备

`trace` 功能通过 cgo 链接 `unicorn_lib/libunicorn.a`。  
该文件体积较大（超过 GitHub 单文件 100MB 限制），不会直接随仓库分发，编译前需要手动准备。

#### 方式 1：从 Release 下载（推荐）

1. 打开发布页
2. 下载发布附件中的 ARM64 Unicorn 静态库（`libunicorn.a`）
3. 放到仓库路径：`unicorn_lib/libunicorn.a`

#### 方式 2：自行编译 Unicorn 并拷贝

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

可用以下命令确认文件已就位：

```bash
ls -lh unicorn_lib/libunicorn.a
```

### 编译

```bash
export NDK_ROOT=/path/to/android-ndk
make build
```

编译产物：`bin/eDBG_arm64`

### 部署

```bash
adb push bin/eDBG_arm64 /data/local/tmp/
adb shell chmod +x /data/local/tmp/eDBG_arm64
```
