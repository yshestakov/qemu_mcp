---
name: qemu-mcp
description: Debug the SIYI A8 mini gimbal MCU firmware (Nationstech N32G4FR, Cortex-M4F) in QEMU through the qemu-debug MCP server (github.com/yshestakov/qemu_mcp) - install and register it, boot the firmware with or without its bootloader, set breakpoints/watchpoints, run with timeouts, read registers/memory/peripherals (SVD), symbolized disassembly and backtraces, Cortex-M fault decoding, drive the board (IMU/encoder sensors, UART5 encoder-board link, USB shell), and record/replay with reverse stepping. Use when asked to debug, trace, reverse engineer or test this firmware under emulation, when mcp__qemu-debug__* tools are available, or when setting up qemu_mcp.
---

# qemu-mcp: debugging the A8 mini gimbal firmware in QEMU

`qemu_mcp` is an MCP server (Python standard library only). It owns one debug
session at a time: QEMU running the `siyi-a8-mini` machine, a persistent gdb
attached to QEMU's gdbstub, QMP, and the board peers on the serial ports. Its
tools are named `mcp__qemu-debug__<tool>` once registered under the name
`qemu-debug`.

If the tools are not available yet, set it up first: see
[Setup](#setup). Without an MCP client, `mcp_call.py` runs the same tools from
a shell (see [Without MCP](#without-mcp)).

## Core rules

1. **Start with `qemu_start`.** It halts at the reset vector by default
   (`halted=true`). Only one session exists; `qemu_start` replaces it.
2. **Stopped vs running.** `regs`, `mem_read`, `mem_write`, `disas`, `svd`,
   `backtrace`, `fault_info`, breakpoint changes and most `gdb_command`s need
   a *stopped* target. `shell` needs a *running* one; `link_frames` only gets
   new frames while it runs; `sensor_set` works either way. A tool called in
   the wrong state says so: call `run_interrupt` or `run_continue`.
3. **Run control never blocks for long.** `run_continue timeout_s=N`
   (default 5, max 120) returns either the stop (reason, pc/lr/sp with
   symbols, active exception) or `running`. Then call `run_wait`,
   `run_interrupt`, or do running-target work (`shell`, `link_frames`).
4. **Locations** are `0x...`, a symbol (`main`, `FUN_08033c70`), or
   `symbol+0x10`. Symbols exist only for image `0_4_9` (Ghidra export, 1112
   functions). Every image has landmarks: `bootloader_reset`,
   `Reset_Handler`, `SystemInit`, `SystemInit_return`, `__main`,
   `dma_wait_loop`. Use `sym_lookup` to search names or name an address.
5. **Fresh flash every session.** Firmware writes to flash (its config pages)
   and `mem_write`s to flash do not persist across `qemu_start`.
6. **Stop when done** with `qemu_stop` (logs stay in the run directory).

## Images and boot

| `qemu_start` argument | Effect |
|---|---|
| `image=0_4_9` (default), `0_4_3`, `0_4_12` | Vendor app releases (linked at `0x08003800`) |
| `bootloader=true` (default) | Real bootloader at `0x08000000` with the "app valid" flag (`0x55AA55AA` at `0x0807F800`) set; it jumps to the app |
| `bootloader=false` | Zeroed bootloader area, VTOR preset to `0x08003800`; starts in the app's `Reset_Handler` |
| `image=/path/flash.bin`, `vtor=0x...` | Your own raw flash image starting at `0x08000000` |
| `uid=<24 hex>`, `ucid=<32 hex>` | Chip unique IDs (bytes in address order; the shell's `sys` prints the UID as little-endian words) |
| `icount=auto` | Deterministic instruction counting |
| `mode=record` / `mode=replay`, `recording=<name>` | Record/replay (below) |
| `auto_handshake=false`, `camera_fw=0x...` | UART5 encoder-board peer behaviour |
| `debug_flags=unimp,guest_errors,cpu_reset` | QEMU `-d` log items, read with `qemu_log` |

Boot path with the bootloader: `bootloader_reset` (`0x080001AC`) →
`Reset_Handler` (`0x080039C0`) → `SystemInit` → returns to `0x080039C4` →
`__main` (scatter-load) → `main` → RTOS. `dma_wait_loop` is the first wait on
a DMA transfer in early init.

## Recipes

**Walk the boot:**
`qemu_start` → `break_add location=Reset_Handler` → `run_continue` →
`break_add location=SystemInit` → `run_continue` → `disas count=12` →
`run_step count=5` / `run_step over=true`.

**Who writes this variable?**
`watch_add location=0x20002511 size=1 access=write` → `run_continue
timeout_s=30`. The stop shows old/new values; pc is the instruction after the
store. Then `backtrace`.

**Inspect a peripheral:** stop, then `svd peripheral=RCC` (non-zero fields)
or `svd peripheral=DMA1 registers=CHCFG4,PADDR4` (all fields). `svd` with no
arguments lists peripherals. Data registers with read side effects (FIFOs)
are skipped unless named.

**A crash / fault:** `run_continue` stops with `in exception 3 (HardFault)`
→ `fault_info` (CFSR/HFSR/MMFAR/BFAR decoded) → `backtrace` (decodes the
stacked exception frame: faulting pc, lr, r0-r3).

**Stub out a function:** `mem_write location=<func> hex=7047` (`bx lr`); for
a function returning 0: `hex=00207047` (`movs r0,#0; bx lr`). Example: the
0.4.3 watchdog feed `0x080111A0` → the IWDG fires about 6.5 s later and
`qemu_status` shows `WATCHDOG`/`RESET` QMP events.

**Firmware shell (USB VCP):** `run_continue timeout_s=4` (USB enumerates
after ~2 s) → `shell command=help`, `sys`, `fw`, `cpu`, `task_info`,
`show_temp`, `cali_state`.

**Encoder-board link (UART5, protocol v2 func 0x6B):** the server answers the
MCU's `6b/13` version handshake automatically. `link_frames` lists what the
MCU sent (repeats collapsed; `6b/50` attitude decoded as angles, 10 Hz on
0.4.9/0.4.12). `link_send action_id=0x15 get=true` requests a value (the MCU
replies with the same id); `link_send action_id=0x15 payload_hex=02` sets
it.

**Sensors:** `sensor_get device=imu`; `sensor_set device=imu
property=accel-y value=1000` (mg). The firmware reads level with gravity on
+Y; the default `accel-z=1000` reports pitch -90. Encoders: `device=encoder[0]`
.. `encoder[2]`, `property=angle` (0-65535).

**Reverse debugging:**
1. `qemu_start mode=record recording=bug1`, set breakpoints, run to past the
   point of interest, `qemu_stop`.
2. `qemu_start mode=replay recording=bug1` (same image and options are
   restored), `break_add`, `run_continue` → the same stop with identical
   state.
3. `reverse_step count=N`, `reverse_continue` (back to the previous
   breakpoint/watchpoint hit). A watchpoint plus `reverse_continue` finds
   the last write to a variable; going backwards, gdb reports the hit as
   `signal-received (SIGTRAP)` rather than `watchpoint-trigger`, with pc
   just after the store, as in a forward hit.

In record mode `sensor_set` and `qemu_reset` are refused (not recorded); in
replay mode `link_send`, `shell` and `sensor_set` are disabled (input comes
from the recording). Running past the end of a recording exits QEMU; start
the replay again.

## Tool reference

See [references/tools.md](references/tools.md) for every tool and its
arguments.

## Setup

Requirements: Linux, Python 3 (standard library only; tested with 3.12), `gdb-multiarch` (or another gdb with ARM
support), and:

1. **QEMU with the `siyi-a8-mini` machine** (N32G4FR SoC models):
   ```sh
   git clone -b feat/n32g4fr_soc https://github.com/yshestakov/qemu-n32g4fr
   cd qemu-n32g4fr && ./configure --target-list=arm-softmmu && make -j"$(nproc)"
   # check: ./build/qemu-system-arm -M help | grep siyi-a8-mini
   ```
2. **siyi_a8_mini_re** (protocol v2 module and `N32G4FR.svd`):
   ```sh
   git clone https://gitlab.com/Ostrovskyi_Volodymyr/siyi_a8_mini_re
   ```
3. **Firmware** (not redistributed; the user provides it): one directory
   with `a8-mini-gimbal-0_4_3.bin`, `a8-mini-gimbal-0_4_9.bin`,
   `a8-mini-gimbal-0_4_12.bin` (SIYI releases; any subset) and
   `bootloader.bin` (0x3800 bytes dumped from a device at `0x08000000`, only
   needed for `bootloader=true`; `bootloader=false` works without it).
4. **qemu_mcp**:
   ```sh
   git clone https://github.com/yshestakov/qemu_mcp
   ```
5. **Register** (Claude Code; use absolute paths):
   ```sh
   claude mcp add qemu-debug \
     -e QEMU_BUILD=$HOME/qemu-n32g4fr/build \
     -e SIYI_RE=$HOME/siyi_a8_mini_re \
     -e QEMU_MCP_FIRMWARE=$HOME/a8-firmware \
     -- python3 $HOME/qemu_mcp/server.py
   ```
   Restart the client; `/mcp` should list `qemu-debug`. Other MCP clients use
   the equivalent stdio config:
   ```json
   {"mcpServers": {"qemu-debug": {
     "command": "python3", "args": ["/abs/path/qemu_mcp/server.py"],
     "env": {"QEMU_BUILD": "/abs/path/qemu-n32g4fr/build",
             "SIYI_RE": "/abs/path/siyi_a8_mini_re",
             "QEMU_MCP_FIRMWARE": "/abs/path/a8-firmware"}}}}
   ```

Environment variables: `QEMU_BUILD` (dir with `qemu-system-arm` and
`qemu-img`), or `QEMU_BIN`/`QEMU_IMG` individually; `GDB_BIN`;
`QEMU_MCP_FIRMWARE`; `SIYI_RE`; `N32G4FR_SVD` (default
`$SIYI_RE/firmware/ghidra/N32G4FR.svd`); `QEMU_MCP_RUNS` (run directories,
default `<qemu_mcp>/runs`). The server starts even with missing
dependencies; `qemu_start` then reports exactly which one is missing.

## Without MCP

`mcp_call.py` starts the server and runs tool calls given as arguments,
`NAME key=value ...` (values are JSON when they parse, else strings; `sleep
N` pauses). The environment variables above apply.

```sh
python3 mcp_call.py --list
python3 mcp_call.py 'qemu_start image=0_4_9' 'break_add location=SystemInit' \
    run_continue regs 'disas count=8' qemu_stop
```

The session lives only for one `mcp_call.py` invocation, so put a whole
scenario in one command.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `QEMU failed to start: ...` | Message from QEMU; also `<run dir>/qemu.stderr`. Usually a QEMU without `siyi-a8-mini` (wrong branch/build). |
| `cannot import internal_protocol_v2` | `SIYI_RE` does not point at a siyi_a8_mini_re checkout |
| `... a8-mini-gimbal-<ver>.bin not found` | Set `QEMU_MCP_FIRMWARE`, or pass `image=<path>` |
| `target is running: run_interrupt first` | Stop the target before inspecting it |
| `unknown symbol` | No symbol file for this image (only 0_4_9); use addresses or landmarks |
| `shell` returns no reply | USB not enumerated yet (run ~3 s first) or the target is stopped |
| `QEMU exited (end of the recording)` | Replay ran past the recording; `qemu_start mode=replay` again |
| `gdb_command` "not allowed" | Only read-only commands (`x`, `print`, `info`, `disassemble`, ...); use the typed tools for changes |

Run directory (`qemu_status` prints it): `qemu.log` (the `-d` output, also
via `qemu_log`), `qemu.stderr`, `uart{1-4,6,7}.log` (also via
`uart_output`), `flash.bin`.

## Facts about the target

- N32G4FR: Cortex-M4F, 512 KiB flash at `0x08000000`, 144 KiB SRAM at
  `0x20000000`, STM32F1-style peripherals (RCC `0x40021000`, GPIOA-E
  `0x40010800`+, DMA1/2 `0x40020000`/`0x40020400`, IWDG `0x40003000`).
- Emulated: RCC (clock-ready flags faked), DMA, SPI1-3 (SPI2: ICM-426xx IMU
  on PC10, three MA731 encoders on PB3-5), USART1-3/UART4-7, ADC (constant
  0x800), GPIO, TIM1, flash controller, IWDG, PWR, AFIO, USB device with a
  built-in CDC-ACM host, UID/UCID. Not emulated: SAC crypto, EXTI, RTC,
  I2C, other timers (accesses show with `qemu_log`).
- Serial ports: UART5 = encoder board/camera SoC link, USB VCP = firmware
  shell; the others are logged to `uart<n>.log`.
- The IWDG cannot expire while the target is stopped (virtual clock).
