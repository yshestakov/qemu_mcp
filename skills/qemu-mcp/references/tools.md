# qemu-debug tool reference

Generated from the server's `tools/list`. All arguments are optional unless marked *required*. Tool names are prefixed `mcp__qemu-debug__` in Claude Code.

## Session

### `qemu_start`

Start QEMU (-M siyi-a8-mini) with the firmware, halted at reset by default, and attach gdb, QMP, the UART5 encoder-board peer (answers the 6b/13 handshake) and the USB shell. Stops a running session. mode=record records an execution for deterministic replay; mode=replay replays it with reverse_step/reverse_continue.

| Argument | Type | Description |
|---|---|---|
| `image` | string | 0_4_3, 0_4_9 (default, has symbols), 0_4_12, or a path to a raw flash image starting at 0x08000000 |
| `bootloader` | boolean | Use the real bootloader (default true). False: zeroed bootloader area, VTOR preset to the app at 0x08003800 |
| `halted` | boolean | Stay halted at the reset vector (default true) |
| `uid` | string | UID, 24 hex digits (bytes in address order) |
| `ucid` | string | UCID, 32 hex digits |
| `vtor` | string | Reset VTOR for a custom image path |
| `icount` | string | Deterministic instruction counting: 'auto' or a shift 0-10 (normal mode only; record/replay always use it) |
| `mode` | string (normal, record, replay) |  |
| `recording` | string | Recording name for record/replay (default 'default') |
| `auto_handshake` | boolean | Answer the MCU's 6b/13 handshake (default true) |
| `camera_fw` | string | Camera fw word in the handshake reply (default 0x00010203) |
| `debug_flags` | string | QEMU -d items (default unimp,guest_errors,cpu_reset) |

### `qemu_stop`

Stop QEMU and gdb.

### `qemu_status`

Session state, current stop location, QMP events (RESET, WATCHDOG, ...), handshake state.

### `qemu_reset`

System reset (like the reset pin). The run state (stopped/running) is kept; not available in record/replay.

## Breakpoints and watchpoints

### `break_add`

Add a breakpoint (code) at an address or symbol.

| Argument | Type | Description |
|---|---|---|
| `location` *required* | string | Address (0x...), symbol, or symbol+offset |
| `condition` | string | gdb condition, e.g. $r0 == 1 |
| `temporary` | boolean |  |

### `watch_add`

Add a data watchpoint on an address (stops after the access; pc is the instruction after it).

| Argument | Type | Description |
|---|---|---|
| `location` *required* | string | Address (0x...), symbol, or symbol+offset |
| `size` | integer (1, 2, 4) |  |
| `access` | string (write, read, access) |  |

### `break_list`

List breakpoints and watchpoints.

### `break_delete`

Delete a breakpoint/watchpoint by number, or all.

| Argument | Type | Description |
|---|---|---|
| `number` *required* | string | number or 'all' |

## Run control

### `run_continue`

Resume execution and wait up to timeout_s for a stop (breakpoint, watchpoint, fault...). Returns 'running' if none.

| Argument | Type | Description |
|---|---|---|
| `timeout_s` | number | Seconds to wait for a stop (default 5, max 120) |

### `run_wait`

Wait up to timeout_s for a running target to stop.

| Argument | Type | Description |
|---|---|---|
| `timeout_s` | number | Seconds to wait for a stop (default 5, max 120) |

### `run_interrupt`

Halt a running target.

### `run_step`

Execute count instructions (stepi), or step over calls (nexti) with over=true.

| Argument | Type | Description |
|---|---|---|
| `count` | integer |  |
| `over` | boolean |  |

### `reverse_step`

Replay mode only: step count instructions backwards.

| Argument | Type | Description |
|---|---|---|
| `count` | integer |  |

### `reverse_continue`

Replay mode only: run backwards to the previous breakpoint/watchpoint hit (or the start of the recording).

| Argument | Type | Description |
|---|---|---|
| `timeout_s` | number | Seconds to wait for a stop (default 5, max 120) |

## Inspection

### `regs`

Core registers (r0-r12, sp, lr, pc, xpsr; all=true adds msp/psp/primask/basepri/faultmask/control and FPU registers).

| Argument | Type | Description |
|---|---|---|
| `all` | boolean |  |

### `reg_write`

Set a core register.

| Argument | Type | Description |
|---|---|---|
| `name` *required* | string |  |
| `value` *required* | string |  |

### `mem_read`

Read memory (target must be stopped). Reading peripheral data registers can have side effects (e.g. pops a FIFO).

| Argument | Type | Description |
|---|---|---|
| `location` *required* | string | Address (0x...), symbol, or symbol+offset |
| `length` | integer | bytes, max 4096 |
| `format` | string (words, bytes, ascii) |  |

### `mem_write`

Write bytes to memory: RAM, a peripheral register, or flash (a debugger write, e.g. 7047 = bx lr to stub out a function; it is not written back to the flash file).

| Argument | Type | Description |
|---|---|---|
| `location` *required* | string | Address (0x...), symbol, or symbol+offset |
| `hex` *required* | string | bytes as hex |

### `disas`

Disassemble count instructions (Thumb) from an address (default pc), with symbol names.

| Argument | Type | Description |
|---|---|---|
| `location` | string | Address (0x...), symbol, or symbol+offset |
| `count` | integer |  |

### `backtrace`

Call stack. The ELFs have no frame info, so besides gdb's unwind this decodes an exception frame (EXC_RETURN in lr) and scans the stack for return addresses that follow a BL/BLX.

| Argument | Type | Description |
|---|---|---|
| `scan_words` | integer | stack words to scan (default 128) |

### `fault_info`

Decode the Cortex-M fault state: CFSR/HFSR/MMFAR/BFAR, ICSR active/pending exception.

### `svd`

Peripheral registers decoded from N32G4FR.svd (target must be stopped). No peripheral: list them. Data registers with read side effects are skipped unless named.

| Argument | Type | Description |
|---|---|---|
| `peripheral` | string |  |
| `registers` | array/string | register names (prefix optional) |
| `all_fields` | boolean |  |

### `sym_lookup`

Resolve a symbol to its address, an address to name+offset, or search symbol names by substring.

| Argument | Type | Description |
|---|---|---|
| `query` *required* | string |  |

### `gdb_command`

Run a read-only gdb console command (x, print, output, info, disassemble, ptype, whatis, bt, frame, display, show). Other commands and $_shell are rejected.

| Argument | Type | Description |
|---|---|---|
| `command` *required* | string |  |

## Board

### `sensor_get`

Read the board's sensor properties: device 'imu' (accel-x/y/z mg, gyro-x/y/z mdps, temperature m-degC) or 'encoder[0..2]' (angle, 0-65535). Gravity on +Y reads level.

| Argument | Type | Description |
|---|---|---|
| `device` *required* | string |  |

### `sensor_set`

Set a sensor property (see sensor_get). Works while running; not in record/replay.

| Argument | Type | Description |
|---|---|---|
| `device` *required* | string |  |
| `property` *required* | string |  |
| `value` *required* | integer |  |

### `link_frames`

Frames the MCU sent on UART5 (to the encoder board) since the last call; identical consecutive frames are collapsed.

| Argument | Type | Description |
|---|---|---|
| `max` | integer |  |
| `keep` | boolean | do not clear the buffer |

### `link_send`

Send a frame to the MCU as the encoder board (0x2C). get=true sets need_ack (a request; the MCU answers with the same id).

| Argument | Type | Description |
|---|---|---|
| `action_id` *required* | string |  |
| `payload_hex` | string |  |
| `get` | boolean |  |
| `func` | string | default 0x6b |

### `shell`

Run a firmware shell command over the USB VCP (help, sys, fw, cpu, task_info, show_temp, ...). The target must be running.

| Argument | Type | Description |
|---|---|---|
| `command` *required* | string |  |
| `wait_s` | number |  |

### `uart_output`

Bytes the firmware wrote to USART1-3/UART4/6/7 (UART5 is the encoder link, see link_frames).

| Argument | Type | Description |
|---|---|---|
| `port` *required* | integer |  |
| `tail` | integer |  |

### `qemu_log`

QEMU -d log (unimplemented devices, guest errors, resets), duplicates counted.

| Argument | Type | Description |
|---|---|---|
| `lines` | integer |  |
| `grep` | string |  |

