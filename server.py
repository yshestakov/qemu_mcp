#!/usr/bin/env python3
"""MCP server: debug the SIYI A8 mini gimbal firmware on QEMU's siyi-a8-mini.

Standard library only.  Speaks MCP (JSON-RPC 2.0, newline-delimited) on
stdio and owns one debug session at a time:

    QEMU (build/qemu-system-arm -M siyi-a8-mini, always from a pflash image)
      <- GDB/MI (gdb-multiarch, persistent)  via the gdbstub on 127.0.0.1
      <- QMP (unix socket in a private temp dir) for reset, sensors, events
      <- UART5 encoder-board peer (protocol v2, answers the 6b/13 handshake)
      <- USB VCP firmware shell (protocol v2 func 0xF0 id 0x07)
    UART1-4/6/7 output goes to files in the run directory.

Design points:
  * Run control never blocks for long: run_continue returns the stop
    reason or "still running" after timeout_s; run_wait / run_interrupt
    follow up.
  * The ELFs have no symbols; addresses are resolved here from Ghidra
    exports in syms/<version>.txt (only 0.4.9 exists), in both
    directions (break_add main, FUN_08033c70+0x10; pc <name+off>).
  * Determinism: icount=auto|<shift>; mode=record/replay uses QEMU
    record/replay (flash as qcow2 behind blkreplay, snapshot "init") and
    enables reverse_step / reverse_continue in replay.
  * Security: no free-form QEMU arguments, no raw QMP/HMP, the gdbstub,
    chardevs and QMP listen on localhost / a private directory, gdb runs
    with -nx and auto-load off, gdb_command only accepts an allow-list of
    read-only commands and rejects $_shell.

Configuration (environment; defaults fit a checkout at <qemu>/.tmp/qemu_mcp):
    QEMU_BUILD         QEMU build dir with qemu-system-arm and qemu-img
                       (a tree with the siyi-a8-mini machine)
    QEMU_BIN, QEMU_IMG override the two binaries individually
    GDB_BIN            gdb with ARM support (default gdb-multiarch)
    QEMU_MCP_FIRMWARE  dir with a8-mini-gimbal-<ver>.bin and bootloader.bin
    SIYI_RE            siyi_a8_mini_re checkout (protocol v2 module, SVD)
    N32G4FR_SVD        SVD file (default $SIYI_RE/firmware/ghidra/N32G4FR.svd)
    QEMU_MCP_RUNS      run directories (default <this dir>/runs)

Register with Claude Code:
    claude mcp add qemu-debug -e QEMU_BUILD=... -e QEMU_MCP_FIRMWARE=... \
        -e SIYI_RE=... -- python3 /path/to/qemu_mcp/server.py
"""
import collections
import ctypes
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
# Original layout: this directory is <qemu>/.tmp/qemu_mcp
_TMP = os.path.dirname(HERE)
QEMU_BUILD = os.environ.get("QEMU_BUILD",
                            os.path.join(os.path.dirname(_TMP), "build"))
QEMU = os.environ.get("QEMU_BIN", os.path.join(QEMU_BUILD, "qemu-system-arm"))
QEMU_IMG = os.environ.get("QEMU_IMG", os.path.join(QEMU_BUILD, "qemu-img"))
GDB = os.environ.get("GDB_BIN", shutil.which("gdb-multiarch") or "gdb")
FIRMWARE = os.environ.get("QEMU_MCP_FIRMWARE", _TMP)
SIYI_RE = os.environ.get("SIYI_RE", os.path.join(_TMP, "siyi_a8_mini_re"))
os.environ.setdefault("SIYI_RE", SIYI_RE)       # for gdb_svd.DEFAULT_SVD
RUNS = os.environ.get("QEMU_MCP_RUNS", os.path.join(HERE, "runs"))
IMAGES = os.path.join(RUNS, "images")

sys.path.insert(0, HERE)
import gdb_svd  # noqa: E402

try:
    sys.path.insert(0, os.path.join(SIYI_RE, "firmware", "scripts"))
    from internal_protocol_v2 import (InterProtoV2Packet, pack_packet,
                                      parse_header, unpack_packet)
    PROTO_ERROR = None
except ImportError as e:
    # Reported by qemu_start, so the server itself still comes up
    PROTO_ERROR = (f"cannot import internal_protocol_v2 from {SIYI_RE}"
                   f"/firmware/scripts ({e}); set SIYI_RE to a "
                   "siyi_a8_mini_re checkout")

VERSIONS = ("0_4_3", "0_4_9", "0_4_12")
FLASH_BASE, FLASH_SIZE = 0x08000000, 0x80000
APP_BASE = 0x08003800
BOOT_SIZE = APP_BASE - FLASH_BASE
APP_VALID_OFF, APP_VALID = 0x7F800, 0x55AA55AA
MCU, ENCODER_BOARD, PC_USB = 0x2E, 0x2C, 0xD0

# Per-version breakpoint landmarks (AGENTS.md)
LANDMARKS = {
    "0_4_3": {"SystemInit": 0x0801634C, "dma_wait_loop": 0x0801544A},
    "0_4_9": {"SystemInit": 0x08017518, "dma_wait_loop": 0x08015E0E},
    "0_4_12": {"SystemInit": 0x080171A8, "dma_wait_loop": 0x08015ACA},
}
COMMON_LANDMARKS = {"bootloader_reset": 0x080001AC, "Reset_Handler": 0x080039C0,
                    "SystemInit_return": 0x080039C4, "__main": 0x08003998}

LINK_NAMES = {
    0x01: "control?", 0x0B: "get_camera_config", 0x0D: "led_sta",
    0x0E: "get_ip_response", 0x13: "version handshake", 0x14: "app_log_set",
    0x15: "motion_mode", 0x17: "mounting_dir", 0x1C: "turn_down",
    0x1F: "turn_down", 0x2E: "led_sta", 0x35: "send_to_uart_sdk_link",
    0x36: "control? (same handler as 01)", 0x3F: "osd_data_transfer",
    0x41: "osd_data_transfer", 0x42: "transfer_osd_status",
    0x48: "transfer_osd_status", 0x50: "attitude",
}

# gdb console commands gdb_command accepts (first word); all read-only
GDB_ALLOWED = {"x", "print", "p", "output", "info", "i", "disassemble",
               "ptype", "whatis", "bt", "backtrace", "where", "frame", "f",
               "display", "undisplay", "show"}


def log(msg):
    print(f"[qemu-mcp] {msg}", file=sys.stderr, flush=True)


def _pdeathsig():
    """Children die with the server (no stray QEMU holding ports)."""
    try:
        ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGTERM)
    except OSError:
        pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def num(v):
    if isinstance(v, int):
        return v
    return int(str(v), 0)


class ToolError(Exception):
    pass


# --------------------------------------------------------------------------
# GDB/MI


class MIParser:
    """Values of GDB/MI output records (c-strings, tuples, lists)."""

    def __init__(self, s):
        self.s, self.i = s, 0

    def cstring(self):
        assert self.s[self.i] == '"'
        self.i += 1
        out = []
        while True:
            c = self.s[self.i]
            if c == '"':
                self.i += 1
                return "".join(out)
            if c == "\\":
                self.i += 1
                c = self.s[self.i]
                if c in "01234567":
                    j = self.i
                    while j < self.i + 3 and self.s[j] in "01234567":
                        j += 1
                    out.append(chr(int(self.s[self.i:j], 8)))
                    self.i = j
                    continue
                out.append({"n": "\n", "t": "\t", "r": "\r"}.get(c, c))
            else:
                out.append(c)
            self.i += 1

    def value(self):
        c = self.s[self.i]
        if c == '"':
            return self.cstring()
        if c == "{":
            self.i += 1
            d = {}
            if self.s[self.i] == "}":
                self.i += 1
                return d
            while True:
                k, v = self.result()
                d[k] = v
                c = self.s[self.i]
                self.i += 1
                if c == "}":
                    return d
        if c == "[":
            self.i += 1
            items = []
            if self.s[self.i] == "]":
                self.i += 1
                return items
            while True:
                if self.s[self.i] in '"{[':
                    items.append(self.value())
                else:
                    items.append(self.result()[1])
                c = self.s[self.i]
                self.i += 1
                if c == "]":
                    return items
        raise ValueError(f"bad MI value at {self.i}: {self.s[self.i:self.i + 20]}")

    def result(self):
        j = self.s.index("=", self.i)
        k = self.s[self.i:j]
        self.i = j + 1
        return k, self.value()

    def results(self):
        d = {}
        while self.i < len(self.s) and self.s[self.i] == ",":
            self.i += 1
            k, v = self.result()
            d[k] = v
        return d


def mi_quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Gdb:
    def __init__(self, elf, port, cwd):
        self.proc = subprocess.Popen(
            [GDB, "--interpreter=mi3", "-nx", "-q",
             "-iex", "set auto-load off", "-iex", "set history save off"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, cwd=cwd, bufsize=1,
            preexec_fn=_pdeathsig)
        self.token = 0
        self.results = {}
        self.console = collections.defaultdict(list)
        self.current = None           # token whose console output we collect
        self.cond = threading.Condition()
        self.running = False
        self.last_stop = None
        self.stop_seq = 0
        self.alive = True
        threading.Thread(target=self._reader, daemon=True).start()
        for c in ("-gdb-set mi-async on", "-gdb-set confirm off",
                  "-gdb-set pagination off", "-gdb-set height 0",
                  "-gdb-set width 0", "-gdb-set arm force-mode thumb",
                  "-gdb-set arm fallback-mode thumb",
                  "-gdb-set can-use-hw-watchpoints 1"):
            self.cmd(c)
        self.cmd(f"-file-exec-and-symbols {mi_quote(elf)}")
        self.cmd(f"-target-select remote 127.0.0.1:{port}", timeout=15)
        with self.cond:
            self.running = False

    def _reader(self):
        for line in self.proc.stdout:
            line = line.rstrip("\n")
            if not line or line == "(gdb) ":
                continue
            m = re.match(r"(\d*)([\^*+=~@&])(.*)", line)
            if not m:
                continue
            tok, kind, rest = m.groups()
            with self.cond:
                if kind in "~@&":
                    try:
                        text = MIParser(rest).cstring()
                    except Exception:
                        text = rest
                    if kind == "~" and self.current is not None:
                        self.console[self.current].append(text)
                    elif kind in "&@" and self.current is not None:
                        self.console[self.current].append(text)
                    continue
                cls, _, tail = rest.partition(",")
                try:
                    res = MIParser("," + tail).results() if tail else {}
                except Exception as e:
                    res = {"_raw": tail, "_parse_error": str(e)}
                if kind == "^":
                    self.results[tok] = (cls, res)
                elif kind == "*":
                    if cls == "running":
                        self.running = True
                    elif cls == "stopped":
                        self.running = False
                        self.last_stop = res
                        self.stop_seq += 1
                self.cond.notify_all()
        with self.cond:
            self.alive = False
            self.cond.notify_all()

    def cmd(self, command, timeout=10):
        """Send an MI command; returns (results, console text)."""
        with self.cond:
            if not self.alive:
                raise ToolError("gdb is not running")
            self.token += 1
            tok = str(self.token)
            self.current = tok
            self.proc.stdin.write(f"{tok}{command}\n")
            self.proc.stdin.flush()
            end = time.monotonic() + timeout
            while tok not in self.results:
                left = end - time.monotonic()
                if left <= 0 or not self.alive:
                    raise ToolError(f"gdb did not answer {command!r}")
                self.cond.wait(left)
            cls, res = self.results.pop(tok)
            text = "".join(self.console.pop(tok, []))
            self.current = None
        if cls == "error":
            raise ToolError(f"gdb: {res.get('msg', res)}")
        return res, text

    def console_cmd(self, command, timeout=10):
        return self.cmd(f"-interpreter-exec console {mi_quote(command)}",
                        timeout)[1]

    def wait_stop(self, seq, timeout):
        with self.cond:
            end = time.monotonic() + timeout
            while self.stop_seq == seq and self.alive:
                left = end - time.monotonic()
                if left <= 0:
                    return False
                self.cond.wait(left)
            return self.stop_seq != seq

    def close(self):
        try:
            self.proc.stdin.write("-gdb-exit\n")
            self.proc.stdin.flush()
            self.proc.wait(2)
        except Exception:
            self.proc.kill()


# --------------------------------------------------------------------------
# QMP


class Qmp:
    def __init__(self, path, proc, timeout=15):
        end = time.monotonic() + timeout
        while True:
            try:
                self.sock = socket.socket(socket.AF_UNIX)
                self.sock.connect(path)
                break
            except OSError:
                self.sock.close()
                if proc.poll() is not None or time.monotonic() > end:
                    raise ToolError("QMP socket did not appear")
                time.sleep(0.05)
        self.f = self.sock.makefile("rw")
        self.f.readline()                    # greeting
        self.lock = threading.Lock()
        self.cond = threading.Condition()
        self.replies = {}
        self.events = collections.deque(maxlen=200)
        self.next_id = 0
        threading.Thread(target=self._reader, daemon=True).start()
        self.execute("qmp_capabilities")

    def _reader(self):
        try:
            for line in self.f:
                msg = json.loads(line)
                with self.cond:
                    if "event" in msg:
                        self.events.append(msg)
                    elif "id" in msg:
                        self.replies[msg["id"]] = msg
                    self.cond.notify_all()
        except (OSError, ValueError):
            pass

    def execute(self, cmd, args=None, timeout=10):
        with self.lock:
            self.next_id += 1
            i = self.next_id
            msg = {"execute": cmd, "id": i}
            if args:
                msg["arguments"] = args
            try:
                self.f.write(json.dumps(msg) + "\n")
                self.f.flush()
            except OSError:
                raise ToolError("QMP connection closed (QEMU exited)")
        with self.cond:
            end = time.monotonic() + timeout
            while i not in self.replies:
                left = end - time.monotonic()
                if left <= 0:
                    raise ToolError(f"QMP {cmd} timed out")
                self.cond.wait(left)
            r = self.replies.pop(i)
        if "error" in r:
            raise ToolError(f"QMP {cmd}: {r['error'].get('desc')}")
        return r.get("return")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# Protocol v2 peers (UART5 encoder board, USB VCP shell)


def split_frames(buf):
    """Pop complete protocol v2 packets from a bytearray."""
    out = []
    while True:
        i = buf.find(0xAA)
        if i < 0:
            buf.clear()
            return out
        del buf[:i]
        if len(buf) < 4:
            return out
        try:
            n = parse_header(bytes(buf[:4])).expected_packet_length
        except ValueError:
            del buf[:1]
            continue
        if len(buf) < n:
            return out
        try:
            p = unpack_packet(bytes(buf[:n]))
        except ValueError:
            del buf[:1]
            continue
        del buf[:n]
        out.append(p)


class Peer:
    """TCP client of a QEMU chardev carrying protocol v2."""

    def __init__(self, port, src, dst, on_packet=None):
        self.src, self.dst = src, dst
        self.seq = 0
        self.on_packet = on_packet
        self.lock = threading.Lock()
        self.packets = collections.deque(maxlen=5000)
        self.sock = None
        end = time.monotonic() + 10
        while self.sock is None:
            try:
                self.sock = socket.create_connection(("127.0.0.1", port))
            except OSError:
                if time.monotonic() > end:
                    raise ToolError(f"cannot connect to chardev port {port}")
                time.sleep(0.05)
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        buf = bytearray()
        while True:
            try:
                data = self.sock.recv(4096)
            except OSError:
                return
            if not data:
                return
            buf += data
            for p in split_frames(buf):
                self.packets.append((time.monotonic(), p))
                if self.on_packet:
                    try:
                        self.on_packet(p)
                    except Exception:
                        log(traceback.format_exc())

    def send(self, func, aid, payload=b"", need_ack=False):
        pkt = InterProtoV2Packet(need_ack=need_ack, hdr_ver=2, seq=self.seq,
                                 pkt_source=self.src, pkt_dest=self.dst,
                                 action_func=func, action_id=aid,
                                 payload=payload)
        with self.lock:
            self.seq = (self.seq + 1) & 0xFFFF
            self.sock.sendall(pack_packet(pkt))

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# Symbols


class Symbols:
    def __init__(self, path=None):
        self.funcs = []           # (addr, size, name), sorted
        self.by_name = {}
        self.path = path
        self.landmarks = {}
        self.add_landmarks(COMMON_LANDMARKS)
        if path and os.path.exists(path):
            for line in open(path):
                parts = line.split(None, 3)
                if len(parts) != 4:
                    continue
                kind, a, size, name = parts
                a, name = int(a, 16), name.strip()
                if kind == "F":
                    self.funcs.append((a, int(size), name))
                self.by_name.setdefault(name.lower(), (a, name))
            self.funcs.sort()

    def add_landmarks(self, d):
        for name, addr in d.items():
            self.by_name.setdefault(name.lower(), (addr, name))
            self.landmarks[addr] = name

    def resolve(self, text):
        """Address from 0x..., decimal, name or name+off."""
        text = str(text).strip()
        m = re.fullmatch(r"\*?(.+?)\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?", text)
        base, off = m.group(1), m.group(2)
        try:
            addr = int(base, 0)
        except ValueError:
            hit = self.by_name.get(base.lower())
            if not hit:
                near = [n for k, (_, n) in self.by_name.items()
                        if base.lower() in k][:10]
                raise ToolError(f"unknown symbol {base!r}" +
                                (f"; similar: {', '.join(near)}" if near else
                                 "" if self.funcs else
                                 " (no symbol file for this image)"))
            addr = hit[0]
        return addr + (int(off, 0) if off else 0)

    def name(self, addr):
        """'name+0x..' for an address inside a known function, else ''."""
        if addr is None:
            return ""
        a = addr & ~1
        lo, hi = 0, len(self.funcs)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.funcs[mid][0] <= a:
                lo = mid + 1
            else:
                hi = mid
        if lo:
            start, size, name = self.funcs[lo - 1]
            if a < start + max(size, 2):
                return name if a == start else f"{name}+0x{a - start:x}"
        return self.landmarks.get(a, "")

    def annotate(self, text):
        def sub(m):
            n = self.name(int(m.group(0), 16))
            return f"{m.group(0)} <{n}>" if n else m.group(0)
        text = re.sub(r"\s*<_start\+\d+>", "", text)
        return re.sub(r"0x0?8[0-9a-fA-F]{6}\b", sub, text)


# --------------------------------------------------------------------------
# Session


class Session:
    def __init__(self, a):
        self.cfg = a
        self.mode = a["mode"]
        self.t0 = time.monotonic()
        self.qemu = self.gdb = self.qmp = self.link = self.shell = None
        self.handshake = None
        try:
            self._start()
        except Exception:
            self.stop()
            raise

    # image preparation ----------------------------------------------------

    def _image(self):
        a = self.cfg
        img = a["image"]
        if img in VERSIONS:
            app = read_firmware(f"a8-mini-gimbal-{img}.bin")
            if a["bootloader"]:
                boot = read_firmware("bootloader.bin")
                vtor = FLASH_BASE
            else:
                # Stand-in for the bootloader: zeros, VTOR preset to the app
                boot, vtor = bytes(BOOT_SIZE), APP_BASE
            data = bytearray(boot.ljust(BOOT_SIZE, b"\xff") + app)
            name = f"{img}-{'boot' if a['bootloader'] else 'app'}"
        else:
            data = bytearray(open(img, "rb").read())
            vtor = num(a.get("vtor") or FLASH_BASE)
            name = os.path.splitext(os.path.basename(img))[0]
        if len(data) > FLASH_SIZE:
            raise ToolError("image larger than 512 KiB flash")
        raw = bytes(data)
        data += b"\xff" * (FLASH_SIZE - len(data))
        if img in VERSIONS:
            struct.pack_into("<I", data, APP_VALID_OFF, APP_VALID)
        # ELF for gdb (architecture; memory always comes from the target)
        os.makedirs(IMAGES, exist_ok=True)
        elf = os.path.join(IMAGES, f"{name}.elf")
        rawf = os.path.join(IMAGES, f"{name}.bin")
        if not os.path.exists(elf) or open(rawf, "rb").read() != raw:
            open(rawf, "wb").write(raw)
            write_elf(elf, raw, FLASH_BASE)
        return bytes(data), vtor, elf

    def _start(self):
        a = self.cfg
        if PROTO_ERROR:
            raise ToolError(PROTO_ERROR)
        for path, hint in ((QEMU, "set QEMU_BUILD or QEMU_BIN"),
                           (GDB, "install gdb-multiarch or set GDB_BIN")):
            if not shutil.which(path):
                raise ToolError(f"{path} not found: {hint}")
        if self.mode != "normal" and not shutil.which(QEMU_IMG):
            raise ToolError(f"{QEMU_IMG} not found (needed for record/"
                            "replay): set QEMU_BUILD or QEMU_IMG")
        if self.mode == "replay":
            d = os.path.join(RUNS, f"rr-{a['recording']}")
            meta = os.path.join(d, "meta.json")
            if not os.path.exists(meta):
                raise ToolError(f"no recording {a['recording']!r} "
                                f"(qemu_start mode=record first)")
            saved = json.load(open(meta))
            # A replay must run the recorded configuration
            for k in ("image", "bootloader", "uid", "ucid", "vtor"):
                a[k] = saved.get(k)
        self.flash, self.vtor, self.elf = self._image()
        if self.mode in ("record", "replay"):
            self.dir = os.path.join(RUNS, f"rr-{a['recording']}")
        else:
            self.dir = os.path.join(RUNS, "current")
        if self.mode != "replay":
            shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir, mode=0o700, exist_ok=True)

        self.gdb_port, self.uart5_port, self.vcp_port = (free_port(),
                                                         free_port(),
                                                         free_port())
        # Unix socket paths are limited to 108 bytes: keep it short
        self.sock_dir = tempfile.mkdtemp(prefix="qemu-mcp-")
        self.qmp_path = os.path.join(self.sock_dir, "qmp.sock")

        m = f"siyi-a8-mini,vtor={self.vtor:#x}"
        for k in ("uid", "ucid"):
            if a.get(k):
                if not re.fullmatch(r"[0-9a-fA-F]+", a[k]):
                    raise ToolError(f"{k} must be hex digits")
                m += f",{k}={a[k]}"
        args = [QEMU, "-M", m, "-nographic", "-monitor", "none",
                "-qmp", f"unix:{self.qmp_path},server=on,wait=off",
                "-gdb", f"tcp:127.0.0.1:{self.gdb_port}", "-S",
                "-d", a["debug_flags"] or "guest_errors",
                "-D", os.path.join(self.dir, "qemu.log")]
        if a["debug_flags"] and not re.fullmatch(r"[a-z_,]+", a["debug_flags"]):
            raise ToolError("debug_flags must be a comma list of -d items")
        for i in range(1, 8):
            if i == 5:
                args += ["-serial", f"tcp:127.0.0.1:{self.uart5_port},"
                                    "server=on,wait=off"]
            else:
                args += ["-serial", f"file:{os.path.join(self.dir, f'uart{i}.log')}"]
        args += ["-serial", f"tcp:127.0.0.1:{self.vcp_port},server=on,wait=off"]

        if self.mode == "normal":
            flash = os.path.join(self.dir, "flash.bin")
            open(flash, "wb").write(self.flash)
            args += ["-drive", f"if=pflash,format=raw,file={flash}"]
            if a.get("icount") is not None:
                ic = str(a["icount"])
                if not re.fullmatch(r"auto|\d+", ic):
                    raise ToolError("icount must be 'auto' or a shift 0-10")
                args += ["-icount", f"shift={ic}"]
        else:
            q = os.path.join(self.dir, "flash.qcow2")
            if self.mode == "record":
                raw = os.path.join(self.dir, "flash.bin")
                open(raw, "wb").write(self.flash)
                subprocess.run([QEMU_IMG, "convert", "-f", "raw", "-O", "qcow2",
                                raw, q], check=True)
                os.unlink(raw)
                json.dump({k: a.get(k) for k in ("image", "bootloader", "uid",
                                                 "ucid", "vtor")},
                          open(os.path.join(self.dir, "meta.json"), "w"))
            args += ["-icount", f"shift=auto,rr={self.mode},rrfile="
                     f"{os.path.join(self.dir, 'replay.bin')},rrsnapshot=init",
                     "-drive", f"file={q},if=none,id=img-direct",
                     "-drive", "driver=blkreplay,if=pflash,image=img-direct"]

        self.args = args
        self.stderr = open(os.path.join(self.dir, "qemu.stderr"), "w")
        self.qemu = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                                     stdout=self.stderr, stderr=self.stderr,
                                     cwd=self.dir, start_new_session=True,
                                     preexec_fn=_pdeathsig)
        try:
            self.qmp = Qmp(self.qmp_path, self.qemu)
        except ToolError:
            raise ToolError("QEMU failed to start:\n" + self.qemu_stderr())

        ver = a["image"] if a["image"] in VERSIONS else None
        self.syms = Symbols(os.path.join(HERE, "syms", f"{ver}.txt")
                            if ver else None)
        if ver:
            self.syms.add_landmarks(LANDMARKS[ver])

        # The chardev peers connect before the guest runs (-S)
        if self.mode != "replay":
            self.link = Peer(self.uart5_port, ENCODER_BOARD, MCU,
                             self._link_packet)
            self.shell = Peer(self.vcp_port, PC_USB, MCU)
        self.gdb = Gdb(self.elf, self.gdb_port, self.dir)
        if not a["halted"]:
            self.cont(0)

    def _link_packet(self, p):
        a = self.cfg
        if (p.action_func == 0x6B and p.action_id == 0x13 and p.need_ack
                and a["auto_handshake"]):
            self.link.send(0x6B, 0x13, struct.pack("<IB", num(a["camera_fw"]),
                                                   0))
            if self.handshake is None and len(p.payload) >= 8:
                self.handshake = struct.unpack_from("<II", p.payload)

    def qemu_stderr(self):
        try:
            self.stderr.flush()
            return open(self.stderr.name).read()[-2000:]
        except OSError:
            return ""

    def alive(self, grace=0):
        """QEMU still running; grace: seconds to wait for an exit in
        progress (gdb sees the disconnect before the process is gone)."""
        if self.qemu is None:
            return False
        try:
            self.qemu.wait(grace)
            return False
        except subprocess.TimeoutExpired:
            return True

    def stop(self):
        for p in (self.link, self.shell):
            if p:
                p.close()
        if self.gdb:
            self.gdb.close()
        if self.qmp and self.alive():
            try:
                self.qmp.execute("quit", timeout=2)
            except ToolError:
                pass
        if self.qmp:
            self.qmp.close()
        if self.qemu:
            try:
                self.qemu.wait(3)
            except subprocess.TimeoutExpired:
                self.qemu.kill()
                self.qemu.wait()
        if getattr(self, "sock_dir", None):
            shutil.rmtree(self.sock_dir, ignore_errors=True)

    # run control ----------------------------------------------------------

    def need_stopped(self):
        if not self.alive():
            raise ToolError(self.exited())
        if self.gdb.running:
            raise ToolError("target is running: run_interrupt first")

    def describe_stop(self):
        st = self.gdb.last_stop or {}
        reason = st.get("reason", "halted")
        if reason == "signal-received":
            reason += f" ({st.get('signal-name')})"
        if "bkptno" in st:
            reason += f" #{st['bkptno']}"
        if "wpt" in st or "hw-awpt" in st or "hw-rwpt" in st:
            w = st.get("wpt") or st.get("hw-awpt") or st.get("hw-rwpt")
            reason += f" #{w.get('number')} {w.get('exp')}"
            if "value" in st:
                reason += f" {st['value']}"
        try:
            return reason + "\n" + self.brief_regs()
        except ToolError:
            if self.alive(grace=3):
                raise
            return self.exited()

    def exited(self):
        end = (" (end of the recording)" if self.mode == "replay" else "")
        return (f"QEMU exited{end}, code {self.qemu.wait()}; qemu_start to "
                f"begin again\n" + self.qemu_stderr()).rstrip()

    def brief_regs(self):
        r = self.read_regs(["pc", "sp", "lr", "xpsr"])
        pc = r.get("pc")
        out = [f"pc  {pc:#010x} {self.syms.name(pc)}",
               f"lr  {r.get('lr', 0):#010x} {self.syms.name(r.get('lr'))}",
               f"sp  {r.get('sp', 0):#010x}"]
        ipsr = r.get("xpsr", 0) & 0x1FF
        if ipsr:
            out.append(f"in exception {ipsr} ({exc_name(ipsr)})")
        return "\n".join(out)

    def read_regs(self, names=None):
        if not hasattr(self, "_regnames"):
            res, _ = self.gdb.cmd("-data-list-register-names")
            self._regnames = res["register-names"]
        res, _ = self.gdb.cmd("-data-list-register-values --skip-unavailable x")
        out = {}
        for r in res["register-values"]:
            n = self._regnames[int(r["number"])]
            if n and (names is None or n in names):
                try:
                    out[n] = int(r["value"], 16)
                except ValueError:
                    pass
        return out

    def cont(self, timeout, reverse=False):
        if not self.alive():
            raise ToolError("QEMU has exited:\n" + self.qemu_stderr())
        if self.gdb.running:
            return self.wait(timeout)
        seq = self.gdb.stop_seq
        self.gdb.cmd("-exec-continue" + (" --reverse" if reverse else ""))
        return self._wait_seq(seq, timeout)

    def _wait_seq(self, seq, timeout):
        if timeout and self.gdb.wait_stop(seq, timeout):
            return "stopped: " + self.describe_stop()
        if not self.alive():
            return self.exited()
        return (f"running (no stop within {timeout}s); use run_wait or "
                "run_interrupt")

    def wait(self, timeout):
        if not self.gdb.running:
            return "stopped: " + self.describe_stop()
        return self._wait_seq(self.gdb.stop_seq, timeout)

    def interrupt(self):
        if not self.gdb.running:
            return "already stopped: " + self.describe_stop()
        seq = self.gdb.stop_seq
        self.gdb.cmd("-exec-interrupt")
        if not self.gdb.wait_stop(seq, 10):
            raise ToolError("target did not stop")
        return "stopped: " + self.describe_stop()

    def step(self, count, over, reverse=False):
        self.need_stopped()
        seq = self.gdb.stop_seq
        cmd = ("reverse-" if reverse else "") + ("nexti" if over else "stepi")
        self.gdb.console_cmd(f"{cmd} {count}")
        self.gdb.wait_stop(seq, 30)
        return "stopped: " + self.describe_stop()

    def read_mem(self, addr, length):
        self.need_stopped()
        res, _ = self.gdb.cmd(f"-data-read-memory-bytes {addr:#x} {length}")
        out = bytearray()
        for blk in res["memory"]:
            out += bytes.fromhex(blk["contents"])
        if len(out) < length:
            raise ToolError(f"only {len(out)} of {length} bytes readable at "
                            f"{addr:#x}")
        return bytes(out)


def read_firmware(name):
    path = os.path.join(FIRMWARE, name)
    if not os.path.exists(path):
        raise ToolError(f"{path} not found: set QEMU_MCP_FIRMWARE to the "
                        "directory with a8-mini-gimbal-<ver>.bin and "
                        "bootloader.bin, or pass image=<flash image path>")
    return open(path, "rb").read()


def write_elf(path, data, base):
    """Minimal ELF32 ARM executable: one loadable .text holding data.

    gdb only needs it for the architecture (memory and code are always
    read from the target); the entry is the image's reset vector.
    """
    shstr = b"\0.text\0.shstrtab\0"
    ehsize, phsize, shsize = 52, 32, 40
    text_off = ehsize + phsize
    shstr_off = text_off + len(data)
    sh_off = (shstr_off + len(shstr) + 3) & ~3
    entry = struct.unpack_from("<I", data, 4)[0] if len(data) >= 8 else base
    eh = struct.pack("<16sHHIIIIIHHHHHH",
                     b"\x7fELF\x01\x01\x01" + bytes(9), 2, 40, 1, entry,
                     ehsize, sh_off, 0x05000000, ehsize, phsize, 1,
                     shsize, 3, 2)
    ph = struct.pack("<IIIIIIII", 1, text_off, base, base, len(data),
                     len(data), 5, 4)
    sh = (bytes(shsize)
          + struct.pack("<IIIIIIIIII", 1, 1, 6, base, text_off, len(data),
                        0, 0, 4, 0)
          + struct.pack("<IIIIIIIIII", 7, 3, 0, 0, shstr_off, len(shstr),
                        0, 0, 1, 0))
    with open(path, "wb") as f:
        f.write(eh + ph + data + shstr)
        f.write(bytes(sh_off - shstr_off - len(shstr)) + sh)


EXC_NAMES = {1: "Reset", 2: "NMI", 3: "HardFault", 4: "MemManage",
             5: "BusFault", 6: "UsageFault", 11: "SVCall", 12: "DebugMon",
             14: "PendSV", 15: "SysTick"}


def exc_name(n):
    return EXC_NAMES.get(n, f"IRQ{n - 16}" if n >= 16 else "reserved")


# --------------------------------------------------------------------------
# Tools

TOOLS = {}
SESSION = None


def tool(name, desc, props=None, required=()):
    def deco(fn):
        TOOLS[name] = {"fn": fn, "schema": {
            "name": name, "description": desc,
            "inputSchema": {"type": "object", "properties": props or {},
                            "required": list(required)}}}
        return fn
    return deco


def S():
    if SESSION is None:
        raise ToolError("no session: call qemu_start first")
    return SESSION


ADDR = {"type": "string",
        "description": "Address (0x...), symbol, or symbol+offset"}


@tool("qemu_start",
      "Start QEMU (-M siyi-a8-mini) with the firmware, halted at reset by "
      "default, and attach gdb, QMP, the UART5 encoder-board peer (answers "
      "the 6b/13 handshake) and the USB shell. Stops a running session. "
      "mode=record records an execution for deterministic replay; "
      "mode=replay replays it with reverse_step/reverse_continue.",
      {"image": {"type": "string", "description":
                 "0_4_3, 0_4_9 (default, has symbols), 0_4_12, or a path to "
                 "a raw flash image starting at 0x08000000"},
       "bootloader": {"type": "boolean", "description":
                      "Use the real bootloader (default true). False: zeroed "
                      "bootloader area, VTOR preset to the app at 0x08003800"},
       "halted": {"type": "boolean",
                  "description": "Stay halted at the reset vector (default true)"},
       "uid": {"type": "string", "description": "UID, 24 hex digits (bytes in address order)"},
       "ucid": {"type": "string", "description": "UCID, 32 hex digits"},
       "vtor": {"type": "string", "description": "Reset VTOR for a custom image path"},
       "icount": {"type": "string", "description":
                  "Deterministic instruction counting: 'auto' or a shift "
                  "0-10 (normal mode only; record/replay always use it)"},
       "mode": {"type": "string", "enum": ["normal", "record", "replay"]},
       "recording": {"type": "string",
                     "description": "Recording name for record/replay (default 'default')"},
       "auto_handshake": {"type": "boolean",
                          "description": "Answer the MCU's 6b/13 handshake (default true)"},
       "camera_fw": {"type": "string",
                     "description": "Camera fw word in the handshake reply (default 0x00010203)"},
       "debug_flags": {"type": "string", "description":
                       "QEMU -d items (default unimp,guest_errors,cpu_reset)"}})
def t_start(image="0_4_9", bootloader=True, halted=True, uid=None, ucid=None,
            vtor=None, icount=None, mode="normal", recording="default",
            auto_handshake=True, camera_fw="0x00010203",
            debug_flags="unimp,guest_errors,cpu_reset"):
    global SESSION
    if SESSION:
        SESSION.stop()
        SESSION = None
    if mode not in ("normal", "record", "replay"):
        raise ToolError("mode must be normal, record or replay")
    if not re.fullmatch(r"[\w.-]+", recording):
        raise ToolError("recording must be a simple name")
    SESSION = Session(dict(image=image, bootloader=bootloader, halted=halted,
                           uid=uid, ucid=ucid, vtor=vtor, icount=icount,
                           mode=mode, recording=recording,
                           auto_handshake=auto_handshake, camera_fw=camera_fw,
                           debug_flags=debug_flags))
    s = SESSION
    out = [f"started {s.cfg['image']} ({'bootloader' if s.cfg['bootloader'] else 'app only'}),"
           f" mode {mode}, VTOR {s.vtor:#x}, run dir {s.dir}",
           f"symbols: {len(s.syms.funcs)} functions"
           + ("" if s.syms.funcs else " (only landmarks: "
              + ", ".join(sorted(n for _, n in s.syms.by_name.values())) + ")")]
    out.append(s.wait(0) if not halted else "stopped: " + s.describe_stop())
    if mode == "replay":
        out.append("replay: serial input comes from the recording; "
                   "link_send/shell/sensor_set are disabled")
    return "\n".join(out)


@tool("qemu_stop", "Stop QEMU and gdb.")
def t_stop():
    global SESSION
    if SESSION:
        d = SESSION.dir
        SESSION.stop()
        SESSION = None
        return f"stopped (logs kept in {d})"
    return "no session"


@tool("qemu_status", "Session state, current stop location, QMP events "
      "(RESET, WATCHDOG, ...), handshake state.")
def t_status():
    s = S()
    out = [f"image {s.cfg['image']}, mode {s.mode}, up {time.monotonic() - s.t0:.1f}s,"
           f" run dir {s.dir}"]
    if not s.alive():
        out.append(s.exited())
        return "\n".join(out)
    try:
        out.append(f"QEMU status: {s.qmp.execute('query-status')['status']}")
    except ToolError:
        if s.alive(grace=3):
            raise
        out.append(s.exited())
        return "\n".join(out)
    out.append("running" if s.gdb.running else "stopped: " + s.describe_stop())
    if s.handshake:
        out.append(f"6b/13 handshake answered: MCU fw {s.handshake[0]:#010x},"
                   f" loader {s.handshake[1]:#010x}")
    ev = [f"{e['event']}{' ' + json.dumps(e.get('data')) if e.get('data') else ''}"
          for e in s.qmp.events if e["event"] not in ("STOP", "RESUME")]
    if ev:
        out.append("QMP events: " + "; ".join(ev[-20:]))
    return "\n".join(out)


@tool("qemu_reset", "System reset (like the reset pin). The run state "
      "(stopped/running) is kept; not available in record/replay.")
def t_reset():
    s = S()
    if s.mode != "normal":
        raise ToolError("reset is not recorded; restart instead")
    s.qmp.execute("system_reset")
    return "reset requested\n" + (s.describe_stop() if not s.gdb.running
                                  else "running")


@tool("break_add", "Add a breakpoint (code) at an address or symbol.",
      {"location": ADDR,
       "condition": {"type": "string", "description": "gdb condition, e.g. $r0 == 1"},
       "temporary": {"type": "boolean"}}, ["location"])
def t_break(location, condition=None, temporary=False):
    s = S()
    s.need_stopped()
    addr = s.syms.resolve(location)
    if condition and ("$_shell" in condition or "\n" in condition):
        raise ToolError("condition rejected")
    cmd = "-break-insert" + (" -t" if temporary else "")
    if condition:
        cmd += f" -c {mi_quote(condition)}"
    res, _ = s.gdb.cmd(f"{cmd} *{addr:#x}")
    b = res["bkpt"]
    return f"breakpoint {b['number']} at {addr:#010x} {s.syms.name(addr)}"


@tool("watch_add", "Add a data watchpoint on an address (stops after the "
      "access; pc is the instruction after it).",
      {"location": ADDR, "size": {"type": "integer", "enum": [1, 2, 4]},
       "access": {"type": "string", "enum": ["write", "read", "access"]}},
      ["location"])
def t_watch(location, size=4, access="write"):
    s = S()
    s.need_stopped()
    addr = s.syms.resolve(location)
    ty = {1: "unsigned char", 2: "unsigned short", 4: "unsigned int"}[int(size)]
    flag = {"write": "", "read": "-r ", "access": "-a "}[access]
    res, _ = s.gdb.cmd(f"-break-watch {flag}{mi_quote(f'*({ty} *){addr:#x}')}")
    w = next(iter(res.values()))
    return f"watchpoint {w['number']} ({access}) on {addr:#010x}"


@tool("break_list", "List breakpoints and watchpoints.")
def t_break_list():
    s = S()
    res, _ = s.gdb.cmd("-break-list")
    rows = res["BreakpointTable"].get("body", [])
    if not rows:
        return "none"
    out = []
    for b in rows:
        addr = b.get("addr", "")
        try:
            sym = s.syms.name(int(addr, 16))
        except ValueError:
            sym = ""
        out.append(f"{b['number']}: {b['type']} {addr or b.get('what', '')} "
                   f"{sym} hits={b.get('times')}"
                   + (f" if {b['cond']}" if b.get("cond") else "")
                   + ("" if b.get("enabled") == "y" else " (disabled)"))
    return "\n".join(out)


@tool("break_delete", "Delete a breakpoint/watchpoint by number, or all.",
      {"number": {"type": "string", "description": "number or 'all'"}},
      ["number"])
def t_break_delete(number):
    s = S()
    s.need_stopped()
    if str(number) == "all":
        s.gdb.cmd("-break-delete")
    else:
        s.gdb.cmd(f"-break-delete {int(number)}")
    return "deleted"


TIMEOUT = {"type": "number",
           "description": "Seconds to wait for a stop (default 5, max 120)"}


def _timeout(t, default=5):
    return max(0.0, min(float(default if t is None else t), 120.0))


@tool("run_continue", "Resume execution and wait up to timeout_s for a stop "
      "(breakpoint, watchpoint, fault...). Returns 'running' if none.",
      {"timeout_s": TIMEOUT})
def t_continue(timeout_s=None):
    return S().cont(_timeout(timeout_s))


@tool("run_wait", "Wait up to timeout_s for a running target to stop.",
      {"timeout_s": TIMEOUT})
def t_wait(timeout_s=None):
    return S().wait(_timeout(timeout_s))


@tool("run_interrupt", "Halt a running target.")
def t_interrupt():
    return S().interrupt()


@tool("run_step", "Execute count instructions (stepi), or step over calls "
      "(nexti) with over=true.",
      {"count": {"type": "integer"}, "over": {"type": "boolean"}})
def t_step(count=1, over=False):
    return S().step(max(1, min(int(count), 100000)), over)


@tool("reverse_step", "Replay mode only: step count instructions backwards.",
      {"count": {"type": "integer"}})
def t_rstep(count=1):
    s = S()
    if s.mode != "replay":
        raise ToolError("reverse execution needs mode=replay")
    return s.step(max(1, min(int(count), 100000)), False, reverse=True)


@tool("reverse_continue", "Replay mode only: run backwards to the previous "
      "breakpoint/watchpoint hit (or the start of the recording).",
      {"timeout_s": TIMEOUT})
def t_rcont(timeout_s=None):
    s = S()
    if s.mode != "replay":
        raise ToolError("reverse execution needs mode=replay")
    return s.cont(_timeout(timeout_s, 30), reverse=True)


@tool("regs", "Core registers (r0-r12, sp, lr, pc, xpsr; all=true adds "
      "msp/psp/primask/basepri/faultmask/control and FPU registers).",
      {"all": {"type": "boolean"}})
def t_regs(all=False):
    s = S()
    s.need_stopped()
    r = s.read_regs()
    core = [f"r{i}" for i in range(13)] + ["sp", "lr", "pc", "xpsr"]
    sysr = ["msp", "psp", "primask", "basepri", "faultmask", "control"]
    names = core + sysr + ([n for n in r if n not in core + sysr] if all else [])
    out = []
    for n in names:
        if n in r:
            v = r[n]
            sym = s.syms.name(v) if n in ("pc", "lr") or 0x08000000 <= v < 0x08080000 else ""
            out.append(f"{n:<9} {v:#010x} {sym}".rstrip())
    ipsr = r.get("xpsr", 0) & 0x1FF
    out.append(f"IPSR {ipsr}: {exc_name(ipsr) if ipsr else 'thread mode'}")
    return "\n".join(out)


@tool("mem_read", "Read memory (target must be stopped). Reading "
      "peripheral data registers can have side effects (e.g. pops a FIFO).",
      {"location": ADDR, "length": {"type": "integer", "description": "bytes, max 4096"},
       "format": {"type": "string", "enum": ["words", "bytes", "ascii"]}},
      ["location"])
def t_mem_read(location, length=64, format="words"):
    s = S()
    addr = s.syms.resolve(location)
    length = max(1, min(int(length), 4096))
    data = s.read_mem(addr, length)
    if format == "ascii":
        return data.decode("latin-1")
    out = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        if format == "words" and len(chunk) % 4 == 0:
            body = " ".join(f"{w:08x}" for w in struct.unpack(f"<{len(chunk) // 4}I", chunk))
        else:
            body = chunk.hex(" ")
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{addr + off:08x}: {body}  {asc}")
    return "\n".join(out)


@tool("mem_write", "Write bytes to memory: RAM, a peripheral register, or "
      "flash (a debugger write, e.g. 7047 = bx lr to stub out a function; "
      "it is not written back to the flash file).",
      {"location": ADDR, "hex": {"type": "string", "description": "bytes as hex"}},
      ["location", "hex"])
def t_mem_write(location, hex):
    s = S()
    s.need_stopped()
    addr = s.syms.resolve(location)
    data = bytes.fromhex(str(hex).replace(" ", ""))
    s.gdb.cmd(f"-data-write-memory-bytes {addr:#x} {data.hex()}")
    return f"wrote {len(data)} bytes at {addr:#010x}"


@tool("reg_write", "Set a core register.",
      {"name": {"type": "string"}, "value": {"type": "string"}},
      ["name", "value"])
def t_reg_write(name, value):
    s = S()
    s.need_stopped()
    if not re.fullmatch(r"[a-z0-9]+", name):
        raise ToolError("bad register name")
    s.gdb.cmd(f"-gdb-set ${name}={num(value)}")
    return f"{name} = {num(value):#x}"


@tool("disas", "Disassemble count instructions (Thumb) from an address "
      "(default pc), with symbol names.",
      {"location": ADDR, "count": {"type": "integer"}})
def t_disas(location=None, count=16):
    s = S()
    s.need_stopped()
    addr = (s.read_regs(["pc"])["pc"] if location is None
            else s.syms.resolve(location)) & ~1
    count = max(1, min(int(count), 200))
    res, _ = s.gdb.cmd(f"-data-disassemble -s {addr:#x} -e {addr + count * 4:#x} -- 0")
    out = []
    pc = s.read_regs(["pc"])["pc"]
    for ins in res["asm_insns"][:count]:
        a = int(ins["address"], 16)
        n = s.syms.name(a)
        label = f"<{n}>" if n and "+" not in n else ""
        if label:
            out.append(f"{label}:")
        out.append(f"{'=>' if a == pc else '  '} {a:08x}: "
                   f"{s.syms.annotate(ins['inst'])}")
    return "\n".join(out)


def _is_call_return(s, ret):
    """ret (odd) follows a BL / BLX in flash."""
    a = (ret & ~1)
    if not (FLASH_BASE + 4 <= a < FLASH_BASE + FLASH_SIZE):
        return False
    try:
        b = s.read_mem(a - 4, 4)
    except ToolError:
        return False
    hi, lo = struct.unpack("<HH", b)
    if (hi & 0xF800) == 0xF000 and (lo & 0xC000) == 0xC000:
        return True                      # BL / BLX imm (32-bit)
    return (lo & 0xFF87) == 0x4780       # BLX Rm (16-bit)


@tool("backtrace", "Call stack. The ELFs have no frame info, so besides "
      "gdb's unwind this decodes an exception frame (EXC_RETURN in lr) and "
      "scans the stack for return addresses that follow a BL/BLX.",
      {"scan_words": {"type": "integer", "description": "stack words to scan (default 128)"}})
def t_backtrace(scan_words=128):
    s = S()
    s.need_stopped()
    r = s.read_regs()
    out = [f"pc {r['pc']:#010x} {s.syms.name(r['pc'])}",
           f"lr {r['lr']:#010x} {s.syms.name(r['lr'])}"]
    sp = r["sp"]
    if (r["lr"] & 0xFFFFFF00) == 0xFFFFFF00:
        exc = r["lr"]
        frame_sp = r["psp"] if exc & 4 else r["msp"]
        f = struct.unpack("<8I", s.read_mem(frame_sp, 32))
        out.append(f"exception frame on {'PSP' if exc & 4 else 'MSP'} "
                   f"{frame_sp:#010x} (EXC_RETURN {exc:#x}"
                   f"{', FPU frame' if not exc & 0x10 else ''}):")
        out.append(f"  stacked pc {f[6]:#010x} {s.syms.name(f[6])}, "
                   f"lr {f[5]:#010x} {s.syms.name(f[5])}, xpsr {f[7]:#010x}")
        out.append(f"  r0-r3 {f[0]:#x} {f[1]:#x} {f[2]:#x} {f[3]:#x}, r12 {f[4]:#x}")
        sp = frame_sp + (0x68 if not exc & 0x10 else 0x20)
    try:
        res, _ = s.gdb.cmd("-stack-list-frames 0 15", timeout=5)
        frames = [f"#{f['level']} {f.get('addr')} {s.syms.name(int(f.get('addr', '0'), 16))}"
                  for f in res.get("stack", [])]
        out.append("gdb unwind: " + "; ".join(frames))
    except ToolError as e:
        out.append(f"gdb unwind failed: {e}")
    n = max(8, min(int(scan_words), 1024))
    try:
        words = struct.unpack(f"<{n}I", s.read_mem(sp, n * 4))
    except ToolError:
        words = ()
    hits = [(sp + i * 4, w) for i, w in enumerate(words)
            if w & 1 and _is_call_return(s, w)]
    out.append(f"stack scan from {sp:#010x} (likely return addresses):")
    out += [f"  [{a:#010x}] {w:#010x} {s.syms.name(w)}" for a, w in hits] or ["  none"]
    return "\n".join(out)


@tool("fault_info", "Decode the Cortex-M fault state: CFSR/HFSR/MMFAR/BFAR, "
      "ICSR active/pending exception.")
def t_fault():
    s = S()
    s.need_stopped()
    icsr, = struct.unpack("<I", s.read_mem(0xE000ED04, 4))
    cfsr, hfsr = struct.unpack("<II", s.read_mem(0xE000ED28, 8))
    mmfar, bfar = struct.unpack("<II", s.read_mem(0xE000ED34, 8))
    bits = {0: "IACCVIOL", 1: "DACCVIOL", 3: "MUNSTKERR", 4: "MSTKERR",
            5: "MLSPERR", 7: "MMARVALID", 8: "IBUSERR", 9: "PRECISERR",
            10: "IMPRECISERR", 11: "UNSTKERR", 12: "STKERR", 13: "LSPERR",
            15: "BFARVALID", 16: "UNDEFINSTR", 17: "INVSTATE", 18: "INVPC",
            19: "NOCP", 24: "UNALIGNED", 25: "DIVBYZERO"}
    set_bits = [n for b, n in bits.items() if cfsr >> b & 1]
    h = [n for b, n in {1: "VECTTBL", 30: "FORCED", 31: "DEBUGEVT"}.items()
         if hfsr >> b & 1]
    out = [f"ICSR  {icsr:#010x} active {exc_name(icsr & 0x1FF) if icsr & 0x1FF else 'none'},"
           f" pending {exc_name(icsr >> 12 & 0x1FF) if icsr >> 12 & 0x1FF else 'none'}",
           f"CFSR  {cfsr:#010x} {' '.join(set_bits) or '-'}",
           f"HFSR  {hfsr:#010x} {' '.join(h) or '-'}"]
    if cfsr & (1 << 7):
        out.append(f"MMFAR {mmfar:#010x}")
    if cfsr & (1 << 15):
        out.append(f"BFAR  {bfar:#010x}")
    return "\n".join(out)


SVD = None


@tool("svd", "Peripheral registers decoded from N32G4FR.svd (target must be "
      "stopped). No peripheral: list them. Data registers with read side "
      "effects are skipped unless named.",
      {"peripheral": {"type": "string"},
       "registers": {"type": ["array", "string"], "items": {"type": "string"},
                     "description": "register names (prefix optional)"},
       "all_fields": {"type": "boolean"}})
def t_svd(peripheral=None, registers=None, all_fields=False):
    global SVD
    if SVD is None:
        SVD = gdb_svd.Device(gdb_svd.DEFAULT_SVD)
    if not peripheral:
        return "\n".join(f"{p.name:<8} {p.base:#010x} {p.desc}"
                         for p in sorted(SVD.periphs.values(), key=lambda p: p.base))
    s = S()
    s.need_stopped()
    p = SVD.periphs.get(peripheral.upper())
    if not p:
        raise ToolError(f"unknown peripheral {peripheral}")
    if isinstance(registers, str):
        registers = re.findall(r"[\w]+", registers)
    if registers:
        regs = []
        for n in registers:
            r = p.find(n)
            if not r:
                raise ToolError(f"unknown register {n} in {p.name}")
            regs.append(r)
        all_fields = True
    else:
        regs = [r for r in p.registers if r.name not in gdb_svd.READ_SIDE_EFFECT]
    out = [f"{p.name} @ {p.base:#010x}"]
    for r in regs:
        addr = p.base + r.offset
        try:
            val = int.from_bytes(s.read_mem(addr, max(r.size // 8, 1)), "little")
        except ToolError:
            out.append(f"  {r.name:<16} @{addr:#010x} <unreadable>")
            continue
        out.append(f"  {r.name:<16} @{addr:#010x} = {val:#0{r.size // 4 + 2}x}")
        for f in r.fields:
            v = (val >> f.lsb) & ((1 << f.width) - 1)
            if v or all_fields:
                bits = f"[{f.lsb}]" if f.width == 1 else f"[{f.lsb + f.width - 1}:{f.lsb}]"
                out.append(f"      {f.name:<14}{bits:>8} = {v:#x}")
    return "\n".join(out)


@tool("sym_lookup", "Resolve a symbol to its address, an address to "
      "name+offset, or search symbol names by substring.",
      {"query": {"type": "string"}}, ["query"])
def t_sym(query):
    s = S()
    try:
        a = int(query, 0)
        return f"{a:#010x} {s.syms.name(a) or '(no symbol)'}"
    except ValueError:
        pass
    q = query.lower()
    hits = sorted((addr, n) for k, (addr, n) in s.syms.by_name.items() if q in k)
    if not hits:
        return "no match" + ("" if s.syms.funcs else " (no symbol file for this image)")
    more = f"\n... {len(hits) - 50} more" if len(hits) > 50 else ""
    return "\n".join(f"{a:#010x} {n}" for a, n in hits[:50]) + more


SENSORS = re.compile(r"imu|encoder\[[0-2]\]")


@tool("sensor_get", "Read the board's sensor properties: device 'imu' "
      "(accel-x/y/z mg, gyro-x/y/z mdps, temperature m-degC) or "
      "'encoder[0..2]' (angle, 0-65535). Gravity on +Y reads level.",
      {"device": {"type": "string"}}, ["device"])
def t_sensor_get(device):
    s = S()
    if not SENSORS.fullmatch(device):
        raise ToolError("device must be imu or encoder[0-2]")
    path = f"/machine/{device}"
    out = []
    for p in s.qmp.execute("qom-list", {"path": path}):
        if p["type"] in ("int", "uint32", "uint16", "int32", "uint8", "int16"):
            out.append(f"{p['name']} = {s.qmp.execute('qom-get', {'path': path, 'property': p['name']})}")
    return "\n".join(out)


@tool("sensor_set", "Set a sensor property (see sensor_get). Works while "
      "running; not in record/replay.",
      {"device": {"type": "string"}, "property": {"type": "string"},
       "value": {"type": "integer"}}, ["device", "property", "value"])
def t_sensor_set(device, property, value):
    s = S()
    if s.mode != "normal":
        raise ToolError("sensor changes are not recorded; use mode=normal")
    if not SENSORS.fullmatch(device):
        raise ToolError("device must be imu or encoder[0-2]")
    path = f"/machine/{device}"
    names = {p["name"] for p in s.qmp.execute("qom-list", {"path": path})}
    if property not in names or property in ("type", "parent_bus", "realized"):
        raise ToolError(f"unknown property {property}")
    s.qmp.execute("qom-set", {"path": path, "property": property, "value": int(value)})
    return f"{device}.{property} = {int(value)}"


def _fmt_packet(t0, t, p):
    name = LINK_NAMES.get(p.action_id, "") if p.action_func == 0x6B else ""
    extra = ""
    if p.action_func == 0x6B and p.action_id == 0x50 and len(p.payload) == 6:
        extra = " angles " + ", ".join(f"{v / 10:.1f}" for v in struct.unpack("<3h", p.payload))
    return (f"{t - t0:8.3f} {p.action_func:02x}/{p.action_id:02x} "
            f"ack={int(p.need_ack)} {p.payload.hex()} {name}{extra}").rstrip()


@tool("link_frames", "Frames the MCU sent on UART5 (to the encoder board) "
      "since the last call; identical consecutive frames are collapsed.",
      {"max": {"type": "integer"}, "keep": {"type": "boolean",
                                            "description": "do not clear the buffer"}})
def t_link_frames(max=60, keep=False):
    s = S()
    if not s.link:
        raise ToolError("no UART5 peer in replay mode")
    pk = list(s.link.packets)
    if not keep:
        s.link.packets.clear()
    rows, prev, cnt = [], None, 0
    for t, p in pk:
        key = (p.action_func, p.action_id, p.need_ack, p.payload)
        if key == prev:
            cnt += 1
            continue
        if prev is not None and cnt:
            rows.append(f"         (x{cnt + 1})")
        rows.append(_fmt_packet(s.t0, t, p))
        prev, cnt = key, 0
    if cnt:
        rows.append(f"         (x{cnt + 1})")
    hs = (f"handshake answered: MCU fw {s.handshake[0]:#010x}, loader {s.handshake[1]:#010x}"
          if s.handshake else "handshake not seen yet")
    note = "" if s.gdb.running else "\n(target is stopped: no new frames until it runs)"
    return f"{hs}\n{len(pk)} frames\n" + "\n".join(rows[-int(max):]) + note


@tool("link_send", "Send a frame to the MCU as the encoder board (0x2C). "
      "get=true sets need_ack (a request; the MCU answers with the same id).",
      {"action_id": {"type": "string"}, "payload_hex": {"type": "string"},
       "get": {"type": "boolean"}, "func": {"type": "string",
                                            "description": "default 0x6b"}},
      ["action_id"])
def t_link_send(action_id, payload_hex="", get=False, func="0x6b"):
    s = S()
    if not s.link:
        raise ToolError("no UART5 peer in replay mode")
    payload = bytes.fromhex(str(payload_hex).replace(" ", ""))
    s.link.send(num(func), num(action_id), payload, bool(get))
    return (f"sent {num(func):02x}/{num(action_id):02x} ack={int(bool(get))} {payload.hex()}"
            + ("" if s.gdb.running else " (target is stopped; it is processed after run_continue)"))


@tool("shell", "Run a firmware shell command over the USB VCP (help, sys, "
      "fw, cpu, task_info, show_temp, ...). The target must be running.",
      {"command": {"type": "string"}, "wait_s": {"type": "number"}},
      ["command"])
def t_shell(command, wait_s=2.0):
    s = S()
    if not s.shell:
        raise ToolError("no USB shell in replay mode")
    if s.gdb.running is False:
        raise ToolError("target is stopped: run_continue first")
    data = command.strip().encode() + b" \n"
    if len(data) > 255:
        raise ToolError("command too long")
    s.shell.packets.clear()
    s.shell.send(0xF0, 0x07, data)
    time.sleep(max(0.2, min(float(wait_s), 30)))
    text = "\n".join(p.payload.decode("utf-8", "replace").rstrip()
                     for _, p in list(s.shell.packets))
    return text or "(no reply; the USB device may not be enumerated yet)"


@tool("uart_output", "Bytes the firmware wrote to USART1-3/UART4/6/7 "
      "(UART5 is the encoder link, see link_frames).",
      {"port": {"type": "integer"}, "tail": {"type": "integer"}}, ["port"])
def t_uart(port, tail=2000):
    s = S()
    port = int(port)
    if port not in (1, 2, 3, 4, 6, 7):
        raise ToolError("port must be 1-4, 6 or 7")
    p = os.path.join(s.dir, f"uart{port}.log")
    data = open(p, "rb").read() if os.path.exists(p) else b""
    data = data[-max(1, min(int(tail), 65536)):]
    if not data:
        return "(nothing)"
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data) > 0.9 * len(data)
    return data.decode("latin-1") if printable else data.hex(" ")


@tool("qemu_log", "QEMU -d log (unimplemented devices, guest errors, "
      "resets), duplicates counted.",
      {"lines": {"type": "integer"}, "grep": {"type": "string"}})
def t_qemu_log(lines=40, grep=None):
    s = S()
    p = os.path.join(s.dir, "qemu.log")
    if not os.path.exists(p):
        return "(empty)"
    rows = collections.Counter()
    order = []
    with open(p, errors="replace") as f:
        for line in f:
            line = line.rstrip()
            if (not line or re.match(r"(R\d+|PSR|FPSCR|XPSR|[sd]\d+)=", line)
                    or (grep and grep not in line)):
                continue
            if line not in rows:
                order.append(line)
            rows[line] += 1
    out = [f"{rows[l]:6} {l}" for l in order[-int(lines):]]
    return "\n".join(out) or "(no matching lines)"


@tool("gdb_command", "Run a read-only gdb console command (x, print, "
      "output, info, disassemble, ptype, whatis, bt, frame, display, show). "
      "Other commands and $_shell are rejected.",
      {"command": {"type": "string"}}, ["command"])
def t_gdb(command):
    s = S()
    c = command.strip()
    word = re.match(r"[A-Za-z_-]*", c).group(0)
    if (word not in GDB_ALLOWED or "\n" in c or "\r" in c
            or "_shell" in c.lower() or "$_as_" in c):
        raise ToolError(f"not allowed; allowed: {', '.join(sorted(GDB_ALLOWED))}")
    if word == "show" and re.search(r"\b(convenience|conv)\b", c):
        raise ToolError("not allowed")
    if s.gdb.running and word not in ("show",):
        raise ToolError("target is running: run_interrupt first")
    return s.syms.annotate(s.gdb.console_cmd(c)) or "(no output)"


# --------------------------------------------------------------------------
# MCP stdio


INSTRUCTIONS = (
    "Debug the SIYI A8 mini gimbal MCU firmware (N32G4FR, Cortex-M4F) in "
    "QEMU. Start with qemu_start (halted at reset). Use break_add / "
    "watch_add, then run_continue (returns on a stop or after timeout_s; "
    "run_wait/run_interrupt to follow up). Memory, registers, svd and "
    "disas need a stopped target; shell, link_frames and sensor_set need "
    "a running one. Symbols exist for image 0_4_9 only; other images have "
    "landmarks (Reset_Handler, SystemInit, dma_wait_loop, ...). For "
    "reverse debugging: qemu_start mode=record, run, qemu_stop, then "
    "qemu_start mode=replay and use reverse_step/reverse_continue.")


def handle(msg):
    method, mid = msg.get("method"), msg.get("id")
    params = msg.get("params") or {}
    if method == "initialize":
        return {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "qemu-debug", "version": "1.0"},
                "instructions": INSTRUCTIONS}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": [t["schema"] for t in TOOLS.values()]}
    if method == "tools/call":
        t = TOOLS.get(params.get("name"))
        if not t:
            raise LookupError(f"unknown tool {params.get('name')}")
        try:
            text = t["fn"](**(params.get("arguments") or {}))
            err = False
        except Exception as e:
            text, err = f"error: {e}", True
            if not isinstance(e, ToolError):
                log(traceback.format_exc())
        return {"content": [{"type": "text", "text": text}], "isError": err}
    if mid is None:
        return None
    raise LookupError(f"method not found: {method}")


def main():
    out = sys.stdout
    sys.stdout = sys.stderr            # stray prints must not corrupt MCP
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            mid = msg.get("id")
            try:
                res = handle(msg)
                if mid is None:
                    continue
                reply = {"jsonrpc": "2.0", "id": mid, "result": res}
            except LookupError as e:
                if mid is None:
                    continue
                reply = {"jsonrpc": "2.0", "id": mid,
                         "error": {"code": -32601, "message": str(e)}}
            except Exception as e:
                log(traceback.format_exc())
                if mid is None:
                    continue
                reply = {"jsonrpc": "2.0", "id": mid,
                         "error": {"code": -32603, "message": str(e)}}
            out.write(json.dumps(reply) + "\n")
            out.flush()
    finally:
        if SESSION:
            SESSION.stop()


if __name__ == "__main__":
    main()
