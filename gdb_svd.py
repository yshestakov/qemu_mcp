"""GDB `svd` command: show N32G4FR peripheral registers decoded from an SVD.

Standard library only (gdb's embedded Python has no lxml / cmsis-svd).

  (gdb) source gdb_svd.py               # loads $N32G4FR_SVD (see DEFAULT_SVD)
  (gdb) svd                             # list peripherals
  (gdb) svd RCC                         # all RCC registers, non-zero fields
  (gdb) svd RCC RCC_CFG                 # one register, every field
  (gdb) svd USART1 STS                  # register prefix may be omitted
  (gdb) svd/a RCC                       # all fields, zero ones too
  (gdb) svd-load other.svd              # switch SVD file

Data registers whose read has side effects in the model (USART_DAT pops
the RX FIFO, ...) are skipped in whole-peripheral dumps; name them
explicitly to read them.  Tab completion works for peripherals/registers.
"""
import os
import xml.etree.ElementTree as ET

try:
    import gdb
except ImportError:
    # Imported outside gdb (e.g. by qemu_mcp) for the SVD parser only
    gdb = None

# $N32G4FR_SVD, else $SIYI_RE/firmware/ghidra/N32G4FR.svd, else a
# siyi_a8_mini_re checkout next to this file
DEFAULT_SVD = os.environ.get("N32G4FR_SVD") or os.path.join(
    os.environ.get("SIYI_RE") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "siyi_a8_mini_re"),
    "firmware", "ghidra", "N32G4FR.svd")
# Reading these pops a FIFO / clears flags in the QEMU models (as on HW)
READ_SIDE_EFFECT = {"USART_DAT", "SPI_DAT", "I2C_DAT", "SDIO_DATFIFO",
                    "QSPI_DATx", "ADC_DAT"}


def _int(text, default=0):
    return int(text, 0) if text else default


class Field:
    def __init__(self, e):
        self.name = e.findtext("name")
        self.desc = (e.findtext("description") or "").strip()
        self.lsb = _int(e.findtext("bitOffset"))
        self.width = _int(e.findtext("bitWidth"), 1)


class Register:
    def __init__(self, e):
        self.name = e.findtext("name")
        self.desc = (e.findtext("description") or "").strip()
        self.offset = _int(e.findtext("addressOffset"))
        self.size = _int(e.findtext("size"), 32)
        self.fields = sorted((Field(f) for f in e.findall("fields/field")),
                             key=lambda f: -f.lsb)


class Peripheral:
    def __init__(self, e, by_name):
        self.name = e.findtext("name")
        self.base = _int(e.findtext("baseAddress"))
        src = by_name.get(e.get("derivedFrom"))
        self.desc = (e.findtext("description")
                     or (src.desc if src else "")).strip()
        regs = e.findall("registers/register")
        self.registers = ([Register(r) for r in regs] if regs or not src
                          else src.registers)
        self.irqs = [(i.findtext("name"), _int(i.findtext("value")))
                     for i in e.findall("interrupt")]

    def find(self, name):
        """Exact name, or without the peripheral-type prefix (STS)."""
        name = name.upper()
        for r in self.registers:
            if r.name.upper() == name:
                return r
        hits = [r for r in self.registers
                if r.name.upper().split("_", 1)[-1] == name]
        return hits[0] if len(hits) == 1 else None


class Device:
    def __init__(self, path):
        root = ET.parse(path).getroot()
        self.path = path
        self.name = root.findtext("name")
        self.periphs = {}
        for e in root.find("peripherals"):
            p = Peripheral(e, self.periphs)
            self.periphs[p.name.upper()] = p


DEVICE = None


def _read(addr, size):
    nbytes = max(size // 8, 1)
    mem = gdb.selected_inferior().read_memory(addr, nbytes)
    return int.from_bytes(bytes(mem), "little")


def _show_reg(p, r, all_fields):
    addr = p.base + r.offset
    try:
        val = _read(addr, r.size)
    except gdb.MemoryError:
        print(f"  {r.name:<16} @0x{addr:08x}  <unreadable>")
        return
    print(f"  {r.name:<16} @0x{addr:08x} = 0x{val:0{r.size // 4}x}")
    for f in r.fields:
        v = (val >> f.lsb) & ((1 << f.width) - 1)
        if not v and not all_fields:
            continue
        bits = (f"[{f.lsb}]" if f.width == 1
                else f"[{f.lsb + f.width - 1}:{f.lsb}]")
        desc = f"  {f.desc}" if f.desc and f.desc != f.name else ""
        print(f"      {f.name:<14}{bits:>8} = 0x{v:x}{desc}")


class SvdCommand(gdb.Command if gdb else object):
    """Show peripheral registers from the SVD: svd [/a] [PERIPH [REG...]]

With no argument, list peripherals.  With PERIPH, dump its registers
(non-zero fields; /a shows all fields).  With REG, show those registers
with every field.  REG may omit the type prefix (STS for USART_STS)."""

    def __init__(self):
        super().__init__("svd", gdb.COMMAND_DATA)

    def complete(self, text, word):
        if DEVICE is None:
            return []
        word = (word or "").upper()
        args = text.split()
        if len(args) <= 1 and not text.endswith(" "):
            return [n for n in DEVICE.periphs
                    if n.startswith(word)]
        p = DEVICE.periphs.get(args[0].upper())
        if not p:
            return []
        return [r.name for r in p.registers
                if r.name.upper().startswith(word)]

    def invoke(self, arg, from_tty):
        if DEVICE is None:
            raise gdb.GdbError("no SVD loaded: svd-load FILE")
        all_fields = False
        if arg.startswith("/"):
            mod, _, arg = arg.partition(" ")
            all_fields = "a" in mod
        args = arg.split()
        if not args:
            print(f"{DEVICE.name} ({DEVICE.path}):")
            for p in sorted(DEVICE.periphs.values(), key=lambda p: p.base):
                irq = ", ".join(f"{n}={v}" for n, v in p.irqs)
                irq = f"  [IRQ {irq}]" if irq else ""
                print(f"  {p.name:<8} 0x{p.base:08x}  {p.desc}{irq}")
            return
        p = DEVICE.periphs.get(args[0].upper())
        if not p:
            raise gdb.GdbError(f"unknown peripheral {args[0]}")
        if len(args) == 1:
            print(f"{p.name} @0x{p.base:08x}  {p.desc}")
            for r in p.registers:
                if r.name in READ_SIDE_EFFECT:
                    print(f"  {r.name:<16} @0x{p.base + r.offset:08x}"
                          "  (skipped: read has side effects)")
                    continue
                _show_reg(p, r, all_fields)
            return
        for name in args[1:]:
            r = p.find(name)
            if not r:
                raise gdb.GdbError(f"unknown register {name} in {p.name}")
            _show_reg(p, r, True)


class SvdLoadCommand(gdb.Command if gdb else object):
    """Load a CMSIS-SVD file for the svd command: svd-load FILE"""

    def __init__(self):
        super().__init__("svd-load", gdb.COMMAND_DATA, gdb.COMPLETE_FILENAME)

    def invoke(self, arg, from_tty):
        global DEVICE
        path = os.path.expanduser(arg.strip())
        DEVICE = Device(path)
        print(f"svd: {DEVICE.name}, {len(DEVICE.periphs)} peripherals "
              f"from {path}")


if gdb is not None:
    SvdCommand()
    SvdLoadCommand()
    if os.path.exists(DEFAULT_SVD):
        gdb.execute(f"svd-load {DEFAULT_SVD}")
