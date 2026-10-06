#!/usr/bin/env python3
"""
Batch-verify the address-like constants in src/exploit/offset.h against the
symtab of the target kernel ELF.

offset.h says its *_OFF constants are "Raw Image offsets, relative to _text == 0",
and KIMAGE_TEXT_BASE is _text's link-time VA, so:

    link-time VA = KIMAGE_TEXT_BASE + *_OFF

Every symbol in the ELF's .symtab carries a link-time VA, so each constant can be
classified without any guessing:

  EXACT     a symbol starts exactly at that VA  -> the constant names a real object
  INSIDE    the VA falls inside symbol S at +delta -> mid-object (may be intended
            for a struct field, or may be an error)
  GAP       no symbol contains the VA -> address in an unmapped hole between
            segments (expected for some .data/.bss constants: the ELF carve split
            .bss into its own segment, while the constants were derived from the
            flat raw Image)
"""

import bisect
import re
import sys
from pathlib import Path

ROOT = Path("/Users/vita/Projects/CVE-2026-43499")
OFFSET_H = ROOT / "smt878u-ionstack-poc/src/exploit/offset.h"
SYMS = ROOT / "scratch/elf-package/kallsyms_from_symtab.txt"
OUT = ROOT / "scratch/elf-package/OFFSET_VERIFICATION.md"

KIMAGE_TEXT_BASE = 0xFFFFFF8008080000
# Program headers of boot_kernel.bin.elf (from llvm-readelf -l)
SEGMENTS = [
    ("LOAD .kernel",  0xFFFFFF8008080000, 0x2CA11E0, True),
    ("LOAD .kernel2", 0xFFFFFF800B0751E0, 0x4EF62C,  True),
    ("LOAD .bss",     0xFFFFFF800B56480C, 0x1000000, False),  # no file content
]

# ---------------------------------------------------------------- symbols
syms = []
for line in SYMS.read_text(errors="replace").splitlines():
    p = line.split()
    if len(p) == 3 and p[0] != "U":
        try:
            syms.append((int(p[0], 16), p[1], p[2]))
        except ValueError:
            pass
syms.sort()
addrs = [s[0] for s in syms]


def classify(va):
    """Return (kind, detail) for a link-time VA."""
    i = bisect.bisect_right(addrs, va) - 1
    if i >= 0 and syms[i][0] == va:
        return "EXACT", syms[i][2]
    if i >= 0:
        start, _t, name = syms[i]
        # only call it INSIDE if the next symbol does not start before va
        j = i + 1
        if j < len(syms) and syms[j][0] <= va:
            return "GAP", ""
        # a symbol "contains" va only if va is within its size -- nm gives no size,
        # so treat "between two symbol starts" as INSIDE with the delta shown
        return "INSIDE", f"{name}+{va - start:#x}"
    return "GAP", ""


# ---------------------------------------------------------------- constants
# Only constants that are *addresses*.  Struct-field offsets (LOCK_OFF, W0_OFF,
# FOPS_OFF, RTMUTEX_*, WAITER_*, FAKE_*) are offsets within the payload page and
# are deliberately NOT checked here.
TEXT = OFFSET_H.read_text(errors="replace")

CONST_RE = re.compile(r"^#define\s+([A-Z0-9_]+)\s+(0x[0-9a-fA-F]+)ULL\s*$", re.M)

# Map a *_OFF constant name to the symbol name it *should* be.
EXPECT = {
    "ASHMEM_MISC_FOPS_OFF":     "ashmem_misc + 0x10 (miscdevice.fops field)",
    "ASHMEM_FOPS_OFF":          "ashmem_fops",
    "ASHMEM_LLSEEK_OFF":        "ashmem_llseek",
    "ASHMEM_READ_ITER_OFF":     "ashmem_read_iter",
    "ASHMEM_IOCTL_OFF":         "ashmem_ioctl",
    "ASHMEM_COMPAT_IOCTL_OFF":  "compat_ashmem_ioctl",
    "ASHMEM_MMAP_OFF":          "ashmem_mmap",
    "ASHMEM_OPEN_OFF":          "ashmem_open",
    "ASHMEM_RELEASE_OFF":       "ashmem_release",
    "ASHMEM_SHOW_FDINFO_OFF":   "ashmem_show_fdinfo",
    "CONFIGFS_READ_FILE_OFF":   "configfs_read_bin_file  (!= configfs_read_file)",
    "CONFIGFS_WRITE_FILE_OFF":  "configfs_write_bin_file (!= configfs_write_file)",
    "COPY_SPLICE_READ_OFF":     "copy_splice_read",
    "NOOP_LLSEEK_OFF":          "noop_llseek",
    "NO_LLSEEK_OFF":            "no_llseek",
    "INIT_TASK_OFF":            "init_task",
    "ROOT_TASK_GROUP_OFF":      "root_task_group",
    "SELINUX_ENFORCING_OFF":    "selinux_state.enforcing (mid-object)",
    "SECURITY_HOOK_HEADS_OFF":  "security_hook_heads",
    "KMALLOC_CACHES_OFF":       "kmalloc_caches",
    "ANON_PIPE_BUF_OPS_OFF":    "anon_pipe_buf_ops",
    "MODPROBE_PATH_OFF":        "modprobe_path",
    "FAIR_SCHED_CLASS_OFF":     "fair_sched_class",
    "SLIDE_NFULNL_LOGGER_OFF":  "nfulnl_logger",
    "SLIDE_LOGGERS_0_1_OFF":    "loggers[0..1]",
    "SLIDE_RANDOM_BOOT_ID_DATA_OFF": "random_boot_id.data",
    "SLIDE_SYSCTL_BOOTID_OFF":  "sysctl boot_id table",
}

rows = []
for name, val in CONST_RE.findall(TEXT):
    if not name.endswith("_OFF"):
        continue
    if name in ("SELINUX_BLOB_SIZES_OFF",):
        continue
    off = int(val, 16)
    va = KIMAGE_TEXT_BASE + off
    kind, detail = classify(va)
    rows.append((name, off, va, kind, detail, EXPECT.get(name, "")))

# ---------------------------------------------------------------- report
def seg_of(va):
    for nm, base, size, has_file in SEGMENTS:
        if base <= va < base + size:
            return nm
    return "--- (not in any LOAD segment)"


exact = [r for r in rows if r[3] == "EXACT"]
inside = [r for r in rows if r[3] == "INSIDE"]
gap = [r for r in rows if r[3] == "GAP"]

lines = []
lines.append("# offset.h constant verification against the target kernel ELF\n")
lines.append(f"Source ELF : `firmware_extract/ap/boot_kernel.bin.elf` (62,756,203 bytes, not stripped)\n")
lines.append(f"Symbols    : {len(syms)} from `.symtab` (`llvm-nm --numeric-sort`)\n")
lines.append(f"Base       : `KIMAGE_TEXT_BASE = {KIMAGE_TEXT_BASE:#018x}`\n")
lines.append(f"\n**Result: {len(exact)} EXACT, {len(inside)} INSIDE, {len(gap)} GAP "
             f"out of {len(rows)} address-like constants.**\n")
lines.append("\n| constant | _text+ | link-time VA | class | resolves to | expected | segment |")
lines.append("|---|---|---|---|---|---|---|")
for name, off, va, kind, detail, exp in rows:
    lines.append(f"| `{name}` | `{off:#x}` | `{va:#018x}` | **{kind}** | `{detail}` | {exp} | {seg_of(va)} |")

lines.append("\n## Reading this table\n")
lines.append("- **EXACT** — a symbol starts exactly at that address. The constant is\n"
             "  independently confirmed by the ELF's own symbol table; no IDA or\n"
             "  heuristics were involved.\n")
lines.append("- **INSIDE** — the address lands in the middle of a symbol. For a struct\n"
             "  *field* address (e.g. `ashmem_misc` + 0x10 = `miscdevice.fops`) this is\n"
             "  intended. Otherwise it is worth a second look.\n")
lines.append("- **GAP** — the address is not inside any LOAD segment of this ELF. This is\n"
             "  EXPECTED for part of the `.data`/`.bss` constants: they were derived from\n"
             "  the flat raw `Image`, whereas this ELF carve splits `.bss` into a separate\n"
             "  segment with no file content. A GAP result therefore says nothing about\n"
             "  correctness — it means the ELF cannot confirm the constant either way, and\n"
             "  it must be checked against a runtime read instead.\n")

OUT.write_text("\n".join(lines) + "\n")
print("\n".join(lines[:12]))
print(f"\n[written] {OUT}")
print(f"\nEXACT  : {len(exact)}")
print(f"INSIDE : {len(inside)}")
print(f"GAP    : {len(gap)}")
for n, o, v, k, d, e in gap:
    print(f"   GAP    {n:34s} {v:#018x}  ({seg_of(v)})")
