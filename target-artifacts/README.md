# Target artifacts — SM-T878U / gts7l / `T878USQS8DXE1`

Everything needed to analyze this target **without** the device. Prepared
2026-10-07 for an external reviewer.

Source of truth for the exploit's progress remains the repo
[`README.md`](../README.md) → *Current status (UNFINISHED)*.

---

## 1. What is here

| File | Size | Where | What |
|---|---|---|---|
| `boot_kernel.bin.elf` | 62,756,203 B | **GitHub Release asset** | The target kernel, ELF64 AArch64, **not stripped** |
| `kallsyms_from_symtab.txt` | 6,624,814 B | this directory | All 152,788 symbols, `llvm-nm --numeric-sort` |
| `config-4.19.113-27114284.txt` | 190,566 B | this directory | `/proc/config.gz` decompressed |
| `config.gz` | 42,647 B | this directory | The raw device copy, as pulled |
| `OFFSET_VERIFICATION.md` | 4,870 B | this directory | Every address-like constant in `offset.h` checked against the ELF |
| `DISASM_EVIDENCE.txt` | 172,056 B | this directory | Disassembly of the 12 functions that matter |
| `verify_offsets.py` | 7,327 B | this directory | The script that produced `OFFSET_VERIFICATION.md` — re-runnable |

The 60 MB ELF is a **release asset, not a committed blob**, so it does not enter
git history. See *Download* below.

### Hashes

```
88b8b97eb632cc7b96be85ea7061299ff7625f556d5eb8f54a32ef785003fcb4  boot_kernel.bin.elf
933d4982f378c559ce2f5736e641769183052717da86e11f399554f7cc92bbb5  kallsyms_from_symtab.txt
c36e21abcd1bfc7e39382658d7e3551cc6778598f57ce3a911a321f0d79152f2  config.gz
```

---

## 2. Version correspondence — **CONFIRMED, and this is the strongest result here**

The question was: is this ELF from the official firmware package, or dd'd off a
device — and does the version actually match?

**Answer: from the official firmware package, and the version matches the
running device byte for byte.**

The ELF's own embedded `linux_banner` (link-time string, read straight out of the
binary) is:

```
Linux version 4.19.113-27114284 (dpi@21DKGA05) (clang version 10.0.6 for Android NDK) #1 SMP PREEMPT Wed May 15 19:38:01 KST 2024
```

The device, over adb (`/proc/version`):

```
Linux version 4.19.113-27114284 (dpi@21DKGA05) (clang version 10.0.6 for Android NDK) #1 SMP PREEMPT Wed May 15 19:38:01 KST 2024
```

Identical — same build user (`dpi@21DKGA05`), same toolchain
(`clang 10.0.6 for Android NDK`), same build stamp (`Wed May 15 19:38:01 KST
2024`). Matching device properties:

```
ro.build.fingerprint = samsung/gts7lsqwnc/gts7l:13/TP1A.220624.014/T878USQS8DXE1:user/release-keys
ro.boot.bootloader   = T878USQS8DXE1
uname                = Linux localhost 4.19.113-27114284 #1 SMP PREEMPT ... aarch64
```

So: **`T878USQS8DXE1`, kernel `4.19.113-27114284`.** Nothing needs re-porting.

Provenance chain (as preserved on disk):

```
firmware_extract/ap/boot.img.lz4   27,167,181 B   <- from the official AP tarball
  -> boot.img                      71,303,168 B   (lz4 -d)
  -> boot_kernel.bin               55,461,900 B   (kernel carved out of boot.img)
  -> boot_kernel.bin.elf           62,756,203 B   (ELF wrapper + symtab)
```

The exact tool that produced the `.elf` from `boot_kernel.bin` is **not preserved
in this workspace** — treat that one step as unverified. It does not matter for
correctness, because the ELF was validated against the device independently
(banner match above, and the 24 exact symbol matches in §4).

---

## 3. The ELF: it is **NOT stripped**

This settles the "do you also need kallsyms?" question — **no**.

```
$ file boot_kernel.bin.elf
ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, not stripped

$ llvm-readelf -h
  Class: ELF64      Machine: AArch64      Type: EXEC
  Entry point address: 0xFFFFFF800AC00870
  Number of program headers: 3      Number of section headers: 8
```

Sections:

```
[Nr] Name       Type      Address            Off      Size     Flg
[ 1] .kernel    PROGBITS  ffffff8008080000   000240   2ca11e0  WAX
[ 2] .kernel2   PROGBITS  ffffff800b0751e0   2ca1420  4ef62c   WAX
[ 3] .bss       NOBITS    ffffff800b56480c   3190a4c  1000000  WAX
[ 4] .symtab    SYMTAB    0000000000000000   3190a4c  37f3f8
[ 5] .strtab    STRTAB    0000000000000000   350fe44  37583c
[ 7] .rela.dyn  RELA      0000000000000000   38856bb  353e08
```

`KIMAGE_TEXT_BASE = 0xffffff8008080000` (== `_text`), and the ELF's `.kernel`
segment is mapped at exactly that VA, which is why `link-time VA =
KIMAGE_TEXT_BASE + offset` works for every constant in `offset.h`.

### Symbol table — read this before trusting it

```
total 152,788    T: 41,936   t: 109,588   W: 202   A: 1   V: 2   U: 1,059
.rela.dyn: 145,387 relocation entries
```

Two things worth noting:

* The **1,059 undefined (`U`) symbols plus a 145,387-entry `.rela.dyn`** are the
  signature of a **genuine linker-produced symbol table**, not a table
  reconstructed from the kernel's embedded kallsyms. A kallsyms reconstruction
  cannot produce `U` entries and does not carry relocations. So the symbol names
  and their link-time addresses are original build artifacts.
* But the section names (`.kernel`, `.kernel2`) are **not** stock vmlinux names
  (stock would be `.text`/`.rodata`/`.data`/`.bss`), so this ELF *has* been
  post-processed. The addresses are still link-time VAs — which is all the
  exploit needs — but do not assume section-level layout matches a stock vmlinux.

**There is no fallback**: `/proc/kallsyms` on the device is `Permission denied`
to `uid 2000` (`ls: /proc/kallsyms: Permission denied`). This ELF's `.symtab` is
the only symbol source available. (`CONFIG_KALLSYMS=y` and `CONFIG_KALLSYMS_ALL=y`
are both set, so the data is there — just not readable without root.)

---

## 4. Where `offset.h`'s constants came from — and which ones are verified

**Origin.** `src/exploit/offset.h` declares its `*_OFF` constants as *"Raw Image
offsets, relative to `_text == 0`"*. The file's own comments cite **IDA** analysis
(`firmware_extract/ap/` still holds the `.i64` / `.id0` / `.id1` / `.nam` / `.til`
database). The file began as a port of the public `xpad2-ionstack-poc` layout and
was re-derived for `T878USQS8DXE1`. So the historical source is **IDA + manual
carving**, i.e. exactly the circular-argument risk you flagged.

**Independent check.** Because the ELF is not stripped, every address-like
constant can now be checked mechanically against the ELF's own symbol table — no
IDA, no heuristics. `verify_offsets.py` does this and writes
`OFFSET_VERIFICATION.md`.

**Result: 24 EXACT / 3 INSIDE / 0 GAP, out of 27 address-like constants.**

"EXACT" means a symbol starts at precisely `KIMAGE_TEXT_BASE + constant`. The 3
non-exact are all explainable:

| constant | resolves to | verdict |
|---|---|---|
| `ASHMEM_MISC_FOPS_OFF` | `ashmem_misc + 0x10` | **intended** — `+0x10` is the `miscdevice.fops` field, so the constant points at the `.fops` member, not the struct head |
| `SLIDE_RANDOM_BOOT_ID_DATA_OFF` | `__per_cpu_end + 0x255018` | a `.bss` object; `.bss` is `NOBITS`, so no symbol can start at a `+0x…`-after-`__per_cpu_end` address. Unverifiable from the ELF, not wrong |
| `SLIDE_SYSCTL_BOOTID_OFF` | `random_table + 0x108` | lands inside `random_table[]`, consistent with a specific `ctl_table` entry |

Representative exact matches (full table in `OFFSET_VERIFICATION.md`):

```
ASHMEM_FOPS_OFF       0x1f1a3d8  -> ashmem_fops        (exact)
ASHMEM_LLSEEK_OFF     0x11bfc34  -> ashmem_llseek      (exact)
ASHMEM_READ_ITER_OFF  0x11bfcdc  -> ashmem_read_iter   (exact)
ASHMEM_IOCTL_OFF      0x11bfd9c  -> ashmem_ioctl       (exact)
ASHMEM_MMAP_OFF       0x11c0684  -> ashmem_mmap        (exact)
ASHMEM_OPEN_OFF       0x11c0804  -> ashmem_open        (exact)
ASHMEM_RELEASE_OFF    0x11c088c  -> ashmem_release     (exact)
ASHMEM_SHOW_FDINFO_OFF 0x11c098c -> ashmem_show_fdinfo (exact)
INIT_TASK_OFF         0x31ad980  -> init_task          (exact)
MODPROBE_PATH_OFF     0x31bbe90  -> modprobe_path      (exact)
ANON_PIPE_BUF_OPS_OFF 0x1da1e40  -> anon_pipe_buf_ops  (exact)
FAIR_SCHED_CLASS_OFF  0x1d88960  -> fair_sched_class   (exact)
```

### ⚠️ One naming trap you should know about

`CONFIGFS_READ_FILE_OFF` / `CONFIGFS_WRITE_FILE_OFF` are **misleading names**.
They do not resolve to `configfs_read_file` / `configfs_write_file`:

```
CONFIGFS_READ_FILE_OFF   0x3044bc -> configfs_read_bin_file    (NOT configfs_read_file   @0x30414c)
CONFIGFS_WRITE_FILE_OFF  0x30464c -> configfs_write_bin_file   (NOT configfs_write_file  @0x30427c)
```

Both are exact symbol matches — the constants are not wrong, they are just named
after the wrong pair. The author knew (`offset.h:62-63` aliases them to
`CONFIGFS_READ_ITER_OFF` / `CONFIGFS_BIN_WRITE_ITER_OFF`, and `fops.c:3140-3144`
says *"configfs_read_bin_file through ashmem hard-faults on dentry->d_fsdata"*),
and the exploit only uses the write path for this reason. **If you plan to use
the configfs read path, you need `0x30414c`, not `0x3044bc`** — and you will hit
`to_frag(file)` (a `dentry`/fragment dereference) that the text variant does not
do.

---

## 5. The three verification tasks — results

### (1) `rt_mutex_adjust_prio_chain` line → instruction mapping

`rt_mutex_adjust_prio_chain` is at `_text+0xc7c64` = `0xffffff8008147c64`.
Full disassembly in `DISASM_EVIDENCE.txt`. Key facts confirmed from the binary:

* **The retry loop re-enters ABOVE `again:`.** After a failed `585` the code does
  `_raw_spin_unlock_irq(&task->pi_lock); yield; _raw_spin_lock_irq(...); ldr
  x25,[x19,#0x8f8]; cbnz x25, <507>` — it reloads `task->pi_blocked_on` and jumps
  back to the *body*, not to `again:`. Consequence: **`++depth` never re-runs**,
  so `max_lock_depth` can never terminate this loop.
* `_raw_spin_trylock` (rtmutex.c:585) is an out-of-line call to
  `_raw_spin_trylock` @ `_text+0x1b9958c`; `_raw_spin_unlock` @ `_text+0x1b998ec`.
* `rt_mutex_dequeue`/`rt_mutex_enqueue` (664/685) inline to
  `rb_erase_cached` @ `_text+0x1b86e94` plus stores to `waiter+0x40` (`prio`).

**On your witness criterion.** You are right to suspect it, and the suspicion is
confirmed — but *in favour* of `wait_lock.val == 1`:

`CONFIG_DEBUG_QSPINLOCK_OWNER=y` and `CONFIG_ARCH_USE_QUEUED_SPINLOCKS=y`, and
`# CONFIG_DEBUG_SPINLOCK is not set`. In `include/asm-generic/qspinlock.h` the
owner stamp is written by `queued_spin_set_owner()` — but the **`raw_spin_*`
family does not necessarily route through `queued_spin_trylock()`**; this vendor
tree has no `arch/arm64/include/asm/qspinlock.h` override, and `_raw_spin_trylock`
is a separate out-of-line function at `_text+0x1b9958c`. So:

* **`wait_lock.val == 1` is the reliable witness** that `585` succeeded.
* **`owner_cpu != 0` is NOT reliable** — the stamp may never be written on this
  path. The harness has been reporting `owner_cpu=00000000` in 174/174 dumps,
  which under this reading means *nothing* about whether the trylock succeeded.

Worth your independent confirmation: disassemble `_raw_spin_trylock`
(`_text+0x1b9958c`) in `DISASM_EVIDENCE.txt` and check whether it calls into
`queued_spin_set_owner` or does a bare `.val` CAS.

### (2) Stack-frame geometry

Both confirmed from the ELF, in `DISASM_EVIDENCE.txt`:

```
__arm64_sys_futex   _text+0x1111ec : sub sp,sp,#0x70 ; add x29,sp,#0x20
do_futex            _text+0x10d4ec : sub sp,sp,#0x1e0 ; add x29,sp,#0x180
                                     add x28,sp,#0xc0     <-- rt_waiter = do_futex_sp + 0xC0   ✓

__arm64_sys_sendmsg _text+0x1897cd4: sub sp,sp,#0x90 ; add x29,sp,#0x60
___sys_sendmsg      _text+0x18979fc: sub sp,sp,#0x190 ; add x29,sp,#0x140
                                     add x9,sp,#0x38      <-- iovstack  = ___sys_sendmsg_sp + 0x38  ✓
```

`rt_waiter = do_futex_sp + 0xC0` is **confirmed verbatim**. `iovstack = sp + 0x38`
is confirmed; with `E = SP0 - 0x190` this gives `iovstack = E - 0x58`, matching
the model. The `address` half (`x29 - 0x88` → `E + 0x28`) was **not** re-derived
in this pass — it is worth a second pair of eyes, since the whole paint drop
point depends on it.

### (3) Batch-check of `offset.h` constants

Done — see §4. **24 exact, 3 explainable, 0 unresolvable.** The remaining ~165
`#define`s in `offset.h` are **struct-field offsets** (`RTMUTEX_*`, `WAITER_*`,
`LOCK_OFF`, `W0_OFF`, `FOPS_OFF`, …), not addresses. Those are verified against
the *kernel source* (`Kernel_T878USQS8DXE2/`) rather than the ELF, and the
layout is confirmed by the disassembly: e.g. `rt_mutex_adjust_prio_chain` stores
`waiter->prio` at `waiter+0x40`, matching `WAITER_PRIO_OFF 0x40`.

---

## 6. Config facts (from `config-4.19.113-27114284.txt`, all device-verified)

```
CONFIG_ARCH_USE_QUEUED_SPINLOCKS=y     CONFIG_DEBUG_QSPINLOCK_OWNER=y
# CONFIG_DEBUG_SPINLOCK is not set     # CONFIG_DEBUG_LOCK_ALLOC is not set
# CONFIG_DEBUG_RT_MUTEXES is not set   # CONFIG_DEBUG_MUTEXES is not set
# CONFIG_PROVE_LOCKING is not set      CONFIG_RT_MUTEXES=y
CONFIG_FUTEX_PI=y                      CONFIG_PREEMPT=y
CONFIG_KALLSYMS=y                      CONFIG_KALLSYMS_ALL=y
CONFIG_RANDOMIZE_BASE=y                CONFIG_ARM64_VA_BITS=39
CONFIG_SLUB=y                          CONFIG_CROSS_MEMORY_ATTACH=y
CONFIG_PANIC_ON_OOPS=y
# CONFIG_CHECKPOINT_RESTORE is not set  <-- the NebuSec vehicle is compiled out
```

---

## 7. Download

The ELF lives on the release, not in git:

```sh
gh release download target-artifacts-t878usqs8dxe1 -R Wtrwx/smt878u-ionstack-poc
# or
curl -L -O https://github.com/Wtrwx/smt878u-ionstack-poc/releases/download/target-artifacts-t878usqs8dxe1/boot_kernel.bin.elf
shasum -a 256 boot_kernel.bin.elf   # expect 88b8b97eb632cc7b96be85ea7061299ff7625f556d5eb8f54a32ef785003fcb4
```

---

## 8. Suggested next questions (yours to pick)

Given the above, the three highest-value things an outside reviewer could settle:

1. **Does `_raw_spin_trylock` @ `_text+0x1b9958c` write the qspinlock owner stamp?**
   If not, the harness's `owner_cpu` oracle is dead weight and only
   `wait_lock.val == 1` should be trusted. This is a 20-instruction question with
   a large blast radius on how every past run is interpreted.
2. **Re-derive `address = x29 - 0x88` in `___sys_sendmsg`.** The paint drop point
   `E + 0x28` rests on it, and it was the one leg of the geometry not re-checked
   here.
3. **Is `configfs_read_bin_file`'s `to_frag(file)` reachable with a fake `file`?**
   If yes, ring 2 gains a read primitive and the exploit is no longer
   write-only — which is currently the single biggest constraint on the chain.
