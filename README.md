# smt878u-ionstack-poc

> [!CAUTION]
> **THIS PROJECT IS UNFINISHED — IT DOES NOT WORK YET.**
> There is **no working root** on any device as of 2026-10-06. Do **not** expect
> the quick-start below to succeed. Read [Current status](#current-status-unfinished)
> before building or running anything.

> [!WARNING]
> **STATUS: WORK IN PROGRESS — ring 1 not landed**
> - **Not achieved:** persistent or even one-shot `root` on SM-T878U.
> - **Last verified failure:** the stack-reclaim payload never reaches the
>   kernel's write path. Across ~470 instrumented runs the forged lock is
>   **never** observed to be taken at `rtmutex.c:585`, so the store
>   `*(ASHMEM_MISC_FOPS) = fake_fops` never executes.
> - **Former blocker, now resolved:** crash forensics used to be unavailable to
>   `uid 2000 shell` (`/proc/kmsg`, `/proc/last_kmsg`, `/sys/fs/pstore`, `dmesg`
>   → all `EACCES`). A durable `write()`+`fsync()` log mirror
>   (`IONSTACK_LOG_MIRROR`) now survives `CONFIG_PANIC_ON_OOPS=y`, so a panicked
>   run still leaves a complete trail.
> - See [`docs/RTMUTEX_WEAPONIZATION.md`](docs/RTMUTEX_WEAPONIZATION.md) §15.16–§15.18
>   for the full evidence trail.

Pure-C, host-assisted re-root proof of concept for **Samsung Galaxy Tab S7
(SM-T878U / gts7l)** against **CVE-2026-43499** (IonStack / GhostLock).

The runtime chain uses native C/ELF components only. It does not require
Python, Java, DEX, `app_process`, or a JVM on the Android target. ADB is used
for deployment and verification.

---

## Current status (UNFINISHED)

**No root has been obtained.** This section is the authoritative, up-to-date
account of where the chain stands (last revised **2026-10-06**). Everything
below is measured on real hardware (SM-T878U, `T878USQS8DXE1`, kernel
`4.19.113-27114284`), not theory.

### What is proven to work

| Stage | Status | Evidence |
|---|---|---|
| Target identity + KASLR leak | working | `[reroot] LEAK_OK kaslr_base=… task=…` (perf side-channel) |
| CVE trigger: `FUTEX_CMP_REQUEUE_PI` → `-EDEADLK` | **working** | `[*] requeue ret=-1 errno=35` — `EDEADLK == 35` on Linux |
| Buggy rollback leaves dangling `pi_blocked_on` | matches upstream fix | upstream `3bfdc63936dd` changes `current->pi_blocked_on` → `waiter->task->pi_blocked_on` |
| `struct rt_mutex_waiter` layout (4.19) | **verified from source** | `tree_entry@0x00` `pi_tree_entry@0x18` `task@0x30` `lock@0x38` `prio@0x40` `deadline@0x48` |
| Stack geometry `paint == rt_waiter + 0x28` | **verified 4×** incl. objdump | `rt_waiter = do_futex_sp+0xC0`; `address = ___sys_sendmsg_sp+0xB8` |
| Durable crash forensics | **working** | `IONSTACK_LOG_MIRROR` `write()`+`fsync()` trail survives a panic reboot |
| Per-message frag-page identity tag | **working** | `reclaim-scan tag=1 sent=8201 range=1..8201 ok=8192 bad=0 dup=0 undecoded=0 absent=9` |
| Queue scan: kernel wrote 0 bytes into 8192 queued frag pages | **verified** | 256 MB compared byte-for-byte against the payload, `hits=0` |
| `rt_mutex_adjust_prio_chain` reaches the write path | **verified from disassembly** | `top_waiter == NULL` ⇒ `requeue` stays `true` ⇒ `664/682/685/716-725` structurally reachable |

### What is NOT working

1. **The write path never executes.** Across ~470 instrumented runs, all 174
   `page-dump` and 45 `ring1-page` observations report
   `first_diff=8000 (pristine)`, `owner_cpu=00000000`, `case1_gate=0`, and
   `lock_root`/`lock_leftmost` exactly equal to the payload value. The walk has
   **never** been seen to take `fake_lock->wait_lock` at `rtmutex.c:585`, so
   `664/682/685/716-725` — the only branch that can store into
   `*(ASHMEM_MISC_FOPS)` — has never run.
   Note that `_raw_spin_trylock()`/`_raw_spin_unlock()` route through
   out-of-line helpers and this vendor tree has **no arm64 `queued_spin_unlock`
   override**, so `wait_lock.val == 1` is the reliable `585` witness and
   `owner_cpu != 0` is only a secondary one.
2. **The published vehicle is unavailable here.** The only public successful
   exploit of this CVE (NebuSec, *IonStack part II*) reclaims the frame with
   `prctl(PR_SET_MM, PR_SET_MM_MAP, …)`. This kernel ships
   `# CONFIG_CHECKPOINT_RESTORE is not set`, so that syscall is compiled out.
   It also never uses `sendmsg` — our vehicle — which is very likely the root
   cause of (1).
3. **`ring1-read` has never run.** The only userspace read-back of ring 1
   (`configfs_read_once(fd, data_addr(ASHMEM_MISC_FOPS), …)`) sits behind the
   queue-scan gate and behind the harness `MARKER` default, which stops 8 s
   earlier at `ring1-page`. Every run that reached the gate died between
   `page-dump tag=pre-arm` and `page-dump tag=post-arm`.

### Immediate next steps (in priority order)

1. Re-run the one configuration in which `664/682/685` can *complete inside our
   own page* — `IONSTACK_FOPS_WAIT_LOCK_WORD=0` with
   `IONSTACK_PAINT_WAITER_TASK_MODE=fake-task` — and read
   `page-dump tag=post-arm` / `ring1-lock585` for `wait_lock=00000001`.
2. Get `ring1-read` to execute: run with `IONSTACK_RECLAIM_SCAN_QUEUE` unset and
   `MARKER='ring1-read|…'` so the harness does not stop at `ring1-page`.
3. Identify the held page: run with `IONSTACK_RECLAIM_TAG=1` and compare
   `pipe_tag` against `msg_tag` in `page-dump`. All frag pages are byte-identical
   copies of the payload, so `first_diff` alone cannot tell them apart.
4. Re-test the `IONSTACK_FOPS_WAIT_LOCK_WORD` question on a properly posed
   basis — `wlw=0` vs `wlw=1` with `IONSTACK_RECLAIM_TAG` held constant. The
   earlier correlation was confounded by the two variables moving together.
5. Port the `res_in`/`res_out` `pselect6` paint surface from the K40 4.19 port.
6. Only then convert the write primitive into privilege escalation.

### Unrelated open bug

`fops.c:3157 reason=selinux_write ret=-1 errno=22 EINVAL` — still unresolved.

---

## Documentation

| Document | What |
|---|---|
| [`docs/RTMUTEX_WEAPONIZATION.md`](docs/RTMUTEX_WEAPONIZATION.md) | Full evidence trail for the rtmutex chain (largest document) |
| [`docs/ROOT_CHAIN_THEORY.md`](docs/ROOT_CHAIN_THEORY.md) | End-to-end ring 0→4 root chain design |
| [`docs/PAINT_ORACLE_ANALYSIS.md`](docs/PAINT_ORACLE_ANALYSIS.md) | Why the stack-paint oracle reads the way it does |
| [`docs/PSELECT_GEOMETRY_FINDINGS.md`](docs/PSELECT_GEOMETRY_FINDINGS.md) | `pselect6` as an alternative paint vehicle |
| [`docs/RING1_RECLAIM_IDENTITY_2026-10-06.md`](docs/RING1_RECLAIM_IDENTITY_2026-10-06.md) | Per-message frag-page identity tag; queue-scan verification |
| [`docs/RING1_585_NEVER_SUCCEEDED_2026-10-06.md`](docs/RING1_585_NEVER_SUCCEEDED_2026-10-06.md) | Proof that `rtmutex.c:585` never succeeded |
| [`docs/RING1_ORACLE_FIX_2026-10-05.md`](docs/RING1_ORACLE_FIX_2026-10-05.md) | Oracle correction |
| [`docs/RING1_ORACLE_WRONG_FRAGMENT_2026-10-06.md`](docs/RING1_ORACLE_WRONG_FRAGMENT_2026-10-06.md) | Why the held fragment was mis-identified |

---

## Supported profile

This POC intentionally fails closed unless all profile checks match:

```text
device:      gts7l
Android:     13 / SDK 33
fingerprint: samsung/gts7lsqwnc/gts7l:13/TP1A.220624.014/T878USQS8DXE1:user/release-keys
kernel:      4.19.113
build:       T878USQS8DXE1
```

Unsupported or failed runs can panic or reboot the device. Keep a recovery
path available.

This repository is narrowly scoped to the firmware profile above. It is not a
general-purpose rooting tool, and offsets or assumptions must not be reused on
other devices without independent validation.

## Security research only

- Use only on hardware you own or are explicitly authorized to test.
- Successful exploitation can panic, reboot, or brick devices.
- Root produced by this POC is ephemeral and does not modify AVB, boot images,
  or system partitions; reboot removes it.

## Quick start

1. Build on a macOS or Linux host (see [Build](#build)).
2. Install the official Android SDK Platform Tools and connect the supported
   device with USB debugging enabled.
3. Confirm ADB sees the device:

```sh
adb devices -l
```

Then:

```sh
./build/smt878u-ionstack-reroot -s SERIAL --preflight-only
./build/smt878u-ionstack-reroot -s SERIAL --validate-only
./build/smt878u-ionstack-reroot -s SERIAL
```

After the host reports success, verify root and open a shell:

```sh
adb -s SERIAL shell /data/local/tmp/su -c id
adb -s SERIAL shell /data/local/tmp/su
```

`-s SERIAL` is optional when exactly one ADB device is connected.

## Build

Requirements:

- macOS or Linux host with `clang`, `make`, and `adb`
- Android NDK (API 35 is the default build API)
- an arm64/compat32 target matching the profile above

```sh
make -j4
```

Override discovery when needed:

```sh
make NDK_ROOT=/path/to/android-ndk API=35 -j4
```

All artifacts are emitted under `build/`.

### Host platforms

The host controller supports macOS arm64, Linux x86_64, and Windows x86_64.
The Android device artifacts are identical across host platforms.

```sh
# native host controller only
make host

# Windows x86_64 controller with LLVM-MinGW
make host-windows \
  WINDOWS_CC=/path/to/llvm-mingw/bin/x86_64-w64-mingw32-clang
```

## Run

Start with the non-exploit profile check, then validation, then the full chain:

```sh
./build/smt878u-ionstack-reroot -s SERIAL --preflight-only
./build/smt878u-ionstack-reroot -s SERIAL --validate-only
./build/smt878u-ionstack-reroot -s SERIAL
```

Logs are written below `results/YYYY-MM-DD/` by default.

### Collect reboot / crash artifacts

```sh
./tools/collect_reboot_artifacts.sh SERIAL
```

## Using `su` after a successful run

The supported user-facing client is installed at `/data/local/tmp/su`. It
connects to the temporary root daemon through
`/data/local/tmp/temp_su.sock`. Do not move it into `/system/bin`, and do not
rely on it surviving reboot.

## Layout

| Path | What |
|---|---|
| `src/host/` | Host-side ADB orchestrator |
| `src/device/` | On-device reroot / perf helpers |
| `src/exploit/` | IonStack-derived exploit chain (SM-T878U offsets) |
| `src/trigger/` | Chainwalk / diagnostic probe |
| `tools/su_daemon.c` | Temporary `su` daemon client/server bits |
| `tools/collect_reboot_artifacts.sh` | Post-reboot artifact collector |
| `docs/` | Analysis notes and evidence trails (see [Documentation](#documentation)) |
| `build/` | Build outputs (gitignored) |
| `results/` | Run logs (gitignored) |
| `scratch/` | Local harness + run logs (gitignored) |

## Provenance

This tree started from the public `xpad2-ionstack-poc` packaging layout and an
IonStack CVE-2026-43499 source snapshot, then was re-ported to SM-T878U
(`gts7l` / `T878USQS8DXE1`).

- Combined project: `GPL-3.0-or-later` (`LICENSE`)
- IonStack-derived files under `src/exploit/` and `tools/su_daemon.c`: Apache-2.0
  provenance retained (`NOTICE`, `licenses/Apache-2.0.txt`)

## Security reports

Please do not include device identifiers, private firmware images, crash dumps,
or other sensitive data in a public issue. See `SECURITY.md`.

## Disclaimer

Provided **as-is**, without warranty of any kind. Authors and contributors are
not responsible for misuse, damage, or legal consequences arising from use of
this material.
