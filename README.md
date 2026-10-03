# smt878u-ionstack-poc

> [!CAUTION]
> **THIS PROJECT IS UNFINISHED — IT DOES NOT WORK YET.**
> There is **no working root** on any device as of 2026-10-03. Do **not** expect
> the quick-start below to succeed. Read [Current status](#current-status-unfinished)
> before building or running anything.

> [!WARNING]
> **STATUS: WORK IN PROGRESS / BLOCKED**
> - **Not achieved:** persistent or even one-shot `root` on SM-T878U.
> - **Last verified failure:** all stack-reclaim attempts crash the device
>   (`CONFIG_PANIC_ON_OOPS=y`) before the write primitive fires.
> - **Blocker:** kernel crash forensics is unavailable to `uid 2000 shell`
>   (`/proc/kmsg`, `/proc/last_kmsg`, `/sys/fs/pstore`, `dmesg` → all `EACCES`),
>   so each iteration costs a reboot and yields no usable stack trace.
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
account of where the chain stands. Everything below is measured on real
hardware (SM-T878U, `T878USQS8DXE1`, kernel `4.19.113-27114284`), not theory.

### What is proven to work

| Stage | Status | Evidence |
|---|---|---|
| Target identity + KASLR leak | working | `[reroot] LEAK_OK kaslr_base=… task=…` (perf side-channel) |
| CVE trigger: `FUTEX_CMP_REQUEUE_PI` → `-EDEADLK` | **working** | `[*] requeue ret=-1 errno=35` — `EDEADLK == 35` on Linux |
| Buggy rollback leaves dangling `pi_blocked_on` | matches upstream fix | upstream `3bfdc63936dd` changes `current->pi_blocked_on` → `waiter->task->pi_blocked_on` |
| `struct rt_mutex_waiter` layout (4.19) | **verified from source** | `tree_entry@0x00` `pi_tree_entry@0x18` `task@0x30` `lock@0x38` `prio@0x40` `deadline@0x48` |
| Stack geometry `paint == rt_waiter + 0x28` | **verified 4×** incl. objdump | `rt_waiter = do_futex_sp+0xC0`; `address = ___sys_sendmsg_sp+0xB8` |

### What is NOT working

1. **Stack reclaim does not land.** Three instrumented runs
   (`scratch/runs/paint*_20261001_19*.log`) all crashed the device.
   A survivable oracle (`IONSTACK_PAINT_PRIO=139`) was added: if the forged
   waiter lands, `rt_mutex_adjust_pi()` early-returns at `rtmutex.c:1135` and
   the device **survives**. It crashed every time ⇒ the forged waiter never
   reaches the residual `rt_mutex_waiter`.
2. **The published vehicle is unavailable here.** The only public successful
   exploit of this CVE (NebuSec, *IonStack part II*) reclaims the frame with
   `prctl(PR_SET_MM, PR_SET_MM_MAP, …)`. This kernel ships
   `# CONFIG_CHECKPOINT_RESTORE is not set`, so that syscall is compiled out.
   It also never uses `sendmsg` — our vehicle — which is very likely the root
   cause of (1).
3. **No crash forensics.** Every crash is currently undiagnosable (see blocker
   above). Until this is fixed, further payload shapes are blind attempts.

### Immediate next steps (in priority order)

1. Restore observability (ramoops / `/data/log` / alternate SELinux domain).
2. Replace the `sendmsg` reclaim vehicle with `pselect6` (route already
   present) or `process_vm_readv` (`CONFIG_CROSS_MEMORY_ATTACH=y`).
3. Switch from one blocking call to repeated stamping racing the consumer,
   plus memfd + `fallocate(FALLOC_FL_PUNCH_HOLE)` window stretching.
4. Only then convert the write primitive into privilege escalation.

### Unrelated open bug

`fops.c:3157 reason=selinux_write ret=-1 errno=22 EINVAL` — still unresolved.

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
| `build/` | Build outputs (gitignored) |
| `results/` | Run logs (gitignored) |

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
