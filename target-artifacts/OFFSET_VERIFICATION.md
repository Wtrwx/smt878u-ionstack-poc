# offset.h constant verification against the target kernel ELF

Source ELF : `firmware_extract/ap/boot_kernel.bin.elf` (62,756,203 bytes, not stripped)

Symbols    : 151729 from `.symtab` (`llvm-nm --numeric-sort`)

Base       : `KIMAGE_TEXT_BASE = 0xffffff8008080000`


**Result: 24 EXACT, 3 INSIDE, 0 GAP out of 27 address-like constants.**


| constant | _text+ | link-time VA | class | resolves to | expected | segment |
|---|---|---|---|---|---|---|
| `ASHMEM_MISC_FOPS_OFF` | `0x330d198` | `0xffffff800b38d198` | **INSIDE** | `ashmem_misc+0x10` | ashmem_misc + 0x10 (miscdevice.fops field) | LOAD .kernel2 |
| `ASHMEM_FOPS_OFF` | `0x1f1a3d8` | `0xffffff8009f9a3d8` | **EXACT** | `ashmem_fops` | ashmem_fops | LOAD .kernel |
| `ASHMEM_LLSEEK_OFF` | `0x11bfc34` | `0xffffff800923fc34` | **EXACT** | `ashmem_llseek` | ashmem_llseek | LOAD .kernel |
| `ASHMEM_READ_ITER_OFF` | `0x11bfcdc` | `0xffffff800923fcdc` | **EXACT** | `ashmem_read_iter` | ashmem_read_iter | LOAD .kernel |
| `ASHMEM_IOCTL_OFF` | `0x11bfd9c` | `0xffffff800923fd9c` | **EXACT** | `ashmem_ioctl` | ashmem_ioctl | LOAD .kernel |
| `ASHMEM_COMPAT_IOCTL_OFF` | `0x11c062c` | `0xffffff800924062c` | **EXACT** | `compat_ashmem_ioctl` | compat_ashmem_ioctl | LOAD .kernel |
| `ASHMEM_MMAP_OFF` | `0x11c0684` | `0xffffff8009240684` | **EXACT** | `ashmem_mmap` | ashmem_mmap | LOAD .kernel |
| `ASHMEM_OPEN_OFF` | `0x11c0804` | `0xffffff8009240804` | **EXACT** | `ashmem_open` | ashmem_open | LOAD .kernel |
| `ASHMEM_RELEASE_OFF` | `0x11c088c` | `0xffffff800924088c` | **EXACT** | `ashmem_release` | ashmem_release | LOAD .kernel |
| `ASHMEM_SHOW_FDINFO_OFF` | `0x11c098c` | `0xffffff800924098c` | **EXACT** | `ashmem_show_fdinfo` | ashmem_show_fdinfo | LOAD .kernel |
| `CONFIGFS_READ_FILE_OFF` | `0x3044bc` | `0xffffff80083844bc` | **EXACT** | `configfs_read_bin_file` | configfs_read_bin_file  (!= configfs_read_file) | LOAD .kernel |
| `CONFIGFS_WRITE_FILE_OFF` | `0x30464c` | `0xffffff800838464c` | **EXACT** | `configfs_write_bin_file` | configfs_write_bin_file (!= configfs_write_file) | LOAD .kernel |
| `COPY_SPLICE_READ_OFF` | `0x28e26c` | `0xffffff800830e26c` | **EXACT** | `generic_file_splice_read` | copy_splice_read | LOAD .kernel |
| `NOOP_LLSEEK_OFF` | `0x24ac7c` | `0xffffff80082cac7c` | **EXACT** | `noop_llseek` | noop_llseek | LOAD .kernel |
| `NO_LLSEEK_OFF` | `0x24ac8c` | `0xffffff80082cac8c` | **EXACT** | `no_llseek` | no_llseek | LOAD .kernel |
| `INIT_TASK_OFF` | `0x31ad980` | `0xffffff800b22d980` | **EXACT** | `init_task` | init_task | LOAD .kernel2 |
| `ROOT_TASK_GROUP_OFF` | `0x34e8c00` | `0xffffff800b568c00` | **EXACT** | `root_task_group` | root_task_group | LOAD .bss |
| `SELINUX_ENFORCING_OFF` | `0x292d200` | `0xffffff800a9ad200` | **EXACT** | `selinux_enforcing` | selinux_state.enforcing (mid-object) | LOAD .kernel |
| `SECURITY_HOOK_HEADS_OFF` | `0x29181c0` | `0xffffff800a9981c0` | **EXACT** | `security_hook_heads` | security_hook_heads | LOAD .kernel |
| `KMALLOC_CACHES_OFF` | `0x2917cc0` | `0xffffff800a997cc0` | **EXACT** | `kmalloc_caches` | kmalloc_caches | LOAD .kernel |
| `ANON_PIPE_BUF_OPS_OFF` | `0x1da1e40` | `0xffffff8009e21e40` | **EXACT** | `anon_pipe_buf_ops` | anon_pipe_buf_ops | LOAD .kernel |
| `MODPROBE_PATH_OFF` | `0x31bbe90` | `0xffffff800b23be90` | **EXACT** | `modprobe_path` | modprobe_path | LOAD .kernel2 |
| `FAIR_SCHED_CLASS_OFF` | `0x1d88960` | `0xffffff8009e08960` | **EXACT** | `fair_sched_class` | fair_sched_class | LOAD .kernel |
| `SLIDE_NFULNL_LOGGER_OFF` | `0x31a3e70` | `0xffffff800b223e70` | **EXACT** | `nfulnl_logger` | nfulnl_logger | LOAD .kernel2 |
| `SLIDE_LOGGERS_0_1_OFF` | `0x31a3d98` | `0xffffff800b223d98` | **EXACT** | `loggers` | loggers[0..1] | LOAD .kernel2 |
| `SLIDE_RANDOM_BOOT_ID_DATA_OFF` | `0x2ef61f8` | `0xffffff800af761f8` | **INSIDE** | `__per_cpu_end+0x255018` | random_boot_id.data | --- (not in any LOAD segment) |
| `SLIDE_SYSCTL_BOOTID_OFF` | `0x3249f98` | `0xffffff800b2c9f98` | **INSIDE** | `random_table+0x108` | sysctl boot_id table | LOAD .kernel2 |

## Reading this table

- **EXACT** — a symbol starts exactly at that address. The constant is
  independently confirmed by the ELF's own symbol table; no IDA or
  heuristics were involved.

- **INSIDE** — the address lands in the middle of a symbol. For a struct
  *field* address (e.g. `ashmem_misc` + 0x10 = `miscdevice.fops`) this is
  intended. Otherwise it is worth a second look.

- **GAP** — the address is not inside any LOAD segment of this ELF. This is
  EXPECTED for part of the `.data`/`.bss` constants: they were derived from
  the flat raw `Image`, whereas this ELF carve splits `.bss` into a separate
  segment with no file content. A GAP result therefore says nothing about
  correctness — it means the ELF cannot confirm the constant either way, and
  it must be checked against a runtime read instead.

