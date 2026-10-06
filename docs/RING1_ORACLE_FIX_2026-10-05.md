# 环 1 判据修复与第一次正确测量 — 2026-10-05

## TL;DR

1. **GitHub 报告的核心前提对当前代码已过时。** `sendmsg` 车辆（`IONSTACK_PAINT_IOVLEN=8`）
   **已经**能写 `E+0x00..E+0x28`（`import_iovec` 把 8 个 iovec 拷进 `iovstack`，落点
   `E-0x58..E+0x28`）。已用 ELF 反汇编逐条核对。**换成 `process_vm_readv` /
   `tcp_zerocopy` / `multicast_waiter` 不是当前缺环。**
2. **发现并修复了让「环 1 从未落地」这一结论无法成立的判据 bug**：`verify_paint_gate()`
   从 `snap + FOPS_OFF` 读 `fake_fops->owner/llseek`，但 `snap` 是**页偏移**索引，而
   `fake_fops` 在**载荷偏移** `FOPS_OFF` 上（`payload_base = page_base + SKB_DATA_DELTA`，
   `SKB_DATA_DELTA = -0xE80`）。真实偏移是 `FOPS_OFF + SKB_DATA_DELTA = 0x180`。
   **旧判据恒定读一个零区**，因此 `case1_gate` 永远是 0。
3. **发现并修复了跑批脚本 bug**：`run_paint.sh` 的 `MARKER` 匹配 `paint-result`，
   而该行在 `verify_paint_gate()` **之前**打印 ⇒ 循环立刻 break、3 秒后杀掉设备进程
   ⇒ `ring1-read` 在 `scratch/runs/` 的 ~100 份日志里**一次都没出现过**
   （`grep -c ring1-read` 恒为 0）。环 1 判据实际上从未被读取。

## 1. 反汇编核对：sendmsg 车辆的几何（推翻报告前提）

用 NDK `llvm-objdump` 反汇编 `firmware_extract/ap/boot_kernel.bin.elf`：

| 符号 | 帧 | 关键指令 |
|---|---|---|
| `__arm64_sys_sendmsg` @ `0xffffff8009917cd4` | `sub sp, sp, #0x90` | 末尾直接 `bl ___sys_sendmsg`（**不经过 `__sys_sendmsg`**） |
| `___sys_sendmsg` @ `0xffffff80099179fc` | `sub sp, sp, #0x190` | `add x9, sp, #0x38` = `iovstack`；`sub x10, x29, #0x88` = `&address` |

设 `SP0` = 进入 `__arm64_sys_*` 时的 sp（`el0_svc` 无帧、`el0_svc_handler` 0x10、
`el0_svc_common` 0x40 ⇒ `SP0 = pt_regs - 0x50`，与既有约定一致）。则

```
___sys_sendmsg 帧基 = SP0 - 0x90 - 0x190 = SP0 - 0x220
iovstack = 帧基 + 0x38 = SP0 - 0x1e8 = E - 0x58     (E = SP0 - 0x190)
address  = 帧基 + 0xb8 = SP0 - 0x168 = E + 0x28
```

`copy_msghdr_from_user` → `import_iovec(type, uiov, nr_segs, fast_segs=8, uiov=&iovstack, ...)`
→ `rw_copy_check_uvector` 在 `nr_segs <= 8` 时走快路径，做
`copy_from_user(iovstack, uvector, 16*nr_segs)`。取 `nr_segs = 8` ⇒ 拷 0x80 字节，
覆盖 `E-0x58 .. E+0x28`，于是：

```
E+0x00 = iovstack[5].iov_len    E+0x08 = iovstack[6].iov_base
E+0x10 = iovstack[6].iov_len    E+0x18 = iovstack[7].iov_base
E+0x20 = iovstack[7].iov_len
```

`main.c` 把 `iov[1..7]` 留成 `{NULL, 0}`（`access_ok(NULL,0)` 为真），
所以这 5 个 qword **确实是用户可控的 0**。`E+0x28..E+0x50` 由 `msg_namelen=0x28`
的 `move_addr_to_kernel` 写入（task / lock / prio / deadline）。

⇒ **整个残余 waiter 都被涂到，`E+0x00..E+0x28` 不再是盲区。**
`___sys_sendmsg` 自己的帧只到 `E-0x90` 起（callee-saved 存 `帧基+0x140..0x190` = `E+0xb0..E+0x100`），
**不踩 waiter**。

结论：报告建议的「换车辆」在此处无收益；真正的缺口在别处（见 §3）。

## 2. Bug #1：环 1 页判据读错地址 0xE80

`snapshot_reclaim_page()` 的输出按**页偏移**索引（`util.c:1587-1593`：`out[i]` = `page_base + i`）。
而 `util.c:2459/2464`：

```c
uintptr_t payload_base = base + SKB_DATA_DELTA;   /* SKB_DATA_DELTA = -0xe80 */
fake_fops = payload_base + FOPS_TABLE_OFF;        /* FOPS_TABLE_OFF = FOPS_OFF = 0x1000 */
```

⇒ `fake_fops` 在页内的真实偏移 = `0x1000 - 0xe80 = 0x180`。
旧代码读 `snap + FOPS_OFF` = `page_base + 0x1000` —— 那是 fops 表（载荷 0x1000..~0x10e0）
与 fake_w0（载荷 0x2220）之间的**零填充区**，恒为 0。这正好解释 ~100 份日志里
清一色的 `owner=0 ok=1 | llseek=0 ok=0 | case1_gate=0`。

**修复**（`main.c:verify_paint_gate()`）：改用载荷实际安装的指针
`size_t fops_off = (uintptr_t)fake_fops - page_base;`，并把旧地址作为 `legacy@1000`
一并打印做 A/B。注意 `dump_reclaim_page_state()` 一直是对的
（`util.c:2008-2011` 用 `LOCK_OFF - fragment_bias`），所以它打印的
`lock_off=4d0 / w0_off=13a0 / task_off=2380` 可信 —— 这也独立印证了本修复。

**实机验证**（`scratch/runs/paint_20261005_193115.log`）：

```
[+] ring1-page fake_fops=ffffffc1b1070180 fops_off=180 lock_off=4d0
    owner=0000000000000000 want=0 ok=1 |
    llseek=ffffffc1b10713b8 want=ffffffc00338d198 ok=0 | case1_gate=0 |
    legacy@1000 owner=0000000000000000 llseek=0000000000000000
```

* `fops_off=180`、`lock_off=4d0` —— 与模型一致，修复生效。
* 修正后的 `llseek = base+0x13b8 = &fake_w0->pi_tree_entry`（= 形状行的 `fake_pi_entry`），
  即**载荷初值**，说明 `__rb_change_child` 的 stamp 仍未落地 —— 但这是**第一次真实的测量**。
* 旧地址 `legacy@1000 llseek=0` 直接证实了它读的是零区。

## 3. Bug #2：跑批脚本提前杀掉设备进程

`run_paint.sh` 原 `MARKER` 含 `paint-result`，而该行在 `verify_paint_gate()` 之前打印。
循环一命中就 break，`sleep 3` 后 `kill`，于是 `ring1-read` 从未执行。

修复：`MARKER` 去掉 `paint-result`，改为 `ring1-page|ring1-read|ring1 skipped|paint ABORT|\[host\] final`，
并把命中后的 `sleep` 从 3 s 提到 8 s（`verify_paint_gate()` 内有 500 ms 等待 + 页快照 + open/configfs 读）。
另外补上 `IONSTACK_PAINT_LOCK_DELTA` / `IONSTACK_PAINT_WAITER_TASK_MODE` 的转发
（host runner 本来就会转发所有 `IONSTACK_*`，显式列出只是消除歧义）。

## 4. 第一次正确测量说了什么

配置：`PI_RB_SHAPE=target-left`、`LOCK_OWNER_MODE=fake-task`、`WAIT_LOCK_WORD=0`、
`IOVLEN=8`、`PAINT_PRIO=0x7fffffff`、`PAINT_LOCK_DELTA=0x1cb0`（⇒ `waiter->lock` = SCRATCH 区）、
`PAINT_WAITER_TASK_MODE=init-task`。

结果：

```
paint: ... paint_lock=ffffffc1b1072180 paint_task=ffffff800b05d980   (SCRATCH / init_task)
paint-result verdict=painted survived=1 armed=1 consumer_calls=1 consumer_success=0 nice=19
page-dump tag=post-arm+200ms  first_diff=8000(pristine)  scratch=全 0
```

推理链（每一步都只用已证事实）：

1. `consumer_success=0` ⇒ `sched_setattr_tid(W)` 没返回。
   对照：`PAINT_PRIO=120`（探针值）的 run 一律 `cs=1`（`d2_r1/r2`、`ring1g`）。
   ⇒ `cs` 是有效的「门开/门关」指示器。
2. `cs=0` ⇒ 链走**越过了** `rtmutex.c:1135` 的
   `rt_mutex_waiter_equal(waiter, task_to_waiter(W))` 早退
   ⇒ `E->prio ≠ W->prio` ⇒ **涂写确实落地**。
3. 但 SCRATCH 区（`paint_lock`，载荷里被显式清零 `util.c:2977-2981`）**一个字节都没被写**
   （`scratch=` 全 0，且 `first_diff=8000(pristine)`）。
   ⇒ 链走**没有到达** `585` 的成功 trylock（那会写 `SCRATCH+0x00 = 1`），
   也没有到达 `706` 的 unlock（那会留 `owner_cpu = ffffffff`）。

⇒ **`main.c:744-773` 记录的「DELTA 探针会干净走完 585→698」这一模型未被证实，
且本次测量与它矛盾。** 崩点/挂点位于 `502..585` 区间，不是 664/685/723。

## 5. 下一步（按信息量排序）

1. **先钉住 `502..585` 的挂点。** 最小实验：DELTA 配置 + `IONSTACK_FOPS_WAIT_LOCK_WORD=1`。
   * 若仍 `cs=0` 且 `scratch` 全 0 ⇒ 与「585 retry 自旋」同签名，无法区分；
     改用 **`wait_lock_word=1` + `LOCK_OWNER_MODE=none` + 非 DELTA**（`a2_r2`/`w1_r1` 的冻结构型）
     作为「585 可达」的正对照，再对照 DELTA 构型。
   * 更干净的做法：给 `rt_mutex_adjust_prio_chain` 加一个**用户态可见的分段计数器**
     —— 把 `waiter->lock` 指向一个「探针 rt_mutex」，其 `wait_lock`/`owner`/`rb_node`
     分三次由链走写入，回读即可知道走到哪一步。目前 `scratch=` 已具备这个能力，
     只需确认它确实被读到（本次为 0 ⇒ 说明没走到）。
2. **确认 SCRATCH 区在 fire 时刻确实为 0。** 本次 `first_diff=8000(pristine)` 说明
   载荷页与用户态副本逐字节一致，间接支持；但 `binwrite_target == paint_lock`
   （`util.c:2474`，`PAGE_PAYLOAD_FOPS`）是个隐患 —— 一旦 ring-2 的 configfs 写原语
   被 arm，`SCRATCH+0x00` 会变成节点指针，585 的 trylock 必然失败。
   **建议：把 DELTA 探针的落点从 `SCRATCH_OFF` 换到一个专属的、永不被 binwrite 使用的
   页内偏移**（例如新增 `PROBE_LOCK_OFF`）。
3. 只有在 2 成立之后，才值得回头看 664/685/716/723。
4. 报告里唯一值得吸收的点是「用用户态可见副作用当判据」——本项目已经有
   （`WAIT_LOCK_WORD` 刹车 + 页回读），问题在于**回读地址算错了**，已修。

## 6. 未采纳（附理由）

| 报告建议 | 结论 |
|---|---|
| 换 `process_vm_readv` 当涂栈载体 | **不需要**：`iovstack` 路线已覆盖 `E+0x00..E+0x28`（§1）。且 `process_vm_readv` 的 `iovec` 元素受 `access_ok` 约束，`iov_base` 只能是用户地址，反而**不能**携带内核指针（`lock`/`task`），比 `sendmsg` 的 `msg_name` 通道更弱。 |
| 换 `tcp_zerocopy` / `multicast_waiter` | 同上；且需要先在 ELF 里量出帧几何，当前无证据优于现方案。 |
| 放弃 `pselect6`（`SELECT_STACK_ALLOC=256`） | 报告的「几何不可行」只针对 `get_fd_set` 的 in/out/ex（全局词 0..14）。本项目实际用的是 **res-race**（`res_out` = 全局词 20..24，由 `do_select` 写回），机制上覆盖 waiter 词 4..8。结论：**pselect 不必放弃**，但它是独立路线，与本次修复无关。 |
| 用共享页 CAS 当判据 | 已在做（`WAIT_LOCK_WORD` + 页回读）；真正缺的是**回读地址正确**，已修。 |
