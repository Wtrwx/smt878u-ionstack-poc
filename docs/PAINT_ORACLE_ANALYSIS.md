# paint 判据的理论分析：三次崩溃是「涂写已落地」的证据，不是反证

> 目标机：SM-T878U / gts7l，`T878USQS8DXE1`，内核 `4.19.113-27114284`
> 权威二进制：`firmware_extract/ap/boot_kernel.bin.elf`
> 源码参考：`Kernel_T878USQS8DXE2/`（版本与实机不完全一致，**所有偏移/指令一律以二进制为准**）
> 日期：2026-10-03

---

## 0. 一句话结论

当前 PoC 卡住的**不是几何、不是触发路径、也不是涂写通道** —— 这三样本轮已逐条用设备二进制复核通过。
卡住的是**判据本身**：

1. `IONSTACK_PAINT_PRIO` 的「探针」取值**算错了 1**（用了 `121`，而门要求 `120`），
   导致该探针**在任何情况下都会崩**；
2. 它的**读法正好是反的** —— 崩溃意味着涂写**落地了**，存活才意味着没落地。

⇒ **三次 paint 崩溃不能推出「涂写未落地」。按正确读法，它是涂写已经落地的证据。**
⇒ 并且可以证明：**在本内核上「存活 / 崩溃」在原理上不可能作为这条通道的判据**，必须改用用户态可见的副作用观测（§6）。

---

## 1. 触发链（源码级，本轮补上了此前缺失的一环）

### 1.1 三线程环

| 线程 | 动作 | 结果 |
|---|---|---|
| **W** | `FUTEX_LOCK_PI(f_pi_chain)` | W 持有 `f_pi_chain` |
| **W** | `FUTEX_WAIT_REQUEUE_PI(f_wait → f_pi_target)` | `futex_q.rt_waiter = &rt_waiter`（**W 自己的栈**，futex.c:3274），阻塞 |
| **M** | `FUTEX_LOCK_PI(f_pi_target)` | M 持有 `f_pi_target` |
| **M** | `FUTEX_LOCK_PI(f_pi_chain)` | M 阻塞（W 持有）⇒ `M->pi_blocked_on = M_waiter` |
| **R** | `FUTEX_CMP_REQUEUE_PI(f_wait → f_pi_target)` | 见下 |

`futex_requeue()`（R 上下文）在 futex.c:2156 调用：

```c
ret = rt_mutex_start_proxy_lock(&pi_state->pi_mutex,
                                this->rt_waiter,     /* ← W 栈上的 rt_waiter */
                                this->task);         /* ← W */
```

`rt_mutex_start_proxy_lock()`（rtmutex.c:1797-1810）：

```c
	ret = __rt_mutex_start_proxy_lock(lock, waiter, task);
	if (unlikely(ret))
		remove_waiter(lock, waiter);      /* ← current == R，waiter == W 的对象 */
```

`__rt_mutex_start_proxy_lock()` → `task_blocks_on_rt_mutex()`（rtmutex.c:929-1009）：

```c
	waiter->task     = task;          /* 954-957: 写入 W / &pi_mutex / W->prio / W->dl.deadline */
	waiter->lock     = lock;
	waiter->prio     = task->prio;
	waiter->deadline = task->dl.deadline;
	rt_mutex_enqueue(lock, waiter);   /* 962 */
	task->pi_blocked_on = waiter;     /* 964: ★ W->pi_blocked_on = &W 栈上的 rt_waiter */
	...
	res = rt_mutex_adjust_prio_chain(owner, chwalk, lock, next_lock, waiter, task);  /* 1004 */
```

链走 `W → f_pi_target → M → f_pi_chain → W` 成环 ⇒ 返回 **`-EDEADLK`**（设备实测 `errno=35`，`include/uapi/asm-generic/errno.h:7`）。

### 1.2 ★ 本轮补上的一环：W 的退出路径**绕过了 cleanup**

这是此前文档里一直含糊的地方。`futex_wait_requeue_pi()`（futex.c:3296-3302）：

```c
3296	futex_wait_queue_me(hb, &q, to);                       /* W 睡眠 */
3298	spin_lock(&hb->lock);
3299	ret = handle_early_requeue_pi_wakeup(hb, &q, &key2, to);
3300	spin_unlock(&hb->lock);
3301	if (ret)
3302		goto out_put_keys;                             /* ← ★ 直接返回，不进 3314-3374 */
```

`handle_early_requeue_pi_wakeup()`（futex.c:3159-3190）：

```c
	if (!match_futex(&q->key, key2)) {
		plist_del(&q->list, &hb->chain);
		hb_waiters_dec(hb);
		ret = -EWOULDBLOCK;
		if (timeout && !timeout->task)
			ret = -ETIMEDOUT;
		else if (signal_pending(current))
			ret = -ERESTARTNOINTR;
	}
	return ret;                                            /* ← 只动 q，不碰 pi_blocked_on */
```

**为什么这个分支必然成立**：`-EDEADLK` 时 R 在 futex.c:2171-2187 走的是

```c
			} else if (ret) {
				this->pi_state = NULL;
				put_pi_state(pi_state);
				break;                 /* ← break 掉了 */
			}
		}
		requeue_futex(this, hb1, hb2, &key2);   /* 2189 —— 没有执行 */
```

⇒ W 的 `futex_q.key` 仍是 `key1` ≠ `key2` ⇒ `handle_early_requeue_pi_wakeup()` 返回 `-ETIMEDOUT`（非零）
⇒ `goto out_put_keys`（3301-3302）
⇒ **futex.c:3343 的 `rt_mutex_wait_proxy_lock()` 与 3346 的 `rt_mutex_cleanup_proxy_lock()` 全都不执行。**

**而 `rt_mutex_cleanup_proxy_lock()` 是唯一能在 W 自己上下文里清掉 `pi_blocked_on` 的地方**（它内部 1911-1914 会调 `remove_waiter(lock, waiter)`，此时 `current == W`，`current->pi_blocked_on = NULL` 恰好正确）。

⇒ **`W->pi_blocked_on` 保持指向 W 自己栈上的 `rt_waiter`，W 返回用户态后该指针悬垂。悬垂成立，且不存在「自愈」路径。**

> 这一条同时**排除了** `RTMUTEX_WEAPONIZATION.md` §15.18(4) 的第 1 条怀疑
> （"`W->pi_blocked_on` 并未指向 `do_futex` 帧里的 `rt_waiter`"）。

---

## 2. 残余 waiter 的状态（源码 + 反汇编实测）

`remove_waiter()`（rtmutex.c:1068-1119，设备二进制 `0xffffff8008148d74`）：

| 地址 | 指令 | 含义 |
|---|---|---|
| `0x8148da8` | `mrs x20, SP_EL0` | `x20 = current` = **R** |
| `0x8148dac` | `add x21, x20, #0x8c8` | `&R->pi_lock` |
| `0x8148dc8/0x8148dd0` | `bl rb_erase_cached` | 仅当 `!RB_EMPTY_NODE(&waiter->tree_entry)` |
| `0x8148dd4` | `str x23, [x23]` | `RB_CLEAR_NODE(&waiter->tree_entry)` ⇒ `__rb_parent_color = &waiter`（**W 的内核栈地址**） |
| **`0x8148ddc`** | **`str xzr, [x20, #0x8f8]`** | **`current->pi_blocked_on = NULL`（清的是 R，不是 W）** |

残余 waiter（`rt_waiter = E-0x190`，`E` = syscall 入口 SP）的字段状态：

| 偏移 | 字段 | 值 | 来源 |
|---|---|---|---|
| `+0x00` | `tree_entry.__rb_parent_color` | `&waiter`（`RB_CLEAR_NODE`，**栈地址**） | `remove_waiter` → `rt_mutex_dequeue` → `RB_CLEAR_NODE` |
| `+0x18` | `pi_tree_entry` | `RB_CLEAR_NODE` | `remove_waiter` → `rt_mutex_dequeue_pi` |
| `+0x30` | `task` | **W** | rtmutex.c:954 |
| `+0x38` | `lock` | **`&P->pi_mutex`（合法内核地址）** | rtmutex.c:955；`P` 未被释放（`put_pi_state` 走 `pi_state_cache`） |
| `+0x40` | `prio` | **120** | rtmutex.c:957 写入 `W->prio`，而 M 已停靠把 W clamp 到 120（见 §4.2） |
| `+0x48` | `deadline` | `W->dl.deadline` | rtmutex.c:958 |

### 2.1 推论 A（决定性）：**未涂写的残余 waiter 是完全自洽的，不可能崩**

- `sched_setattr(W)` → `rt_mutex_adjust_pi(W)` 在 rtmutex.c:1135 比较 `waiter->prio (120) == W->prio (120)` ⇒ **早退**；
- 即使不早退，`lock = &P->pi_mutex` 是**合法内核地址** ⇒ rtmutex.c:585 的 `raw_spin_trylock(&lock->wait_lock)` 不会 fault。

⇒ **「本构型下不涂写」不可能产生 `rtmutex.c:585` 崩溃。** 所有 `585` 崩溃都必然对应「`waiter->lock` 被外部改写过」。

### 2.2 推论 B（写原语）：**`rb_erase` 那条路是死的**

`rt_mutex_dequeue()`（rtmutex.c:294-301）：

```c
static void
rt_mutex_dequeue(struct rt_mutex *lock, struct rt_mutex_waiter *waiter)
{
	if (RB_EMPTY_NODE(&waiter->tree_entry))      /* ← 残余 waiter 为真 */
		return;                                  /* ← 直接返回，rb_erase 不执行 */
	rb_erase_cached(&waiter->tree_entry, &lock->waiters);
	RB_CLEAR_NODE(&waiter->tree_entry);
}
```

`remove_waiter()` 已经把 `tree_entry` 设成 `RB_CLEAR_NODE` ⇒ **之后每一次 `rt_mutex_dequeue()`（包括 rtmutex.c:664 那次）都会早退。**

⇒ **唯一活着的写原语是 `rt_mutex_enqueue()`（rtmutex.c:685）→ `rb_insert_color_cached()` → `__rb_insert()` 的 Case 3。**
（与 §14.5/§15.6 的结论一致；此处补上"为什么 664 那条路必然不可用"的源码依据。）

⚠️ **并且 685 有前置条件**：若 `lock->waiters.rb_root.rb_node == NULL`，则 `rb_link_node()` 之后 `__rb_insert()` 看到 `parent == NULL` 会立刻 `return`（`rb_set_parent_color(node, NULL, RB_BLACK)`），**一个字节都不写**。
⇒ 这正是 `IONSTACK_FOPS_PI_RB_SHAPE=rbinsert` 存在的理由：**必须让 `lock->waiters` 在 685 时非空且形状可控。**

---

## 3. 涂写通道：`sendmsg` 的双栈拷贝（第 5 次确认，几何无误）

`___sys_sendmsg()` 设备二进制 `0xffffff80099179fc`：

| 地址 | 指令 | 含义 |
|---|---|---|
| `0x99179fc` | `sub sp, sp, #0x190` | 帧 0x190 |
| `0x9917a08` | `add x29, sp, #0x140` | 帧基 |
| `0x9917a38` | `add x9, sp, #0x38` | `iovstack` @ `sp+0x38` |
| `0x9917a3c` | `sub x10, x29, #0x88` | `&address` = `sp+0xB8` |
| `0x9917a48` | `str x10, [x2]` | `msg_sys->msg_name = &address` |
| `0x9917a5c` | `bl copy_msghdr_from_user` | **`address` 拷贝发生在这里面** |

`__copy_msghdr_from_user()`（`net/socket.c:2037-2044`）：

```c
	if (msg.msg_name && kmsg->msg_namelen) {
		if (!save_addr) {                          /* ___sys_sendmsg 传 NULL ⇒ 成立 */
			err = move_addr_to_kernel(msg.msg_name,     /* 用户指针 */
						  kmsg->msg_namelen, /* ulen ≤ 0x80，零校验 */
						  kmsg->msg_name);   /* = &address，内核栈 */
```

⇒ 用户可控的 `msg_namelen` 字节**裸拷**到 `___sys_sendmsg` 的 `&address`。

相对 `E` 的绝对位置（`__arm64_sys_futex` 帧 `0x70`、`do_futex` 帧 `0x1e0`、`rt_waiter = do_futex_sp + 0xc0`）：

```
rt_waiter   = E - 0x190        （10 次指令级确认：0x818e67c add x0,sp,#0xc0 → bl rt_mutex_init_waiter）
address     = E - 0x168
⇒ address   = rt_waiter + 0x28
```

载荷落点（`main.c:666-670`）：

| `paint[]` 偏移 | 写入地址 | 命中字段 |
|---|---|---|
| `+0x00` | `rt_waiter+0x28` | `pi_tree_entry.rb_left` |
| `+0x08` | `rt_waiter+0x30` | `task` |
| `+0x10` | `rt_waiter+0x38` | **`lock`** |
| `+0x18` | `rt_waiter+0x40` | **`prio`** |
| `+0x20` | `rt_waiter+0x48` | `deadline` |

⇒ **几何、载荷布局全部正确。**（`E` 基准约定相差 8 字节不影响 `+0x28` 差值。）

### 3.1 为什么 `msg_iovlen=1` 不会破坏残余 waiter

`iovstack` @ `sp+0x38` = `E-0x1e8`，8 项 × 16B ⇒ 覆盖 `[E-0x1e8, E-0x168)`。
`msg_iovlen=1` ⇒ 只写 `iovstack[0]` = `[E-0x1e8, E-0x1d8)`，**碰不到 `rt_waiter+0x00 = E-0x190`** ✓
（`E-0x190` 落在 `iovstack[5].iov_len` 的位置，正好被跳过。）

⇒ 残余的 `tree_entry = RB_CLEAR_NODE` 得以保留 ⇒ §2.2 的「664 早退」成立 ⇒ 设计意图自洽。

---

## 4. 三次 paint 全崩的真正原因：判据算错了 1

### 4.1 门在哪

`rt_mutex_adjust_pi()`（rtmutex.c:1126-1147）：

```c
	waiter = task->pi_blocked_on;
	if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task))) {
		raw_spin_unlock_irqrestore(&task->pi_lock, flags);
		return;                       /* ← 门：早退，永不读 waiter->lock */
	}
	next_lock = waiter->lock;          /* 1139 */
```

`rt_mutex_waiter_equal()`（rtmutex.c:252-269）在非 DL 时**只比 `prio`**：

```c
	if (left->prio != right->prio)
		return 0;
	if (dl_prio(left->prio))
		return left->deadline == right->deadline;
	return 1;
```

⇒ **门的条件就是 `waiter->prio == task->prio`。**（`task_to_waiter()` 是复合字面量，不读 `waiter->task`。）

同一条门在链走入口 rtmutex.c:565-570 再出现一次，且 `MIN_CHAINWALK` 下 `detect_deadlock = false` ⇒ 同样 `goto out_unlock_pi` 安全退出。

### 4.2 `W->prio` 在 fire 时刻 = **120**（完整推导）

| 步骤 | 事实 | 依据 |
|---|---|---|
| 1 | `IONSTACK_W_NICE=1` ⇒ `W->static_prio = 121`，`W->normal_prio = 121` | `main.c:717`，`NICE_TO_PRIO(n) = n + 120` |
| 2 | **M 停靠在 `f_pi_chain`（W 持有）上** ⇒ `task_blocks_on_rt_mutex()` 里 `rt_mutex_adjust_prio(owner = W)` ⇒ **`W->prio = min(121, M->prio = 120) = 120`** | rtmutex.c:973-977；`M` 是 nice-0 CFS ⇒ `M->prio = 120` |
| 3 | R 发起 requeue ⇒ `task_blocks_on_rt_mutex(pi_mutex, W_rt_waiter, W, FULL)` ⇒ **`W_rt_waiter->prio = W->prio = 120`** | rtmutex.c:957 |
| 4 | consumer 的 `sched_setattr_tid()`（`IONSTACK_CONSUMER_REAL_NICE` 未设 ⇒ 走 flip 分支）⇒ `attr.sched_nice = 0` ⇒ `__setscheduler` 里 `p->prio = normal_prio(W) = NICE_TO_PRIO(0) = 120`，再 `rt_effective_prio(W, 120) = min(120, W->pi_top_task->prio)` | `util.c:1071-1074`；`sched/core.c:4911/4919/4940-4942` |
| 5 | `W->pi_top_task = M`（M 停靠在 W 持有的 `f_pi_chain` 上，`W->pi_waiters` 里有 `M_waiter`）⇒ `rt_effective_prio = min(120, 120) = 120` | rtmutex.c:336-345；反汇编 `0x80fb508-0x80fb51c`（`ldr x9,[x19,#0x8f0]` = `pi_top_task`） |

⇒ **fire 时刻 `W->prio = 120`。**

> **PoC 自己的代码已经把这个事实写下来了**（`main.c:1531-1544`）：
> > "`task_blocks_on_rt_mutex()` freezes `W_waiter->prio = W->normal_prio (121)` instead of the **clamped 120** …
> > `rt_mutex_adjust_prio(W)` sets `W->prio = min(W->normal_prio, M->prio)`, so
> > `/proc/<W>/stat` field 18 drops from `120+nice(W)` to **120** the moment M blocks."
>
> 并且代码里 `want = 120 - 100 = 20`。
> **⇒ 残余 `waiter->prio` 也是 120，fire 时刻的 `W->prio` 也是 120。**

### 4.3 判据取值与读法

| 运行 | `PAINT_PRIO` | `waiter->prio`（落地） | `W->prio` | 门（1135） | 必然结果 |
|---|---|---|---|---|---|
| `paintprobe_20261001_191941` | **121** | 121 | 120 | **开** | 链走 → `579 lock = fake_lock` → `585` → **崩** |
| `paintprobe139_20261001_192402` | **139** | 139 | 120 | **开** | 同上 → **崩** |
| `paintfill139_20261001_193311` | **139** | 139 | 120 | **开** | 同上 → **崩** |

**⇒ 三次都是「门必然打开」，与涂写是否落地无关。崩溃与存活不含信息。**

### 4.4 而且读法是反的

| 实际情形 | `waiter->prio` | `W->prio` | 门 | 现象 |
|---|---|---|---|---|
| 涂写**落地** | 121（涂的） | 120 | **开** | 链走 ⇒ `579 lock = fake_lock` ⇒ `585` ⇒ **崩** |
| 涂写**未落地** | **120（内核在 rtmutex.c:957 写入的残余值，不是栈垃圾）** | 120 | **关** | 1135 早退 ⇒ **存活** |

⇒ `RTMUTEX_WEAPONIZATION.md` §15.16(5) 的结论 **「三种配置全部崩溃 ⇒ 涂写没有落地」是反的**。
⇒ **正确读法：三次崩溃 = 涂写成功落地。**

### 4.5 更硬的结论：**「存活/崩溃」在原理上不可能当判据**

由 §2.1：**未涂写的残余 waiter 完全自洽**（`prio` 120 == 120、`lock` = 合法 `&P->pi_mutex`），任何配置下都不崩。
由 §4.4：**涂写落地且 `prio == 120` 时也不崩**（门关）。

⇒ 「存活」同时覆盖「落地」与「未落地」两种情形；「崩溃」只说明「`prio` 被写成 ≠ 120 且 `lock` 非法」。
⇒ **这条通道必须改用「用户态可见的副作用观测」**（§6 P0-2）。

---

## 5. 落地之后为什么还崩：`fake_lock` 之后的路

`rt_mutex_adjust_prio_chain()` 的 `requeue` 语义（rtmutex.c:448-462）：

```c
	bool requeue = true;
	detect_deadlock = rt_mutex_cond_detect_deadlock(orig_waiter, chwalk);
```

`rt_mutex_adjust_pi()` 传 `chwalk = RT_MUTEX_MIN_CHAINWALK`、`orig_waiter = NULL`
⇒ `detect_deadlock = false`
⇒ rtmutex.c:552-570 的两个分支在 `!detect_deadlock` 时都走 `goto out_unlock_pi`，**不会**把 `requeue` 置 false
⇒ **`requeue` 保持 `true`** ⇒ **链走确实会走到 664 / 685 / 723-725** ✓（原计划成立）。

关键节点：

| 行 | 内容 | 备注 |
|---|---|---|
| 507 | `waiter = task->pi_blocked_on` | = 被涂的对象 |
| 518 | `if (!waiter) goto out_unlock_pi` | 涂写没落地 + `pi_blocked_on` 为 NULL 时的安全出口 |
| 537 | `if (next_lock != waiter->lock) goto out_unlock_pi` | `next_lock` 由 1139 从**同一个** `waiter->lock` 读出 ⇒ **恒等，救不了** |
| 565 | `rt_mutex_waiter_equal(...)` 门 | 同 4.1 |
| 579 | `lock = waiter->lock` | = `fake_lock` |
| **585** | `raw_spin_trylock(&lock->wait_lock)` | `fake_lock+0x00` 必须是「未加锁的 spinlock」（全 0 即可） |
| **600** | `if (lock == orig_lock \|\| rt_mutex_owner(lock) == top_task)` | **`orig_lock = NULL`、`top_task = W` ⇒ 若 `rt_mutex_owner(fake_lock) == W` 则安全退出** |
| 664 | `rt_mutex_dequeue(lock, waiter)` | **早退（`RB_EMPTY_NODE`）** ⇒ 不写 |
| **685** | `rt_mutex_enqueue(lock, waiter)` | **★ 唯一活着的写原语**（`rb_insert_color` Case 3） |
| 698-700 | `task = rt_mutex_owner(lock)`；`get_task_struct(task)` | `fake_lock+0x20` 必须合法 |
| 702 | `raw_spin_lock(&task->pi_lock)` | `task+0x8c8` 必须可锁 |
| 716 | `next_lock = task_blocked_on_lock(task)` | `task+0x8f8` 必须为 NULL 或指向合法对象 |

现在 `IONSTACK_FOPS_LOCK_OWNER_MODE=fake-task` ⇒ `rt_mutex_owner(fake_lock) = fake_task ≠ W`
⇒ **不会在 600 退出** ⇒ 继续走 664/685/698…
⇒ **`fake_task` 必须是自洽的 `task_struct`**（`usage@0x68`、`pi_lock@0x8c8`、`pi_waiters@0x8e0`、`pi_top_task@0x8f0`、`pi_blocked_on@0x8f8`、`dl.deadline@0x430`）。

`FAKE_TASK_OFF = 0x3200`、`SKB_SEND_SIZE = 0x10000`（`offset.h:133`、`common.h:64`）
⇒ `fake_task + 0x8f8 = payload_base + 0x3AF8`，**在 64 KB 缓冲区内，空间充足** ⇒ 崩溃点不在这里，而在字段内容。

---

## 6. 该怎么解决 —— 可执行清单

### P0（不需要新 dump，立刻可做）

**P0-1　把探针取值改对，消掉「三次崩溃」这个假异常**

```
IONSTACK_PAINT_PRIO=120        # 不是 121，不是 139
```
（保持 `IONSTACK_CONSUMER_REAL_NICE` 未设 ⇒ `sched_nice` 被强制为 0 ⇒ `W->prio = 120`。）

- **预测：存活。**
- 意义：确认「残余 waiter 自洽」+「门在 120==120 时关闭」。
- ⚠️ **这条不能证明涂写落地**（落地 120 与未落地 120 同效）。它只是把假异常消掉。

**P0-2　换判据：用用户态可见的副作用，而不是存活/崩溃**

把 `fake_lock` 指向**用户可读页的内核线性映射别名**（PoC 已有 `ashmem`/pipe 页 + 内核地址通道，见 `util.c:init_ashmem_path()` / `snapshot_reclaim_page()` / `tee()` 读回）：

- 链走在 585 对 `*(u32 *)fake_lock` 做 `raw_spin_trylock`（CAS `0 → 1` 并置位）；
- **用户态直接读那个页：看到 `0 → 1` 就是「涂写落地 + 链走真的走到了 579/585」的铁证**，且**完全不需要任何 dump**；
- 这同时是**几何的最终验证** —— 只有精确命中 `waiter+0x38` 才能让 `lock = fake_lock`。

**P0-3　修 `IONSTACK_PAINT_FILL` 的语义**

现在 `PAINT_FILL=1` 把整个 0x80 填成 `prio`，于是 `lock` 也被填成 `prio` 值（非法地址）⇒ **一旦落地必崩**，这条配置**永远无法给出信息**。
应改成：填 0x80，但**末尾 8 字节强制回写一个合法 `lock`**。

### P1（让链走可控，把写原语真正跑出来）

**P1-4　给 `IONSTACK_FOPS_LOCK_OWNER_MODE` 加第三个模式 `owner-is-W`**

把 `*(u64 *)(fake_lock + 0x20)` 直接写成 **W 的 `task_struct` 地址**（PoC 若能拿到）：

- **落地** ⇒ `lock = fake_lock` ⇒ 585 trylock 成功 ⇒ **600 `rt_mutex_owner(lock) == W == top_task` ⇒ 安全退出 ⇒ 存活**；且 585 的 CAS 会改 `fake_lock+0`（配合 P0-2 读回即双向可判）；
- **未落地** ⇒ `lock = &P->pi_mutex` ⇒ `owner = M ≠ W` ⇒ 走到 698 `task = M`（合法）⇒ … ⇒ 最终在 `f_pi_chain` 上 `owner = W == top_task` ⇒ **600 安全退出 ⇒ 也存活**。

⇒ **配合 P0-2 的读回，这是一个「双向可判」且永不崩溃的构型。**

**P1-5　`fake_task` 逐字段自洽**

链走会碰的四个字段必须核：`pi_blocked_on@0x8f8`（NULL 或合法）、`pi_lock@0x8c8`（可锁自旋锁）、`usage@0x68`（可递增）、`dl.deadline@0x430`（可读）。

**P1-6　写原语只押 685，不要押 664**

见 §2.2：`rt_mutex_dequeue()` 因 `RB_EMPTY_NODE` 必然早退。因此必须保证 `lock->waiters` 在 685 时**非空且形状可控**，否则 `__rb_insert()` 在 `parent == NULL` 时立刻 `return`，一个字节都不写。

### P2（时序，消除不确定性）

**P2-7　把 W 在「futex 返回 → paint」之间的 `pr_*` 全部去掉或改成无害写　✅ 已实施**

`waiter_thread()` 在 futex 返回与 `sendmsg` 之间有一次 `pr_success(...)`（原 `main.c:764`），`sendmsg_paint_waiter()` 里 paint 之前还有一次 `pr_info(...)`（原 `main.c:672`）。

`fops.c:396-404` 已经把这条教训记录在案：

> **!!! TIMING CONSTRAINT !!!**
> Every `pr_info()` is a `write()` syscall on the waiter thread; its kernel frame is allocated from the same stack top as `do_futex`'s, so it reuses the very slot that holds the residual `rt_waiter` (SP0-0x190) and destroys the paint before the consumer's `sched_setattr()` can read it. Observed consequence: `waiter->lock` read back as `0x6e` (a stale frame word) instead of the painted `fake_lock`, and `_raw_spin_trylock()` faulted in `rt_mutex_adjust_prio_chain()`.

**pselect 路线正是死在这里。**

**⚠️ 本节上一版写的「`write` 帧够不到 `E-0x190`」是错的 —— 实际是「精确命中」。**
本轮用 `llvm-objdump` 把整条链的 `sub sp, sp, #N` 全部取出来：

| 函数 | 帧 | 进入时的 sp |
|---|---|---|
| `__arm64_sys_write` | `0x10` | `SP0-0x10` |
| `ksys_write` | `0x40` | `SP0-0x50` |
| `vfs_write` | `0x40` | `SP0-0x90` |
| `__vfs_write`（`new_sync_write` + `call_write_iter` 已内联进它） | `0xa0` | `SP0-0x130` |
| `pipe_write` | `0xb0` | **`SP0-0x1e0`** |
| `n_tty_write` | `0xa0` | `SP0-0x280` |

`pipe_write` 的序言（实测反汇编）：

```asm
sub  sp, sp, #0xb0
stp  x29, x16, [sp, #0x50]     ; SP0-0x190 = x29 , SP0-0x188 = 栈金丝雀
add  x29, sp, #0x50
stp  x28, x27, [sp, #0x60]     ; SP0-0x180 / SP0-0x178
stp  x26, x25, [sp, #0x70]     ; SP0-0x170 / SP0-0x168
stp  x24, x23, [sp, #0x80]     ; SP0-0x160 / SP0-0x158
stp  x22, x21, [sp, #0x90]     ; SP0-0x150 / SP0-0x148
stp  x20, x19, [sp, #0xa0]     ; SP0-0x140 / SP0-0x138
```

⇒ **一次 `write()` 就把 `waiter+0x00..waiter+0x58` 整片覆盖**（waiter 基址 = `SP0-0x190`）。
`sendmsg` 的 `address` 拷贝只重涂 `waiter+0x28..0x50`，所以 `waiter+0x00..0x28`
（两个 `rb_node`，以及让 `rtmutex.c:664` 早退的残余 `RB_CLEAR_NODE`）会被寄存器溢出值占据。

> 一个有趣的巧合：`stp x29, x16, [sp, #0x50]` 里的 `x29` 恰好等于 `sp+0x50 = SP0-0x190`
> = `&waiter->tree_entry`，也就是 `RB_EMPTY_NODE()` 要求的值 —— 所以在 **pipe 路径**上
> `waiter+0x00` 会被「恢复」成正确值。但这只是这组帧大小的巧合（`0x10+0x40+0x40+0xa0+0xb0-0x50 = 0x190`），
> `n_tty_write` 路径不成立，而且 `waiter+0x18/0x20` 永远恢复不了。**不能依赖。**

**本轮实施**（`main.c`）：

1. `sendmsg_paint_waiter()` 里的 `pr_info` 删除，改成
   `g_paint_namelen = paint_namelen; g_paint_fill = paint_fill;`（新增两个文件级变量）；
2. `waiter_thread()` 里 futex 返回后的 `pr_success` 删除 —— `ret`/`errno` 本来就已在
   `waiter_futex_ret` / `waiter_futex_errno` 里；
3. `run_paint_oracle()`（**R 线程 = `main()`**）在 `waiter_painting` 置起后、上膛消费者**之前**，
   用一行 `pr_success` 把上面两组值一起打出来。

⇒ W 从 futex 返回到进入阻塞 `sendmsg` 之间现在是 **零 syscall**。
（`write` 路线本身仍因帧大小不可作为 `sendmsg` 的替代载体 —— 这点上一版是对的。）

---

## 7. 需要统一 / 更正的既有内容

| 位置 | 现状 | 应改为 |
|---|---|---|
| `RTMUTEX_WEAPONIZATION.md` §15.16(3) | `rt_waiter = E-0x198`、`address = E-0x170` | **不是笔误，是基准约定不同**：该节定义 `E = T-0x188`（syscall 入口 SP），而本文用 `SP0 = T-0x180` ⇒ `E = SP0-0x08` ⇒ `E-0x198 = SP0-0x190` ✓、`E-0x170 = SP0-0x168` ✓。已在 §16.2 注明，两边不必强改 |
| `RTMUTEX_WEAPONIZATION.md` §3.5.2 | 行内「`0x90 = 16`」与文字「= 16」矛盾（`0x90 = 18`） | **该行是陈旧引用**：本文件已把该段改写成 §3.5 的「输入集只覆盖到 `SP0-0x198`」论证（`RTMUTEX_WEAPONIZATION.md:324-327`），文中已无 `0x90 = 16`。无需再改 |
| `RTMUTEX_WEAPONIZATION.md` §15.16(4) | 探针 `prio` 目标 = 139（= 120 + consumer nice 19） | 只有 `IONSTACK_CONSUMER_REAL_NICE=1` 时才成立；默认（`real_nice=0`）下 `W->prio = 120` |
| `RTMUTEX_WEAPONIZATION.md` §15.16(5) | 「三种配置全部崩溃 ⇒ 涂写没有落地」 | **读反了**。崩溃 = 落地；存活 = 未落地。且「未命中 ⇒ `prio` 是栈垃圾」为假 —— 残余值是内核写的 120 |
| `RTMUTEX_WEAPONIZATION.md` §15.18(4) 第 1 条 | 怀疑 `W->pi_blocked_on` 未指向 `do_futex` 帧里的 `rt_waiter` | **排除**：futex.c:3301-3302 的 `goto out_put_keys` 绕过 cleanup，悬垂成立（§1.2） |
| `src/exploit/util.c:1054-1058` | 注释「the residual waiter recorded `waiter->prio = task->prio` at block time (**nice 0 -> prio 120**)」 | **✅ 已改**。与 `IONSTACK_W_NICE=1` 冲突；实际残余值是 **120**（M 停靠把 W clamp 到 120，`rtmutex.c:956-957` + 973-977），注释已重写为「clamp 到 120」并注明「旧注释是数字对、理由错」 |
| `src/exploit/main.c:631` | 「`IONSTACK_PAINT_PRIO=<W->prio>` (**121** for a nice=1 CFS task)」 | **✅ 已改**为 **120**（与同文件 `main.c:1534` 的 "clamped 120" 一致） |
| `docs/PSELECT_GEOMETRY_FINDINGS.md` §9.2 | `res_*` 通道覆盖不到 `waiter->lock` | **独立印证**：designj 崩溃里 `x21 = 0x56fbdcba4ce30b1f`（栈金丝雀），即 `waiter->lock` 未被 pselect 涂到；且 `fops.c:396-404` 记录了 `write()` 二次覆盖机制 |

### 工具坑（本轮踩到）

- **`grep` 读 `objdump` 输出必须加 `-a`**：否则被当二进制文件、**静默返回空**。
  本轮 `vfs_write` / `ksys_write` / `__arm64_sys_sendmsg` 的 `bl` 搜索全部因此返回空。
- `objdump --disassemble-symbols=` **不加前导下划线**（`___sys_sendmsg` 要写成 `___sys_sendmsg`，`_raw_spin_trylock` 要写成 `raw_spin_trylock`）。

---

## 8. 一句话回答「该怎么解决」

> **不要再修涂写通道，它已经通了。**
> 把 `IONSTACK_PAINT_PRIO` 改成 **120** 消掉假异常；把判据从「存活/崩溃」换成「**`fake_lock+0` 的 trylock 位被置起**」（用户态可直接读）；然后让 `rt_mutex_owner(fake_lock) == W`，使链走在 rtmutex.c:600 安全退出 —— 这样就能在不崩溃的前提下，用 `verify_paint_gate()` 的写门回读第一次真正判定「涂写落地 + 链走走到了 579/585 + 写原语是否触发」。

---

## 9. 第八轮更正（2026-10-03 晚）：本文 §4.4 的「读法是反的」**不成立**，判据另有其人

本节推翻了本文 §4.4/§4.5 的核心论断，并给出替代判据。**以本节为准。**

### 9.1 涂写确实落地 —— 铁证是 `consumer_success=0`（`LANDED+FROZEN@585`）

四个 run 出现 `paint-result ... consumer_calls=1 consumer_success=0`：

| run | `lock_owner_mode` | `wait_lock_word` | `msg_iovlen` | 结局 |
|---|---|---|---|---|
| `ring1j` | `none` | `1` | `1` | `device_rc=143 same_boot=1` |
| `ring1n` | `fake-task` | `1` | `8` | `device_rc=143 same_boot=1` |
| `ring1u` | `fake-task`（`shape=safe`） | `1` | `8` | `device_rc=143 same_boot=1` |
| `wa_r1` | `none` | `1` | `8` | `device_rc=143 same_boot=1` |

`device_rc=143` = 宿主 `run_paint.sh` 超时 SIGTERM，**不是崩溃**（`same_boot=1`、`survived=1`）。
唯一的解释是消费者线程永久卡在 `rtmutex.c:585-588`：

```c
585	if (!raw_spin_trylock(&lock->wait_lock)) {
586		raw_spin_unlock_irq(&task->pi_lock);
587		cpu_relax();
588		goto retry;
589	}
```

* `lock = waiter->lock` ⇒ **涂写把 `waiter->lock` 写成了 `fake_lock`** ⇒ 涂写落地。
* `wa_r1` 与「15 次 pristine」的基线**只差 `IONSTACK_FOPS_WAIT_LOCK_WORD=1`**；
  该变量已确认只被消费成 payload 里 `fake_lock+0x00` 一个 u32
  （`util.c:2139` / `util.c:2538`；设备侧 `ionstack_reroot_device.c:1045` / `:2271`；
  另有 `IONSTACK_EXPECT_FOPS_WAIT_LOCK_WORD` 只是验证项），**没有任何 stage/旁路作用**。
  ⇒ 内核读到的那个非零字**就是我们页里的 `fake_lock+0x00`**
  ⇒ **`page_base` 就是我们持有的页**，`util.c:1617-1653` 的 (A) 情形（"页不是我们的"）**被排除**。

### 9.2 反汇编钉死：trylock 成功 ⇒ 页必脏 ⇒ `owner_cpu`/`wait_owner` 必非零

```
_raw_spin_unlock  @0xffffff8009c198ec:
    mov  w9,#-1 ; mov x10,#-1 ; mov w8,wzr
    str  w9,[x0,#0x4]    ; owner_cpu = 0xffffffff
    str  x10,[x0,#0x8]   ; owner     = 0xffffffffffffffff
    stlrb w8,[x0]        ; val = 0

_raw_spin_trylock @0xffffff8009c1958c  (成功路径 @0xffffff8009c19600):
    ldr  w8,[x0] / cbnz w8,<fail>        ; 只测 *(u32*)lock == 0
    ldaxr/stxr CAS val 0 -> 1
    str  x9,[x0,#0x8]    ; owner     = SP_EL0 (当前任务)
    str  w10,[x0,#0x4]   ; owner_cpu = cpu
```

⇒ **只要 trylock 在我们页上成功过一次，`owner_cpu` 与 `wait_owner` 就必然非零**
（unlock 写 `0xffffffff` / `0xffffffffffffffff`，trylock 成功写 cpu / 任务指针）。
全仓 **0/67** 的 `page-dump` 都是 `owner_cpu=00000000 wait_owner=0000000000000000`
⇒ **trylock 从未在我们页上成功过**；`wa_r1` 的 trylock 失败与之自洽。

### 9.3 `detect_deadlock = false` ⇒ 链走**没有**「无 requeue」的干净出口

`CONFIG_DEBUG_RT_MUTEXES` 未开（`scratch/kconfig/device.config:6815`）⇒ 生效的是
`kernel/locking/rtmutex.h:31-35`：

```c
static inline bool debug_rt_mutex_detect_deadlock(struct rt_mutex_waiter *w,
						  enum rtmutex_chainwalk walk)
{ return walk == RT_MUTEX_FULL_CHAINWALK; }
```

而 `rt_mutex_adjust_pi`（`rtmutex.c:1145-1146`）传 **`RT_MUTEX_MIN_CHAINWALK`**：

```c
	rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL,
				   next_lock, NULL, task);
```

⇒ **`detect_deadlock = false`** ⇒ `requeue` 恒为 `true`（`rtmutex.c:460`；它只在
`rtmutex.c:558` / `:573` 的 `else` 分支被置 `false`，而那两支都要求 `detect_deadlock`）。
⇒ **`rtmutex.c:613` 的 `!requeue` 分支不可达**，链走必然走到 **661 → 664 → 685**。

⇒ 若门开（涂写落地）且 `wait_lock.val == 0`：
* `585` trylock 成功 ⇒ 写 `fake_lock+0x04` / `+0x08`；
* `664` `rt_mutex_dequeue(lock, waiter)`：`iv=8` 时 `waiter->tree_entry = {0,0,0}` ⇒
  `RB_EMPTY_NODE` 为假 ⇒ 不早退 ⇒ `rb_erase_cached` 以 `parent = 0` 收尾 ⇒
  **`fake_lock->waiters.rb_root.rb_node`（页内 `lock_off+0x10`）被写成 `NULL`**。
  （`iv=1` 时 `tree_entry` 保留 `RB_CLEAR_NODE` ⇒ `664` 早退 ⇒ `685` 的 `rb_insert`
  在伪造的 `fake_w0` 上 rebalance ⇒ 这是 `ring1e/f/h/i` 的崩溃路径。）

**⇒ 结论：`none` + `iv=8` + `wl=0` + 落地 ⇒ 页面必然在 `lock_off+0x04 / +0x08 / +0x10` 变脏。**
**而实测 15 次全 pristine（`fd=8000 owc=0 cs=1`）⇒ 与 §9.1 的「涂写落地」直接冲突。**

### 9.4 冲突的第三方解释：设备孤儿进程污染（**已证实的隐藏变量**）

kill 掉实验会留下 `ionstack_reroot_device` / `ionstack_perf_target` 孤儿。实测：

```
loadavg = 13.29 13.66 14.15      8/2852 runnable   (8 核全满)
残留：4375 ionstack_reroot_device   4379 ionstack_perf_target
      4846 ionstack_reroot_device   4848 ionstack_perf_target
      5210 ionstack_reroot_device   5212 ionstack_perf_target
```

`pkill -9` 后 `ionstack_reroot` 变 defunct（`[ionstack_reroot]`），
`ionstack_perf_target`（`freq=8000` 采样、`hold_sec=900`）**杀不掉** ⇒
**只有 `adb reboot` 能拿回干净状态**（重启后 `loadavg 0.31`，无残留）。

**⇒ 此前「`wl=1` 必冻结（4/4）/ `wl=0` 从不落地（0/15+）」的完美分离，
很可能是负载污染造成的伪相关，而不是 `wl` 本身的作用。**

**已修**：`scratch/bisect.sh` 每轮开始前插入
`adb shell "pkill -9 -f ionstack_"` + `sleep 2` + 打印 `loadavg`。

### 9.5 设备侧注释与实测相反（作者的链走模型是反的）

`src/device/ionstack_reroot_device.c:1033-1038` 声称：

> an ownerless `rt_mutex_adjust_prio_chain` walks into
> `rt_mutex_top_waiter(lock)`'s `BUG_ON(w->lock != lock)` on this 4.19 tree

并据此把 `IONSTACK_FOPS_LOCK_OWNER_MODE=none` 钳成 `init-task`
（`effective_t878u_lock_owner_mode()`，`:66-84`）。

**但实测相反：`owner=none` 存活（8/8），`owner=fake-task` 崩（8/14）。**
（`:1022-1050` / `:2248-2276` 已从 `(void)effective_owner_mode` 丢弃改为转发。）
⇒ 该注释的因果是反的，**不能作为 `owner=none` 会崩的依据**。

### 9.6 干净设备上的判决组（`/tmp/decide7.log`，`adb reboot` 后）

```
B: none + iv=8 + wl=0                       ROUNDS=3   ← 基线复测（此前 15/15 pristine）
K: none + iv=8 + wl=0 + LOCK_DELTA=0x1cb0   ROUNDS=4   ← waiter->lock := SCRATCH（全零区）
A: none + iv=8 + wl=1                       ROUNDS=3   ← 落地证明（预期 FROZEN）
J: K + PAINT_PRIO=120                       ROUNDS=2   ← 负对照（预期 pristine）
```

`IONSTACK_PAINT_LOCK_DELTA=0x1cb0` == `SCRATCH_OFF - LOCK_OFF`，已确认被转发
（`ionstack_reroot_device.c:2063` / `:2189`；`main.c:744-784`）。

判据：
* **K 正向信号** = `scratch[0]` 非零 **或** `first_diff != 8000`。
  落地时 `585` 把 `owner_cpu`/`owner` 写进 `SCRATCH+0x04/+0x08`，
  且 `685` 的 `rb_add_cached` 把 `SCRATCH+0x10` 写成 `&rt_waiter->tree_entry`
  （`SCRATCH` 全零 ⇒ `rb_root.rb_node = 0` ⇒ `parent = NULL` ⇒ `rb_link_node` 直写 root）。
  命中 ⇒ **首次拿到「落地 + 存活 + 页内可见写」样本**，且 `698` 因 `owner=0` 干净退出。
* **J 必须 pristine** ⇒ 否则说明门与 `prio` 无关，判据本身有问题。
* **A 若 FROZEN** ⇒ 干净负载下复现落地，§9.1 成立。
* **B 若仍 3/3 pristine** ⇒ 「`none`+`iv=8` 从不落地」在干净负载下依旧成立 ⇒ 需新解释。

### 9.7 本轮新确认的源码/反汇编事实（可复用）

* `net/socket.c:2009-2058` `copy_msghdr_from_user`：
  `2024` 取用户 `msg_namelen` → `2031-2032` clamp 到 `sizeof(sockaddr_storage)=0x80` →
  **`2037-2044` `if (!save_addr) move_addr_to_kernel(msg.msg_name, kmsg->msg_namelen, kmsg->msg_name)`**
  → **`2055` `import_iovec(..., UIO_FASTIOV, iov = iovstack, ...)`**。
  ⇒ **`import_iovec` 在 `move_addr_to_kernel` 之后**，`iovstack` 与涂写区 `+0x28..+0x4F` 不重叠。
* `___sys_sendmsg @0xffffff80099179fc` 反汇编（第 6 次确认）：
  ```
  sub  sp, sp, #0x190
  add  x29, sp, #0x140
  add  x9,  sp, #0x38       ; iovstack = S-0x158
  sub  x10, x29, #0x88      ; &address = S-0xD8
  str  x9,  [sp,#0x8]       ; msg_sys->msg_iov  = iovstack
  str  x10, [x2]            ; msg_sys->msg_name = &address
  ```
  ⇒ `address - iovstack = 0x80` = 8×16 ✓；配合 `rt_waiter = S-0x100`
  （`do_futex` 帧 `0x1C0` + `0xC0`；`do_futex` 与 `___sys_sendmsg` 同为
  `invoke_syscall` 下一层 ⇒ 入口 sp 相同）⇒ **`address == rt_waiter + 0x28`** ✓。
* `src/exploit/offset.h:135-140`（`CONFIG_DEBUG_QSPINLOCK_OWNER=y` ⇒
  `arch_spinlock_t` 是 `{u32 val; u32 owner_cpu; void *owner;}` = 0x10 字节）：
  `wait_lock`@`0x00` / `owner_cpu`@`0x04` / `owner`@`0x08` /
  `waiters.rb_root`@`0x10` / `rb_leftmost`@`0x18` / `rt_mutex.owner`@`0x20`。
* `scratch/kconfig/device.config`：`CONFIG_HZ=250`、`CONFIG_PREEMPT=y`、
  `CONFIG_DEBUG_QSPINLOCK_OWNER=y`、`# CONFIG_DEBUG_RT_MUTEXES is not set`、
  `# CONFIG_DEBUG_SPINLOCK is not set`、`# CONFIG_DEBUG_LOCK_ALLOC is not set`。

### 9.8 工具坑（本轮新增）

* **`nm` / `objdump` 会被 `/opt/anaconda3/bin/nm` 抢走并静默返回空**
  ⇒ 必须显式用 **`/usr/bin/nm`** 与 **`/usr/bin/objdump`**。
* `objdump` 的输出行以 `ffffff...` **顶格开头**（无前导空白）
  ⇒ `grep -aE "^\s+ffffff"` 会返回空；应用 `grep -aE "^ffffff"`。

---

## 10. 第十轮更正（2026-10-03 深夜）：**`PAGE-WRITTEN` 判据本身是坏的** —— 页 dump 是 arm 前的旧快照

### 10.1 一句话

**「0/67 个 run 的页从不被写」不是事实，而是判据的产物。**
`dump_reclaim_page_state()` 读回的那一页**不是内核在解引用的那一页**（或至少不是它的活视图），
所以 `first_diff=8000` / `owner_cpu=0` / `scratch=0` 全部**恒为真**，与链走是否执行无关。
**664/685 的写一直在落地，只是我们看不见。**

### 10.2 判决实验（`/tmp/decide9.log`，干净设备）

| run | `wl` | `LOCK_WAITERS` | `iovlen` | `PAINT_PRIO` | 结局 |
|-----|------|----------------|----------|--------------|------|
| `b1_r1..r3` | 0 | 1 | 8 | `0x7fffffff` | `cs=1`，pristine |
| `w1_r1` / `wa_r1` / `ring1j/n/u` | 1 | 1 | 8 | `0x7fffffff` | **`cs=0` 冻结** |
| `g1_r1`(E4) | 1 | 1 | 8 | **120** | `cs=1` |
| `a3_r1/r2` | 0 | 1 | **1** | `0x7fffffff` | **CRASH ×2** |
| `a1_r1/r2` | 0 | **0** | 8 | `0x7fffffff` | `cs=1`，pristine |
| `a2_r1` / `a2_r2` | 1 | **0** | 8 | `0x7fffffff` | `cs=1` / **`cs=0` 冻结** |
| `dnb_r1-3` / `dnc_r1-3` | 0 | 1 | 8 | `0x7fffffff` | **CRASH ×6（无 `paint-result`）** |
| `ring1e/ring1i` | 0 | 1 | **1** | `0x7fffffff` | **CRASH（注释指认崩点 = 664）** |
| `paintfill139` | — | — | 8 | `139`+FILL | **CRASH** |
| `fa_r1` | 0 | 1 | 8 | `121`+FILL | **CRASH（arm 后无输出）** |

关键读法：

1. **E4 vs E2（只差 `PAINT_PRIO`：120 vs `0x7fffffff`）**
   ⇒ `cs=1` vs `cs=0`。门 = `waiter->prio == W->prio`（§10.3 已把宏读全），
   所以 **冻结 ⟺ 门开 ⟺ 涂写落地**。这是**真判据**，本轮的锚点。
2. **`a3`（`iovlen=1`）2/2 崩**，且 `pre-arm` dump 显示 payload 完好、**无 `paint-result`**
   ⇒ 崩点在 arm 之后、消费者 `sched_setattr` 之内。
   源码注释（`main.c:860-880`）指认 `iovlen=1` 时崩点为 **664 `rb_erase_cached`**
   ⇒ **`wl=0` + 武器 prio 下链走确实跑到 664。**
3. **`dnb/dnc`（`fake-task` 模式，`iovlen=8`）6/6 崩，同样无 `paint-result`**
   ⇒ `waiter->task = fake_task`，`:690 wake_up_process(fake_task)` 必炸
   ⇒ **`wl=0` + `iovlen=8` 下链走跑到 690**（即完整穿过 664/685）。
4. **由 2、3 ⇒ 664 的 `root->rb_node = 0` 与 685 的 `root->rb_node = &E->tree_entry`、
   `root->rb_leftmost = &E->tree_entry` 一定写进了 `fake_lock+0x10/0x18`。**
   而 `b1_r3` / `a1_r1` 显示 `root`/`leftmost` **仍是 payload 原值**、`first_diff=8000`。
   ⇒ **页 dump 看不见真实写。判据坏。**
5. `a2_r1` 的「不冻结」是**涂写没命中**（竞态），不是 `LOCK_WAITERS` 的作用 ——
   `a2_r2` 同配置冻结。⇒ **`lock->waiters` 与冻结无关，585 模型成立。**

### 10.3 本轮钉死的源码事实

* **门的确切语义**（`kernel/locking/rtmutex.c:229-230, 253-271`）：
  ```c
  #define task_to_waiter(p) \
      &(struct rt_mutex_waiter){ .prio = (p)->prio, .deadline = (p)->dl.deadline }
  rt_mutex_waiter_equal(l, r): l->prio != r->prio ? 0 : (dl_prio(l->prio) ? l->deadline == r->deadline : 1)
  ```
  ⇒ 非 DL 时门 = **`waiter->prio == W->prio`**，与 `waiter+0x00..0x28` 完全无关。
* **585 的自旋是死循环**：`retry:` 标号在 `++depth` **之后**（`:502` vs `:474`），
  `:588 goto retry` 不回经 `++depth` ⇒ `max_lock_depth` 拦不住。
* **585 成功后的写会被后续 unlock 清掉**：`:600` 的 `raw_spin_unlock(&lock->wait_lock)`
  与 `:698` 的 `raw_spin_unlock_irq(&lock->wait_lock)` 都会把
  `val`/`owner_cpu`/`owner` 清回 0。
  ⇒ **`owner_cpu == 0` 不能证明「trylock 从未成功」**（§9.2 的结论作废）。
* **664 的 `rt_mutex_dequeue` 不是 no-op**：涂写通过 `import_iovec` 的
  `iovstack` 拷贝覆盖 `waiter+0x00..0x28`，把 `remove_waiter` 留下的
  `RB_CLEAR_NODE` 自指针冲成 `iov[5..7]` 的值（`iov[1..7] = {NULL,0}` ⇒ 全 0）。
  ⇒ `RB_EMPTY_NODE()` 为假 ⇒ 必然执行 `rb_erase_cached`。
  （`main.c:860-880` 的注释早已写明，§2.2「`rb_erase` 那条路是死的」**作废**。）
  `iovlen=8` 使它成为良性的 Case-1 erase（`root->rb_node = 0`）；
  `iovlen=1` 保留 futex 残留 ⇒ 伪造节点 ⇒ `__rb_change_child` 写野 parent ⇒ 崩。
* **`IONSTACK_FOPS_LOCK_WAITERS` 只改 payload 的 `lock_root`/`lock_leftmost`
  与 `fake_w0->tree_entry`，与门无关。**

### 10.4 现在**真正可用**的判据

| 想判定 | 可用判据 | 可靠性 |
|--------|----------|--------|
| 涂写是否落地 **且** 门开 | **`wl=1` + 武器 prio ⇒ `consumer_success=0`（冻结）** | 真，已复现 6/6 |
| 链走是否走到 585 之前就退出 | `wl=1` + `PAINT_PRIO=120` ⇒ `cs=1` | 真（负对照） |
| 链走是否走到 664 | `iovlen=1` + `wl=0` + 武器 prio ⇒ **崩溃** | 真（2/2） |
| 链走是否走到 690 | `IONSTACK_FOPS_WAITER_TASK_MODE=fake-task` + `wl=0` ⇒ **崩溃** | 真（6/6） |
| ~~页是否被写~~ | ~~`first_diff != 0x8000`~~ | **坏（恒 pristine）** |
| ~~trylock 是否成功过~~ | ~~`owner_cpu != 0`~~ | **坏（被 unlock 清零）** |

### 10.5 为什么读回是盲的（待最终确认的机制）

`snapshot_held_reclaim_fragment()`（`util.c:1506-1550`）两条腿：

* 前 `PAGE_SIZE`：`tee(reclaim_frag_pipe[0] → verify_pipe[1])` + `read(verify_pipe[0])`；
* 其余 `ORDER3_SIZE - PAGE_SIZE`：`recv(reclaim_sv[1], …, MSG_PEEK|MSG_DONTWAIT)`。

`reclaim_sv` 上的 `sendmsg` 若把数据**拷贝**进 skb（AF_UNIX 的常规路径），
则 socket 队列里就是一份**发送时刻的副本**，两条腿都只能读到它 ——
与内核通过线性映射别名写的那一页**无关**。
⇒ 三档 dump 因此逐字节相同，且恒等于 payload。

**待办（P0，下一轮第一件事）**：把 `reclaim-pfn-result`（`fa_r1` 里
`candidates=0 free_hits=0 alloc_hits=0 matched_hits=0 matched=0`）
与 `page_base` 的推导对齐，确认 `page_base` 到底是不是被 hold 的那一页；
若是，则读回盲的机制就在上面这条；若否，`wl` 能影响结果就说明另有通道。

### 10.6 结论对后续策略的影响

* **写原语很可能早就在工作**（664 的 `root->rb_node = 0`、
  685 的 `root->rb_node`/`root->rb_leftmost = &E->tree_entry`）。
  过去所有「没落地 / 没写」的判断都建立在坏判据上。
* **不要再把 `first_diff` 当验收条件**。改用 §10.4 表里的三条真判据，
  尤其是 **`fake-task` 崩溃**（走到 690）与 **`wl=1` 冻结**（走到 585）。
* 要把写变成提权，必须给写目标配一个**独立可观测**：
  首选 `IONSTACK_FOPS_PI_RB_SHAPE=target-right` / `binwrite-right`
  （664 的写被设计成写向 `ASHMEM_MISC_FOPS+0x310` 的「合成模块引用计数」），
  再找一个用户态能读到该位置的接口来验收。
