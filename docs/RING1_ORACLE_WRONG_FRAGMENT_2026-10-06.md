# Ring 1: the page oracle has been reading the WRONG FRAGMENT all along

_2026-10-06, second pass. Supersedes `RING1_585_NEVER_SUCCEEDED_2026-10-06.md`._

## 0. One-line result

`hold_first_reclaim_fragment()` splices **stream message #0**, because the perf-based
post-target search that is supposed to skip to the message holding `page_base`
**never fires on this image**. Every message carries a byte-identical copy of the
payload, so the content gate cannot notice. `first_diff == ORDER3_SIZE` and
`owner_cpu == 0` are therefore **properties of the wrong page**, not facts about the
chain walk — and `rtmutex.c:585` has very likely been succeeding all along.

This is the mechanism that `docs/PAINT_ORACLE_ANALYSIS.md` §10.5 left as
"待最终确认的机制" on 2026-10-03.

## 1. Evidence: `skip` is always 0

All 471 logs that reach the reclaim stage:

```
reclaim-posttarget-search sends=8192/8192 sockets=10 hit=0 hit_send=0 hit_socket=0 skip=0 last_errno=11
reclaim-order-gate posttarget_miss content_probe=1 sends=8192
reclaim-frag-gate skip=0 head=3712 pipe_size=4096 spliced=4096 mode=base-page-hold errno=0
reclaim-content-validate tee=4096 first=4096 tail=28672 mismatch=8000 ok=1
```

`hit=0` in **470 of 471** (the 471st is the same line with a CRLF). The post-target
search sends until `read_reclaim_pfn_frag_alloc_total()` changes; util.c's own comment
says the T878U 4.19 PFN frag counters are **dead (always 0)**, so the counter never
changes, the loop runs to `effective_send_limit`, and:

```c
order3_gate_ok = posttarget_hit;                  /* 0 */
if (!order3_gate_ok && content_gate && reclaim_sends > 0) {
    order3_gate_ok = 1;                            /* "content_probe=1" */
}
```

`reclaim_frag_skip_bytes` is set **only** inside the `posttarget_hit` branch, so it
stays 0, and `hold_first_reclaim_fragment()` splices message #0.

## 2. Why `content_ok=1` proves nothing

`validate_held_reclaim_fragment()` compares the held 32 KB against
`skb_buf + 0xE80`. Every one of the 8192 messages is the **same payload**, so this
test answers "is the held page *a* payload page?" — never "is the held page
`page_base`?". It is true for all 8192 messages and therefore vacuous.

The comment above `IONSTACK_RECLAIM_CORRELATE` in `ionstack_reroot_device.c` already
states the consequence:

> the kernel still reads our `wait_lock_word` at `fake_lock+0x00` and still behaves as
> if `page_base` were right, while every write it performs goes into a page we do not hold.

## 3. Where `fake_lock` really is, in stream coordinates

* one reclaim message is `reclaim_send_size = ORDER3_SIZE + (-SKB_DATA_DELTA) = 0x8000 + 0xE80 = 0x8E80`
  bytes (confirmed: `bytes=298844160 / sends=8192 = 36480`);
* the first `0xE80` bytes of a message land in the skb **linear head**
  (`skb->head`), the following `0x8000` bytes land in **one order-3 frag page**
  — which is exactly why `SKB_DATA_DELTA == -0xE80`;
* hence message `k`'s frag page is stream `[k*0x8E80 + 0xE80, k*0x8E80 + 0x8E80)`, and
  **`fake_lock` sits at stream offset `k*0x8E80 + LOCK_OFF`**.

`hold_first_reclaim_fragment()` holds stream `[skip + 0xE80, skip + 0xE80 + 0x8000)`,
and `dump_reclaim_page_state()` reads `page[lock_off]` = stream `skip + LOCK_OFF`. So the
oracle is correct **iff** `skip == k*0x8E80` for the `k` that owns `page_base`. With
`skip == 0` it reads message #0.

## 4. The unlock correction: `owner_cpu` is NOT cleared to 0

`PAINT_ORACLE_ANALYSIS.md` §10.3 claimed the unlock "把 val/owner_cpu/owner 清回 0".
Reading the kernel source in this tree, that is wrong.

`arch/arm64/include/asm/spinlock_types.h` includes `asm-generic/qspinlock_types.h`, so
this kernel uses **qspinlock**, and `include/asm-generic/qspinlock_types.h` puts the
debug fields **inside `arch_spinlock_t`** under `CONFIG_DEBUG_QSPINLOCK_OWNER`:

```c
typedef struct qspinlock {
	union { atomic_t val; ... };          /* +0x00, 4 bytes */
#ifdef CONFIG_DEBUG_QSPINLOCK_OWNER
	unsigned int owner_cpu;               /* +0x04 */
	struct task_struct *owner;            /* +0x08 */
#endif
} arch_spinlock_t;                            /* sizeof == 0x10  */
```

That is exactly `offset.h`'s `RTMUTEX_WAIT_LOCK_OFF 0x00 / OWNER_CPU 0x04 /
OWNER_TASK 0x08`, and it is what makes `waiters.rb_root @ +0x10`, `rb_leftmost @ +0x18`,
`owner @ +0x20` line up. **The offsets were always right.**

The semantics, from `include/asm-generic/qspinlock.h`:

```c
static __always_inline int queued_spin_trylock(struct qspinlock *lock) {
	if (!atomic_read(&lock->val) &&
	    (atomic_cmpxchg_acquire(&lock->val, 0, _Q_LOCKED_VAL) == 0)) {
		queued_spin_set_owner(lock);   /* owner_cpu = cpu; owner = current; */
		return 1;
	}
	return 0;                              /* FAILURE WRITES NOTHING */
}
static __always_inline void queued_spin_unlock(struct qspinlock *lock) {
	queued_spin_clear_owner(lock);         /* owner_cpu = -1; owner = SPINLOCK_OWNER_INIT */
	smp_store_release(&lock->locked, 0);
}
```

with `SPINLOCK_OWNER_INIT == (void *)-1`.

⇒ after a **complete lock/unlock cycle** the fields are

| field | after success | after unlock | observed |
|---|---|---|---|
| `wait_lock.val` | 1 | 0 | payload value |
| `owner_cpu` | cpu id | **0xffffffff** | `00000000` |
| `owner` | `current` | **0xffffffffffffffff** | `0000000000000000` |

So `owner_cpu == 0` **is** a valid "the lock was never taken" signal — the doc's "cleared
to 0" made it look ambiguous when it is not. The reason we see 0 is simply that we are
looking at the wrong page.

## 5. `wait_lock_word` → consumer outcome, re-measured

Cross-tabulating all 76 logs that report `consumer_calls=1`:

| `wait_lock_word` | `succ=1` + `consumer seq=` line | `succ=0`, no line |
|---|---|---|
| `0` | **58** | 2 |
| `1` | 4 | **12** |

`IONSTACK_FOPS_WAIT_LOCK_WORD` is written in exactly **one** place (`util.c`,
`put32(p, LOCK_OFF + RTMUTEX_WAIT_LOCK_OFF, fops_wait_lock_word)`) and is read by the
kernel in exactly one place (`rtmutex.c:585 raw_spin_trylock(&lock->wait_lock)`). There is
no other path by which it can change the outcome. `rtmutex.c:585`'s else-branch
(`586 raw_spin_unlock_irq → 587 cpu_relax → 588 goto retry`) is the **only** non-returning
path in `rt_mutex_adjust_prio_chain()`.

⇒ `wlw=1` freezing 12/16 and `wlw=0` freezing only 2/60 means the walk **does** reach 585
with `lock == fake_lock`, and with `wlw=0` the trylock **succeeds**. The 4 `wlw=1` runs that
returned exited earlier (1135 / 569 gate); the 2 `wlw=0` runs that froze presumably lost the
reclaim race.

So the old "585 has never succeeded" verdict is dead, and the sequence
`585 → 600 → 664 → 685 → 690 → 698 → 716 → 723` is being executed. `PAINT_ORACLE_ANALYSIS.md`
§10.2 reached the same conclusion by a different route (`dnb/dnc` crashing 6/6).

## 6. A second, independent defect: the extra sockets are closed

`reclaim_posttarget_search` sprays across up to `POSTTARGET_MAX_SOCKETS` (32, 10 in
practice) sockets and then immediately runs

```c
close_reclaim_socket_pairs(posttarget_extra_sv, posttarget_extra_count);
```

which frees every frag page of sockets #1..#9 — roughly 90 % of the spray — **before** the
consumer fires. `reclaim_sv` is only reassigned to a later socket inside the
`posttarget_hit` branch, which never executes. So the pages the walk may be writing to can
already have been released back to the buddy allocator.

`IONSTACK_RECLAIM_POSTTARGET_MAX_SOCKETS=1` keeps the whole spray in socket #0: nothing is
freed early, and (not coincidentally) the entire queue becomes scannable.

## 7. The fix

1. **`scan_reclaim_queue_for_writes()`** (util.c) — walks the remaining socket queue one
   message at a time and reports every fragment-page byte that differs from the payload,
   using `rel = (pos + i) mod msg` so no message alignment is needed. Reports
   `msgs / hits / hit_msgs / lock / fops / scratch / other` plus the first hit's message
   index and page offset. Enabled by `IONSTACK_RECLAIM_SCAN_QUEUE=1`; it **drains** the
   socket, so it runs last, after every `dump_reclaim_page_state()`.
2. **`IONSTACK_RECLAIM_FRAG_SKIP_MSGS=<k>`** — sets `reclaim_frag_skip_bytes = k*msg`, so
   the ordinary `dump_reclaim_page_state()` / `verify_paint_gate()` path reads the fragment
   the kernel actually used. This is the two-step: scan to find `k`, then re-run with it.
3. **`IONSTACK_RECLAIM_POSTTARGET_MAX_SOCKETS`** is now overridable (it was hardcoded to
   `"32"`, and because `fixed_environment[]` is copied before the whitelist and `getenv()`
   takes the *first* match, the override had to be emitted **early** in the array).

## 8. What to expect

| `reclaim-scan` output | meaning |
|---|---|
| `lock>0`, `first msg=<k> page_off=4d0` | the walk took `fake_lock->wait_lock` on message `k`'s frag page. **The ring-1 page oracle finally exists.** Re-run with `FRAG_SKIP_MSGS=<k>`. |
| `fops>0` / `first ... [FOPS]` | the 723 store `*(fake_fops+0x08) = data_addr(ASHMEM_MISC_FOPS)` landed — ring 1 executed. |
| `hits=0` | no fragment was written: either the spray missed `page_base` entirely, or the walk exited before 585 in this run. |

## 9. Corrections to earlier documents

* `RING1_585_NEVER_SUCCEEDED_2026-10-06.md` — §1 and §3 are wrong. The three signatures
  are real, but they were being looked for on the wrong page; and §3's "contradiction"
  dissolves once `skip=0` is known.
* `PAINT_ORACLE_ANALYSIS.md` §10.1 was **right** ("判据的产物") and §10.5 is now answered.
  §10.3's "unlock 把 owner_cpu/owner 清回 0" is wrong — see §4 above.
* The `IONSTACK_RECLAIM_CORRELATE` knob distinguishes ORDER3 chunks **of `skb_buf`**, not
  socket messages; with one message == one chunk it cannot identify a message. It does not
  substitute for the scan.
