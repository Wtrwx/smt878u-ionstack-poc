# Ring 1: `rtmutex.c:585` has never succeeded

> **⚠️ SUPERSEDED — 2026-10-06 (second pass).** The conclusion below is an artifact.
> `hold_first_reclaim_fragment()` always splices stream message **#0** (the perf
> post-target search never fires on this image: `hit=0 ... skip=0` in 470/471 logs),
> while `page_base` belongs to whichever of the 8192 byte-identical messages won the
> order-3 allocation. The oracle has therefore been reading the wrong page, so
> `first_diff=8000` and `owner_cpu=0` are constants of *that* page, not facts about the
> walk. Re-measured `wait_lock_word` → consumer outcome (58/60 vs 4/16) shows the walk
> **does** reach and pass 585. See
> [`RING1_ORACLE_WRONG_FRAGMENT_2026-10-06.md`](RING1_ORACLE_WRONG_FRAGMENT_2026-10-06.md).
> §1 and §3 below are wrong; §2 (the two meanings of `consumer_success=0`) and §4
> (the retractions) still stand.

_2026-10-06. Cross-tabulation of all 124 logs under `scratch/**/*.log`._

## Summary

The project's working belief was that the stack paint lands (≈2/3 of the time) and that the
failure is *downstream* of `rtmutex.c:585` — the bisect note read "ring1j (`wait_lock=1`)
survived and is frozen at 585, therefore the fault is at 664".

**That is not supported by the data.** Across all 124 recorded runs there is **no evidence
that `rt_mutex_adjust_prio_chain()` has ever passed line 585**, and no evidence that the
paint has ever written `E+0x38`.

## 1. A successful 585 leaves three independent, unmissable signatures

`585 raw_spin_trylock(&lock->wait_lock)` — on **success** `do_raw_spin_trylock()` runs
`queued_spin_set_owner()`, and with `arch_spinlock_t == {u32 slock; u32 owner_cpu; void *owner}`
(0x10 bytes — confirmed by disassembly: `rt_mutex_owner()` inlines to
`ldr x8,[x21,#0x20]; and x8,x8,#~1`, `rt_mutex_top_waiter()` to `ldr x8,[x21,#0x18]`):

| offset | field | payload writes | success writes |
|---|---|---|---|
| `fake_lock+0x00` | `wait_lock.val` | `wait_lock_word` (0 or 1) | **1** (the CAS) |
| `fake_lock+0x04` | `wait_lock.owner_cpu` | **0** | **cpu id** |
| `fake_lock+0x08` | `wait_lock.owner` | **0** | **current / text addr** |
| `fake_lock+0x10` | `waiters.rb_root.rb_node` | `fake_w0` | `&E->tree_entry` if 664/685 reached |
| `fake_lock+0x18` | `waiters.rb_leftmost` | `fake_w0` | `&E->tree_entry` if 664/685 reached |

The last two matter because the walk, having taken the lock, does
`664 rt_mutex_dequeue(lock, waiter)` (Case 1 of `__rb_erase_augmented`, `parent = 0` →
`root->rb_node = 0`) and then `685 rt_mutex_enqueue(lock, waiter)` — which re-inserts the
**stack** waiter, so `rb_root`/`rb_leftmost` become `&E->tree_entry`, i.e. a
`0xffffffc0..` address, **not** `fake_w0`.

**Observed in every single run:** `wait_lock` = payload value, `owner_cpu = 00000000`,
`wait_owner = 0000000000000000`, `root = leftmost = base+0x13a0` (= `fake_w0`, the payload
initialiser), `first_diff = 8000 (pristine)`.

⇒ **585 has never succeeded.**

## 2. `consumer_success=0` has two different meanings

`consumer_calls` is incremented **before** `sched_setattr_tid()`; `consumer_success` is
incremented **after** it returns 0; and `pr_info("consumer seq=...")` prints **after** it
returns at all. So:

| `consumer_calls` | `consumer_success` | `consumer seq=` line | meaning |
|---|---|---|---|
| 1 | 1 | **present** (31 runs) | syscall returned 0 → walk **exited early** (1135 / 518 / 525 / 537 / 546 / 554 / 569 / 600 …) |
| 1 | 0 | **absent** (7 runs) | syscall **never returned** → stuck in the kernel |

Runs with `calls=1, succ=1`: `a1_r1 a1_r2 a2_r1 b1_r1 b1_r2 b1_r3 bk2a bk2b bk2c bk3_safe_r1..r4
d2_r1 d2_r2 dla_r1 dla_r2 dna_r1..r3 g1_r1 ga_r1..r3 hold k1_r1..r3 ring1g ring1m ring1t`
Runs with `calls=1, succ=0` and no `seq` line: `a2_r2 paint_20261005_193115 ring1j ring1n
ring1u w1_r1 wa_r1`

`rt_mutex_adjust_prio_chain()` has exactly **one** non-returning path — the
`585 → 586 raw_spin_unlock_irq → 587 cpu_relax → 588 goto retry` loop. Every one of its
other exits returns. So "never returned" ⇒ **the walk is spinning at 585**, i.e. the trylock
failed. That part of the old belief survives.

## 3. The contradiction

`paint_20261005_193115.log` (the only run with `IONSTACK_PAINT_LOCK_DELTA=0x1cb0`):

```
paint: ... prio=2147483647 fill=0 namelen=40 msg_iovlen=8 paint_lock=ffffffc1b1072180
page-dump tag=post-arm+200ms ... first_diff=8000(pristine) wait_lock=00000000
    owner_cpu=00000000 wait_owner=0000000000000000
    root=ffffffc1b10713a0 leftmost=ffffffc1b10713a0
    scratch=0,0,0,0|0,0,0,0|sc_owner=0 sc_next=0
paint-result verdict=painted survived=1 armed=1 consumer_calls=1 consumer_success=0
```

`waiter->lock` was painted to `SCRATCH` (`base + 0x2180`), whose `wait_lock` is 0, so 585
**must** succeed — and it did not, and the consumer never returned.

At the same time `wait_lock_word` perfectly predicts the outcome across the record
(`bisect.sh:105-109`: *"23/23 cs=1 at wl=0 vs 4/4 cs=0 at wl=1"*), which can only be true if
the paint **does** reach `fake_lock`.

Both can hold only if **`waiter->lock` is not at `E+0x38`** (or `E != SP0-0x190`), while some
other painted field does land on `fake_lock`'s `wait_lock` word.

## 4. Consequences

* Retracted: *"the crash point is `rtmutex.c:664`"* (from `ring1e`/`ring1i`). Those runs
  never wrote the page, so they cannot localise anything below 585.
* Retracted: *"the paint lands ≈2/3 of the time"*. That was inferred from `PAINT_PRIO=120`
  runs returning 0 — but an **unpainted** residual waiter also has `prio == 120` and
  `deadline == 0` (set by `task_blocks_on_rt_mutex`), so `1135` early-returns and the syscall
  returns 0 there too. `succ=1` is therefore **not** a landing proof.
* Corrected: the lock oracle is **not** blind to success — success has three signatures. It
  is blind to *failure* (`raw_spin_trylock` writes nothing when it fails), which is why a
  stall cannot be localised from the page alone.

## 5. The probe that separates the two hypotheses

`IONSTACK_PAINT_LOCK_FILL=1` puts `paint_lock` at **every** 8-byte slot `0x00..0x38` of the
paint buffer. Then, whichever slot the walk actually reads as `waiter->lock`, it reads
`fake_lock`, whose `wait_lock` is 0 ⇒ 585 succeeds **if the paint lands at all**. And
`first_diff` becomes `lock_off + 8*slot`, which **names the true slot**.

Expected outcomes:

| observation | conclusion |
|---|---|
| `ring1-lock585 hit=1`, `first_diff` = `0x4d0 + 8k` | paint lands; the true `waiter->lock` slot is `k`; 585 reached and passed ⇒ look at 600/664/685/716/723 |
| survives, page pristine, `succ=1` | the walk exits before 585 ⇒ re-check the 1135/569 gates |
| spins at 585 (`succ=0`, no `seq` line) | the paint does not reach `E+0x38` at all ⇒ `E` is wrong; sweep `IONSTACK_PAINT_LOCK_SLOT` |

`IONSTACK_PAINT_LOCK_SLOT` / `IONSTACK_PAINT_TASK_SLOT` sweep the slot individually for the
follow-up. All three are survivable by design (a failing trylock spins; it does not panic —
that is the `ring1j` behaviour).

## 6. Tooling added

* **Durable fsync log mirror** (ported from `ccp-p/ghostlock-cve-2026-43499-4.19-k40`):
  every `pr_*()` line is also `write()`+`fsync()`-ed to
  `/sdcard/Download/log_<ts>.txt` → `/sdcard/Downloads/...` → `/data/local/tmp/log_<ts>.txt`,
  overridable with `IONSTACK_LOG_FILE`. `IONSTACK_LOG_MIRROR=0` / `IONSTACK_LOG_FSYNC=0`
  disable it. This is what makes the next round readable after a panic reboot.
* `verify_paint_gate()` now emits `ring1-lock585 hit=<0|1> wait_lock=… owner_cpu=… wait_owner=…
  root=… leftmost=…` so the three signatures cannot be overlooked again.
