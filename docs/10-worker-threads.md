# EAC In-Game Service: Worker Thread System

Binary: `devirt/eac_service_decoded.dylib` (Mach-O arm64)

## Architecture Overview

The EAC in-game service uses a **5-worker-queue architecture** embedded within a
service context object of 0x2B20 bytes. All worker queues share the same
infrastructure: a priority tree for scheduled jobs, mutex/condvar
synchronization, and a common job-loop thread entry point.

No `pthread_create` calls appear in the emulation trace because the thread
starters are called **from virtualized (CV) code** -- the native starters
themselves are thin wrappers that set up the queue and call `pthread_create`,
but the CV dispatch that invokes them was not reached during the trace. The
trace does show 52 `pthread_mutex_init` and 14 `pthread_cond_init` calls,
confirming all synchronization primitives are initialized eagerly during
service construction.

### Queue Locations in Service Context

| Queue | Offset   | Starter        | Notes                              |
|-------|----------|----------------|------------------------------------|
| Q0    | +0x1C78  | sub_4408       | Dual-queue pair, first half        |
| Q1    | +0x1E90  | sub_4408       | Dual-queue pair, second half (+0x200 from Q0's base) |
| Q2    | +0x2090  | sub_5DE4       | Worker at subobj+0x16E0; mode flags at +8/+0xC |
| Q3    | +0x22A8  | sub_43928      | Lazy-allocated via 0x218-byte object |
| Q4    | +0x26A8  | sub_4F860      | Worker at subobj+0x50             |

Queue sizes (measured by inter-queue deltas): 0x218, 0x200, 0x218, 0x400 bytes.
The standard queue object is 0x218 bytes; Q4 at 0x400 likely has an extended
payload area or is followed by the callback list at +0x26B0.

---

## Worker Queue Object Layout (0x218 bytes, vtable off_B54A8)

```
+0x000  vtable*           -> off_B54A8 (6 entries)
+0x008  pthread_t thread  (stored by start(), zeroed on stop)
+0x010  condvar_wrapper   (sub_4C600: mutex at +0x30, pthread_cond at +0x00)
        ... (used by job-loop for wakeup)
+0x088  atomic<bool> stopped  (release-store: stlrb)
+0x090  mutex_wrapper     (sub_4C8A0)
+0x0D0  tree_root*        (RB-tree left-child pointer)
+0x0D8  tree_sentinel     (sentinel node, self-referencing)
+0x0E0  tree_size         (node count)
+0x0E8  tree_mutex        (protects insert/remove)
+0x128  condvar_wrapper   (wakeup condition for job availability)
+0x1A0  current_time      (mach_absolute_time snapshot during processing)
+0x1A8  current_job_id    (u32)
+0x1B0  mutex_wrapper     (protects dequeue scan)
+0x1F0  jobs_submitted    (u32, incremented on enqueue)
+0x1F4  jobs_completed    (u32, incremented after execute)
+0x1F8  atomic<bool> drain_flag  (when set + submitted==completed, loop exits)
```

### Vtable off_B54A8

| Slot | Address  | Function                                          |
|------|----------|---------------------------------------------------|
| [0]  | 0x4BA00  | destructor (no-free): calls sub_4B988 (teardown)  |
| [1]  | 0x4BA04  | destructor (free): teardown + operator delete      |
| [2]  | 0x4BCF4  | stop(): signal drain, join thread                  |
| [3]  | 0x4B9DC  | stop_nowait(): signal drain, no join               |
| [4]  | 0x4BE2C  | **run_loop()**: main job-processing loop           |
| [5]  | 0x4CBB4  | returns 0 (is_running? / unused query)             |

---

## Thread Plumbing

### sub_4CA10 -- Trampoline (fn, arg)

```
trampoline(x0):
  if x0 == NULL: return 0
  {fn, arg} = *(x0)        // x0 points to 16-byte struct {fn_ptr, arg_ptr}
  fn(arg)                   // blr x8
  free(x0)                  // operator delete
  return 0
```

Allocates a `{function, argument}` pair on the heap (see sub_4CB18 which does
the `_Znwm(0x10)` + `stp` before `pthread_create`). The trampoline calls the
function, frees the pair, and returns NULL as the thread result.

### sub_4CBBC -- start(worker)

```
start(worker):
  lock(worker+0x90)                    // scoped lock on queue mutex
  if worker->thread != 0:             // already running
    unlock(); return 0
  worker->stopped = 0                 // stlrb wzr, [x8] (release store)
  condvar_signal(worker+0x10)         // wake any waiters
  pthread_create(&worker->thread,     // at worker+8
                 NULL,
                 sub_4CA44,           // job-loop entry
                 worker)              // pass queue object as arg
  return (result == 0) ? 1 : 0       // cset w19, eq
```

Key: the thread entry point is **sub_4CA44**, which dispatches through the
vtable to reach the real loop body.

### sub_4CA44 -- Job-Loop Entry (pthread entry point)

```
job_loop_entry(worker):
  if worker == NULL: return 0
  vtable = *(worker)
  vtable[4](worker)        // calls run_loop at vtable+0x20 -> sub_4BE2C
  return 0
```

A simple vtable dispatch: loads `[x0] -> vtable`, then calls `[vtable+0x20]`
which is slot [4] = `sub_4BE2C` (run_loop).

---

## Job Loop Mechanics (sub_4BE2C -- run_loop)

The run_loop is the core of each worker thread. Pseudocode:

```c
void run_loop(WorkerQueue* self) {
    if (is_stopped(self))           // check atomic bool at +0x88
        return;

    while (true) {
        // Check drain condition
        if (self->drain_flag) {
            if (self->jobs_completed == self->jobs_submitted)
                return;             // all work done, exit
        }

        // Calculate sleep time from priority tree
        int wait_ms = calc_next_deadline(self);   // sub_4C088
        condvar_timedwait(self+0x128, wait_ms);   // sub_4C71C
        condvar_signal(self+0x128);               // sub_4C6D8

        // Dequeue the next ready job
        JobItem item;
        scoped_lock(self+0x1B0);
        if (!pop_ready_job(self, &item))          // sub_4C19C
            goto check_stop;

        // Execute the job
        if (!is_stopped(self)) {
            self->current_time = mach_absolute_time();
            self->current_job_id = item.job_id;
            execute_job(&item);                   // sub_4C278
            self->current_time = 0;
            self->current_job_id = 0;

            // Re-enqueue if periodic
            if (!item.cancelled && item.reschedule) {
                submit_job(self, &item, ...);     // sub_4BA28
            }
            self->jobs_completed++;
        }

        // Check stop condition
        if (is_stopped(self))
            return;
    }
}
```

### Priority Tree (std::map / RB-tree)

Jobs are stored in a **red-black tree** ordered by **deadline timestamp**
(field at node+0x78, compared as unsigned words at +0x70 in the insert path).

- **Insert** (sub_4C4D8): allocates 0x88-byte tree node, copies job payload
  into node+0x20, inserts into RB-tree sorted by priority/timestamp.
- **Pop** (sub_4C19C): walks the tree to find the earliest-deadline node where
  `mach_absolute_time() >= node->deadline`. Copies payload, calls
  sub_4C43C (tree erase + free node).
- **Deadline calc** (sub_4C088): scans the tree for the minimum deadline,
  computes sleep duration in milliseconds as
  `(min_deadline - now) / 1,000,000`, clamped to 0.

### Job Execution (sub_4C278)

```c
void execute_job(JobItem* item) {
    void* fn = item->callback ? item->callback : item->fallback;
    if (item->target) {
        bool ok = item->target->vtable->execute(item->target, &fn);
        if (!ok && !item->cancelled)
            item->cancelled = 1;
    }
}
```

Each job carries a target object pointer (+0x18), a primary callback (+0x20),
and a fallback (+0x30). Execution goes through a vtable call on the target
object (slot [6], offset 0x30 in vtable), passing the function pointer.
This is how VM-virtualized handlers get invoked from native worker threads.

---

## Starter Functions

### sub_4408 -- Dual-Queue Starter

Called from VM code to start **two worker queues** on a single object:

```c
bool start_dual(WorkerQueue* base) {
    if (!start(base))                    // sub_4CBBC on base+0
        return 0;
    WorkerQueue* second = base + 0x200;  // add x20, x19, #0x200
    if (!start(second))                  // sub_4CBBC on base+0x200
        return 0;
    notify(base, 0);                     // sub_4CDD0 -- dispatch wakeup
    notify(second, 0);                   // sub_4CDD0
    return 1;
}
```

Manages a **paired queue** pattern -- two independent job loops running on
adjacent memory (Q0 at ctx+0x1C78 and Q1 at ctx+0x1E90). The companion
shutdown function (sub_4470 at 0x4470) iterates a list of registered
observers via vtable[1] calls, then stops both queues via sub_4BCF4.

**Purpose**: Primary processing pair -- likely one for incoming network
messages and one for outgoing responses / heartbeats.

### sub_5DE4 -- Worker with Mode Flags

```c
void start_worker_with_mode(ServiceSubobj* obj, uint32_t mode) {
    start(obj + 0x16E0);                 // sub_4CBBC: worker queue at +0x16E0
    atomic_store_release(&obj->mode, mode);   // stlr w19, [x8] at +0xC
    atomic_store_release(&obj->active, 1);    // stlrb w9, [x8] at +8
}
```

The companion shutdown (sub_5E28 at 0x5E28) stops the queue, clears flag at
+0x13FC, and resets mode/active to 0.

**Purpose**: Detection/scanning worker. The mode flags control which
detection modules are active (VM detection, integrity checks, etc.).
Offset 0x16E0 = 5856 into the subobject indicates this is part of a large
detection subsystem structure.

### sub_43928 -- Lazy Shared Object

```c
void start_lazy_worker(DetectionConfig* cfg) {
    lock(cfg);                           // sub_43BAC
    if (cfg->type != 1)                  // ldr w8, [x19, #0x8C]; cmp w8, #1
        return;
    // Allocate new queue object
    void* q = operator_new(0x218);       // _Znwm(0x218)
    memset(q+8, 0, 16);                  // stp xzr,xzr,[x0,#8]
    q->vtable = off_B5318;              // lazy queue vtable
    queue_init(q + 0x18);               // sub_4B984: full RB-tree + sync init

    // Replace old shared ref
    old = cfg->shared_ref;              // +0x98
    cfg->worker = q;                    // +0x90
    cfg->queue = q;                     // +0x90 pair
    release(old);                       // atomic decrement + destructor

    // Start the queue thread
    start(cfg->worker);                 // sub_4CBBC
    cfg->started = 1;                   // strb w8, [x19, #0xA0]
}
```

Conditionally creates a **new 0x218-byte worker queue** with its own vtable
(off_B5318) when the configuration type field equals 1. Uses reference
counting (atomic decrement + destructor pattern) for the shared object
lifecycle.

**Purpose**: On-demand detection worker, allocated only when a specific
detection mode is requested by the server. The lazy pattern avoids thread
overhead when that mode is disabled.

### sub_4F860 -- Simple Worker Start

```c
void start_simple(Subobj* obj) {
    start(obj + 0x50);                   // sub_4CBBC on subobj+0x50
}
```

The simplest starter: just forwards to `start()` on a queue at offset 0x50.
The companion (sub_4F86C) does a double `stop()` call (sub_4BCF4 twice),
suggesting this queue might have a sub-queue or there is an intentional
double-drain pattern.

**Purpose**: Auxiliary/timer worker. Given its simplicity and the small offset,
this is likely a periodic heartbeat or keepalive timer queue.

---

## Synchronization Primitives

All mutexes are initialized with `pthread_mutexattr_settype(attr, 2)` --
**PTHREAD_MUTEX_RECURSIVE** -- allowing the same thread to re-lock without
deadlock. This is essential because job execution callbacks may themselves
enqueue new jobs or query queue state.

From the trace:
- **52 mutex_init** calls (covers all queues, tree locks, condvar guards)
- **14 cond_init** calls (one per queue wakeup, plus internal coordination)
- **16 mutex_lock / 16 mutex_unlock** pairs during initialization
- **2 cond_broadcast** calls during startup signaling

### Wakeup / Notify (sub_4CDD0)

The notify function dispatches based on a mode parameter:

| Mode | Action                                       |
|------|----------------------------------------------|
| 0    | `sched_yield(1)` + compute core-count-based delay |
| 1    | `sched_yield(1)` + fixed delay formula       |
| 2    | `usleep(1)` + store result                   |

After computing the delay, it calls `kevent64` (at 0x9CD78) to signal the
worker thread via a kernel event. This is a macOS-specific high-performance
wakeup mechanism.

---

## Job Item Structure (0x88 bytes in tree node)

```
Tree node (0x88 bytes total):
+0x00  left_child*
+0x08  right_child*
+0x10  parent*
+0x18  color (red/black)

Job payload (at node+0x20, copied from submission):
+0x20  timestamp / ID pair (from sub_51F8 - likely a unique job ID)
+0x48  target_object*     (vtable-dispatched execution target)
+0x50  shared_ref*        (reference-counted shared state)
+0x58  shared_ref2*
+0x60  flags byte
+0x64  delay_ms (u32)     (scheduling delay)
+0x68  repeat_ms (u32)    (reschedule interval, 0 = one-shot)
+0x70  callback*          (function pointer to execute)
+0x78  deadline           (mach_absolute_time + delay * 1,000,000)
+0x80  priority (u32)     (tree ordering key when deadlines match)
```

The deadline is computed as: `mach_absolute_time() + delay_ms * 0xF4240`
(0xF4240 = 1,000,000, converting milliseconds to nanoseconds for the Mach
timebase).

---

## Thread Count Summary

| Component          | Threads | Entry Point   | Controlled By |
|-------------------|---------|---------------|---------------|
| Primary pair (Q0) | 1       | sub_4CA44     | sub_4408      |
| Primary pair (Q1) | 1       | sub_4CA44     | sub_4408      |
| Detection worker  | 1       | sub_4CA44     | sub_5DE4      |
| Lazy detection    | 0-1     | sub_4CA44     | sub_43928     |
| Aux/timer worker  | 1       | sub_4CA44     | sub_4F860     |
| **Total**         | **4-5** |               |               |

Plus the trampoline mechanism (sub_4CB18 / sub_4CA10) which can spawn
**additional ad-hoc threads** for one-shot async operations outside the
queue system. These are fire-and-forget: allocate {fn,arg}, pthread_create
with trampoline entry, trampoline calls fn(arg) then frees the pair.

---

## Key Observations

1. **All workers share the same code path**: sub_4CA44 -> vtable[4] -> sub_4BE2C.
   The differentiation is in what jobs are enqueued, not how they are processed.

2. **Priority scheduling**: The RB-tree orders jobs by deadline, giving the
   system precise timer-based scheduling without a dedicated timer thread.

3. **No pthread_create in trace**: Thread creation is gated behind VM-dispatched
   starters. The emulation harness hits the native init (mutex/condvar setup)
   but never reaches the CV code that calls the starters. Extending the harness
   to trace worker threads would require either:
   - Emulating the CV dispatch that calls sub_4408/5DE4/43928/4F860, or
   - Hooking the starters directly with forced arguments.

4. **Recursive mutexes everywhere**: Allows re-entrant job submission from
   within job execution callbacks -- a critical design choice for the
   detection pipeline where scan results may trigger follow-up scans.

5. **Drain protocol**: Setting `drain_flag` (atomic bool at +0x1F8) causes
   the loop to exit only after `jobs_completed == jobs_submitted`, ensuring
   graceful shutdown without losing queued work.
