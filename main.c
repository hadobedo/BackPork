#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>

#include <sys/event.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>


#define IOVEC_ENTRY(x) {x ? (char *)x : 0, x ? strlen(x) + 1 : 0}
#define IOVEC_SIZE(x) (sizeof(x) / sizeof(struct iovec))

#define PAYLOAD_NAME "backpork.elf"
#define LOG_DIR "/data/backpork"
#define LOG_FILE "/data/backpork/debug.log"
#define SHELLCORE_FLAG_WAITMODE_OR 2u
#define SHELLCORE_FLAG_ALL_BITS UINT64_MAX
#define RESUME_SETTLE_US 2000000ull
#define REST_POLL_US 250000u

typedef intptr_t backpork_event_flag_t;

enum {
    SYSTEM_STATE_SHUTDOWN_ON_GOING = 100u,
    SYSTEM_STATE_POWER_SAVING = 200u,
    SYSTEM_STATE_SUSPEND_ON_GOING = 300u,
    SYSTEM_STATE_MAIN_ON_STANDBY = 500u,
    SYSTEM_STATE_WORKING = 1000u,
};

typedef struct notify_request {
    char unused[45];
    char message[3075];
} notify_request_t;

typedef struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    char title_id[14];
    char unknown2[0x3c];
} app_info_t;

typedef struct active_fakelib_mount {
    bool valid;
    bool mounted;
    bool unmounted_for_rest;
    pid_t pid;
    char title_id[10];
    char sandbox_id[14];
    char mount_path[PATH_MAX + 1];
} active_fakelib_mount_t;

extern int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);
extern int sceKernelGetAppInfo(pid_t pid, app_info_t *info);
extern int sceKernelOpenEventFlag(backpork_event_flag_t *ef, const char *name);
extern int sceKernelPollEventFlag(backpork_event_flag_t ef, uint64_t bit_pattern,
                                  unsigned int wait_mode,
                                  uint64_t *result_pattern);
extern int sceKernelCloseEventFlag(backpork_event_flag_t ef);

static backpork_event_flag_t g_system_state_flag = -1;
static bool g_power_paused = false;
static bool g_stop_requested = false;
static bool g_have_system_state = false;
static unsigned g_last_system_state = 0;
static int g_last_power_poll_rc = 0;
static bool g_have_power_poll_rc = false;
static uint64_t g_last_resume_us = 0;
static active_fakelib_mount_t g_active_mount = {0};
static FILE *g_log_file = NULL;

static void close_log_file(void) {
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
}

static void open_log_file(void) {
    mkdir(LOG_DIR, 0777);
    g_log_file = fopen(LOG_FILE, "a");
    if (g_log_file) {
        setvbuf(g_log_file, NULL, _IOLBF, 0);
    }
}

static void log_msg(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    if (!g_log_file) {
        return;
    }

    va_start(args, fmt);
    vfprintf(g_log_file, fmt, args);
    va_end(args);
    fflush(g_log_file);
    fsync(fileno(g_log_file));
}

static void notify(const char* fmt, ...) {
    notify_request_t req = {};
    va_list args;
    va_start(args, fmt);
    vsnprintf(req.message, sizeof(req.message) - 1, fmt, args);
    va_end(args);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

static uint64_t monotonic_time_us(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000ull);
}

static void clear_active_mount(void) {
    memset(&g_active_mount, 0, sizeof(g_active_mount));
}

static void remember_active_mount(pid_t pid, const char *title_id,
                                  const char *sandbox_id,
                                  const char *mount_path) {
    clear_active_mount();
    g_active_mount.valid = true;
    g_active_mount.mounted = true;
    g_active_mount.pid = pid;
    snprintf(g_active_mount.title_id, sizeof(g_active_mount.title_id), "%s",
             title_id ? title_id : "");
    snprintf(g_active_mount.sandbox_id, sizeof(g_active_mount.sandbox_id), "%s",
             sandbox_id ? sandbox_id : "");
    snprintf(g_active_mount.mount_path, sizeof(g_active_mount.mount_path), "%s",
             mount_path ? mount_path : "");
    log_msg("[STATE] active mount: pid=%d title=%s sandbox=%s path=%s\n",
            (int)g_active_mount.pid, g_active_mount.title_id,
            g_active_mount.sandbox_id, g_active_mount.mount_path);
}

static void unmount_active_fakelib_for_rest(unsigned state) {
    if (!g_active_mount.valid || !g_active_mount.mounted ||
        g_active_mount.mount_path[0] == '\0') {
        return;
    }

    log_msg("[POWER] unmounting fakelib before rest state %u: pid=%d title=%s sandbox=%s path=%s\n",
            state, (int)g_active_mount.pid, g_active_mount.title_id,
            g_active_mount.sandbox_id, g_active_mount.mount_path);
    if (unmount(g_active_mount.mount_path, 0) == 0 || errno == ENOENT ||
        errno == EINVAL) {
        g_active_mount.mounted = false;
        g_active_mount.unmounted_for_rest = true;
        log_msg("[POWER] fakelib unmounted for rest: title=%s sandbox=%s path=%s\n",
                g_active_mount.title_id, g_active_mount.sandbox_id,
                g_active_mount.mount_path);
        return;
    }

    int err = errno;
    log_msg("[WARNING] fakelib rest unmount failed: %s errno=%d %s\n",
            g_active_mount.mount_path, err, strerror(err));
}

static bool is_rest_state(unsigned state) {
    return state == SYSTEM_STATE_POWER_SAVING ||
           state == SYSTEM_STATE_SUSPEND_ON_GOING ||
           state == SYSTEM_STATE_MAIN_ON_STANDBY;
}

static void apply_system_state(unsigned state) {
    bool changed = !g_have_system_state || g_last_system_state != state;
    unsigned previous_state = g_have_system_state ? g_last_system_state : 0;
    g_have_system_state = true;
    g_last_system_state = state;

    if (changed) {
        log_msg("[POWER] state transition previous=%u current=%u paused=%d active_valid=%d active_mounted=%d active_unmounted_for_rest=%d\n",
                previous_state, state, g_power_paused ? 1 : 0,
                g_active_mount.valid ? 1 : 0, g_active_mount.mounted ? 1 : 0,
                g_active_mount.unmounted_for_rest ? 1 : 0);
    }

    if (state == SYSTEM_STATE_SHUTDOWN_ON_GOING) {
        if (!g_stop_requested) {
            log_msg("[POWER] shutdown in progress, stopping BackPork work\n");
        }
        g_stop_requested = true;
        return;
    }

    if (is_rest_state(state)) {
        if (!g_power_paused) {
            log_msg("[POWER] pausing BackPork work for system state %u\n", state);
        }
        g_power_paused = true;
        unmount_active_fakelib_for_rest(state);
        return;
    }

    if (state == SYSTEM_STATE_WORKING && g_power_paused) {
        g_power_paused = false;
        g_last_resume_us = monotonic_time_us();
        log_msg("[POWER] resumed from system state %u, settling for %u ms\n",
               previous_state, (unsigned)(RESUME_SETTLE_US / 1000ull));
        return;
    }

    if (changed) {
        log_msg("[POWER] system state %u\n", state);
    }
}

static void poll_power_state(void) {
    if (g_system_state_flag < 0) {
        return;
    }

    uint64_t pattern = 0;
    int rc = sceKernelPollEventFlag(g_system_state_flag, SHELLCORE_FLAG_ALL_BITS,
                                    SHELLCORE_FLAG_WAITMODE_OR, &pattern);
    if (rc < 0) {
        if (!g_have_power_poll_rc || g_last_power_poll_rc != rc) {
            log_msg("[POWER] poll failed: 0x%08X\n", (unsigned)rc);
            g_have_power_poll_rc = true;
            g_last_power_poll_rc = rc;
        }
        return;
    }

    g_have_power_poll_rc = true;
    g_last_power_poll_rc = 0;

    apply_system_state((unsigned)(pattern & 0xffffu));
}

static bool init_power_state_monitor(void) {
    int rc = sceKernelOpenEventFlag(&g_system_state_flag, "SceSystemStateMgrInfo");
    if (rc < 0) {
        g_system_state_flag = -1;
        log_msg("[WARNING] SceSystemStateMgrInfo unavailable: 0x%08X\n",
               (unsigned)rc);
        return false;
    }

    poll_power_state();
    log_msg("[POWER] monitoring SceSystemStateMgrInfo\n");
    return true;
}

static void shutdown_power_state_monitor(void) {
    if (g_system_state_flag >= 0) {
        sceKernelCloseEventFlag(g_system_state_flag);
        g_system_state_flag = -1;
    }
}

static bool in_resume_settle_window(void) {
    poll_power_state();
    if (g_last_resume_us == 0) {
        return false;
    }

    uint64_t now_us = monotonic_time_us();
    return now_us != 0 && now_us - g_last_resume_us < RESUME_SETTLE_US;
}

static bool should_pause_work(void) {
    poll_power_state();
    return g_stop_requested || g_power_paused;
}

static bool should_defer_mount_work(void) {
    return should_pause_work() || in_resume_settle_window();
}

static bool wait_until_work_ready(void) {
    while (should_defer_mount_work()) {
        if (g_stop_requested) {
            return false;
        }
        usleep(REST_POLL_US);
    }
    return true;
}

static bool is_process_alive(pid_t pid) {
    if (kill(pid, 0) == 0) {
        return true;
    }
    return errno != ESRCH;
}

// from john-tornblom
static pid_t find_pid(const char *name) {
    int mib[4] = {1, 14, 8, 0};
    pid_t mypid = getpid();
    pid_t pid = -1;
    size_t buf_size;
    uint8_t *buf;

    if (sysctl(mib, 4, 0, &buf_size, 0, 0)) {
        return -1;
    }

    if (!(buf = malloc(buf_size))) {
        return -1;
    }

    if (sysctl(mib, 4, buf, &buf_size, 0, 0)) {
        free(buf);
        return -1;
    }

    for (uint8_t *ptr = buf; ptr < (buf + buf_size);) {
        int ki_structsize = *(int *)ptr;
        pid_t ki_pid = *(pid_t *)&ptr[72];
        char *ki_tdname = (char *)&ptr[447];

        ptr += ki_structsize;
        if (!strcmp(name, ki_tdname) && ki_pid != mypid) {
            pid = ki_pid;
        }
    }

    free(buf);

    return pid;
}

static int cleanup_directory(const char *path) {
    if (should_defer_mount_work()) {
        log_msg("[CLEANUP] deferred directory cleanup path=%s paused=%d settle=%d\n",
                path, g_power_paused ? 1 : 0,
                in_resume_settle_window() ? 1 : 0);
        errno = EINTR;
        return -1;
    }

    DIR *d = opendir(path);
    if (!d) {
        return -1;
    }

    int result = 0;
    struct dirent *entry;

    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[PATH_MAX];
        int path_len = snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        if (path_len < 0 || path_len >= sizeof(full_path)) {
            result = -1;
            break;
        }

        struct stat st;
        if (stat(full_path, &st) != 0) {
            result = -1;
            break;
        }

        if (S_ISDIR(st.st_mode)) {
            if (cleanup_directory(full_path) != 0) {
                result = -1;
                break;
            }
        }
        // Skip files (don't delete them)
    }

    closedir(d);

    if (result == 0) {
        result = rmdir(path);
    }

    return result;
}

static int mount2(const char *src, const char *dst, const char *type) {
    if (should_defer_mount_work()) {
        log_msg("[MOUNT] deferred mount2 type=%s src=%s dst=%s paused=%d settle=%d\n",
                type, src, dst, g_power_paused ? 1 : 0,
                in_resume_settle_window() ? 1 : 0);
        errno = EINTR;
        return -1;
    }

    struct iovec iov[] = {
        IOVEC_ENTRY("fstype"),
        IOVEC_ENTRY(type),
        IOVEC_ENTRY("from"),
        IOVEC_ENTRY(src),
        IOVEC_ENTRY("fspath"),
        IOVEC_ENTRY(dst),
    };

    log_msg("[MOUNT] nmount type=%s src=%s dst=%s\n", type, src, dst);
    int ret = nmount(iov, IOVEC_SIZE(iov), 0);
    if (ret != 0) {
        log_msg("[MOUNT] nmount failed type=%s src=%s dst=%s errno=%d %s\n",
                type, src, dst, errno, strerror(errno));
    } else {
        log_msg("[MOUNT] nmount ok type=%s dst=%s\n", type, dst);
    }
    return ret;
}


static char *mount_fakelibs(const char *sandbox_id, const char *cwd, pid_t pid, char *random_folder) {
    (void)pid;
    if (!wait_until_work_ready()) {
        return NULL;
    }

    char fake_path[PATH_MAX + 1];
    snprintf(fake_path, sizeof(fake_path), "%s/fakelib", cwd);
    log_msg("[PATCH] fakelib check sandbox=%s cwd=%s fake=%s random=%s\n",
            sandbox_id, cwd, fake_path, random_folder);

    struct stat st;
    if (stat(fake_path, &st) != 0) {
        log_msg("[WARNING] stat on %s failed (errno: %d, %s)\n", fake_path, errno, strerror(errno));
        return NULL;
    }

    char *fake_mount_path = (char *)malloc(PATH_MAX + 1);
    if (!fake_mount_path) {
        return NULL;
    }

    snprintf(fake_mount_path, PATH_MAX + 1, "/mnt/sandbox/%s/%s/common/lib", sandbox_id, random_folder);
    log_msg("[PATCH] fakelib mount target=%s\n", fake_mount_path);

    if (should_defer_mount_work()) {
        log_msg("[PATCH] deferred before fakelib mount target=%s\n", fake_mount_path);
        free(fake_mount_path);
        return NULL;
    }

    int res = mount2(fake_path, fake_mount_path, "unionfs");
    if (res != 0) {
        log_msg("[WARNING] mount_unionfs failed: %d (errno: %d, %s)\n", res, errno, strerror(errno));
        unmount(fake_mount_path, MNT_FORCE);
        free(fake_mount_path);
        return NULL;
    }

    log_msg("[INFO] Mounted fakelibs from %s to %s\n", fake_path, fake_mount_path);
    log_msg("[PATCH] fakelib mounted source=%s target=%s\n", fake_path, fake_mount_path);
    return fake_mount_path;
}

static bool wait_for_pid_exit(pid_t pid) {
    int kq = kqueue();
    if (kq == -1) {
        log_msg("[WARNING] kqueue failed while waiting for pid %d: %s\n",
                pid, strerror(errno));
        while (!g_stop_requested && is_process_alive(pid)) {
            wait_until_work_ready();
            usleep(REST_POLL_US);
        }
        return !g_stop_requested;
    }

    struct kevent kev;
    EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR, NOTE_EXIT, 0, NULL);

    int ret = kevent(kq, &kev, 1, NULL, 0, NULL);
    if (ret == -1) {
        log_msg("[WARNING] kevent registration failed for pid %d: %s\n", pid, strerror(errno));
        close(kq);
        while (!g_stop_requested && is_process_alive(pid)) {
            wait_until_work_ready();
            usleep(REST_POLL_US);
        }
        return !g_stop_requested;
    }

    log_msg("[WAIT] waiting for pid=%d active_valid=%d active_mounted=%d active_unmounted_for_rest=%d\n",
            pid, g_active_mount.valid ? 1 : 0, g_active_mount.mounted ? 1 : 0,
            g_active_mount.unmounted_for_rest ? 1 : 0);
    bool logged_defer = false;

    while (!g_stop_requested) {
        if (should_defer_mount_work()) {
            if (!logged_defer) {
                log_msg("[WAIT] deferring pid wait pid=%d paused=%d settle=%d\n",
                        pid, g_power_paused ? 1 : 0,
                        in_resume_settle_window() ? 1 : 0);
                logged_defer = true;
            }
            usleep(REST_POLL_US);
            continue;
        }
        logged_defer = false;

        struct kevent event;
        struct timespec timeout = {0, REST_POLL_US * 1000};
        int nev = kevent(kq, NULL, 0, &event, 1, &timeout);

        if (nev < 0) {
            log_msg("[WARNING] kevent wait failed: %s\n", strerror(errno));
            close(kq);
            return !is_process_alive(pid);
        }

        if (nev > 0 && event.fflags & NOTE_EXIT) {
            log_msg("[INFO] Process %d exited\n", pid);
            if (!wait_until_work_ready()) {
                close(kq);
                return false;
            }
            break;
        }

        if (!is_process_alive(pid)) {
            log_msg("[INFO] Process %d is no longer alive\n", pid);
            if (!wait_until_work_ready()) {
                close(kq);
                return false;
            }
            break;
        }
    }

    close(kq);
    return !g_stop_requested;
}

static int find_highest_sandbox_number(const char* title_id) {
    if (should_defer_mount_work()) {
        return -1;
    }

    char base_path[PATH_MAX];
    int highest = -1;

    for (int i = 0; i < 1000; i++) {
        snprintf(base_path, sizeof(base_path), "/mnt/sandbox/%s_%03d", title_id, i);

        struct stat st;
        if (stat(base_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            highest = i;
        } else {
            break;
        }
    }

    return highest;
}

static char* find_random_folder(const char* title_id, int sandbox_num) {
    if (should_defer_mount_work()) {
        return NULL;
    }

    char base_path[PATH_MAX];
    snprintf(base_path, sizeof(base_path), "/mnt/sandbox/%s_%03d", title_id, sandbox_num);

    DIR* dir = opendir(base_path);
    if (!dir) {
        log_msg("[WARNING] Failed to open directory: %s\n", base_path);
        return NULL;
    }

    struct dirent* entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s/common/lib", base_path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            closedir(dir);
            log_msg("[DEBUG] Found random folder: %s in sandbox %03d\n", entry->d_name, sandbox_num);
            return strdup(entry->d_name);
        }
    }

    closedir(dir);
    log_msg("[WARNING] No random folder found in %s\n", base_path);
    return NULL;
}

static void cleanup_game(pid_t pid, const char *sandbox_id, char *fake_mount_path) {
    bool tracked_mount =
        g_active_mount.valid && strcmp(g_active_mount.mount_path, fake_mount_path) == 0;
    log_msg("[CLEANUP] begin pid=%d sandbox=%s path=%s tracked=%d mounted=%d unmounted_for_rest=%d\n",
            (int)pid, sandbox_id, fake_mount_path, tracked_mount ? 1 : 0,
            g_active_mount.mounted ? 1 : 0,
            g_active_mount.unmounted_for_rest ? 1 : 0);

    // Wait for sandbox to be cleaned up by the system
    char sandbox_app0[PATH_MAX];
    snprintf(sandbox_app0, sizeof(sandbox_app0), "/mnt/sandbox/%s/app0", sandbox_id);
    log_msg("[INFO] Waiting for sandbox cleanup: %s\n", sandbox_app0);

    int wait_count = 0;
    struct stat sandbox_st;
    while (!g_stop_requested && stat(sandbox_app0, &sandbox_st) == 0 && wait_count < 30) {
        if (should_defer_mount_work()) {
            usleep(REST_POLL_US);
            continue;
        }
        usleep(1000000);
        wait_count++;
        if (wait_count % 5 == 0) {
            log_msg("[DEBUG] Still waiting for sandbox cleanup... (%d seconds)\n", wait_count);
        }
    }

    if (g_stop_requested) {
        log_msg("[INFO] Stop requested, leaving fakelib mount untouched: %s\n", fake_mount_path);
        free(fake_mount_path);
        return;
    }

    if (stat(sandbox_app0, &sandbox_st) == 0) {
        log_msg("[CLEANUP] sandbox still active after 30 stable seconds; skipping cleanup\n");
        free(fake_mount_path);
        return;
    } else {
        log_msg("[CLEANUP] sandbox app0 gone after %d seconds; cleanup may proceed\n", wait_count);
    }

    if (!wait_until_work_ready()) {
        log_msg("[INFO] Stop requested before cleanup, leaving fakelib mount untouched: %s\n", fake_mount_path);
        free(fake_mount_path);
        return;
    }

    // Unmount the fakelibs
    if (!tracked_mount || g_active_mount.mounted) {
        log_msg("[INFO] Unmounting %s\n", fake_mount_path);
        if (unmount(fake_mount_path, 0) != 0 && errno != ENOENT && errno != EINVAL) {
            log_msg("[WARNING] Failed to unmount %s: %s\n", fake_mount_path, strerror(errno));
        }
    } else {
        log_msg("[INFO] Fakelib already unmounted for rest: %s\n", fake_mount_path);
    }
    if (tracked_mount) {
        g_active_mount.mounted = false;
    }

    // Remove the entire sandbox directory
    char sandbox_dir[PATH_MAX];
    snprintf(sandbox_dir, sizeof(sandbox_dir), "/mnt/sandbox/%s", sandbox_id);
    log_msg("[INFO] Removing directory %s\n", sandbox_dir);
    if (cleanup_directory(sandbox_dir) == 0) {
		notify("Directory removed successfully.");
        log_msg("[INFO] Directory removed successfully\n");
    } else {
        log_msg("[WARNING] Failed to remove directory: %s\n", strerror(errno));
    }

    free(fake_mount_path);
    if (tracked_mount) {
        clear_active_mount();
    }
    log_msg("[INFO] Cleanup finished.\n");
}

static void patch_game(pid_t child_pid, const char *title_id) {
    log_msg("[PATCH] begin pid=%d title=%s paused=%d settle=%d\n",
            (int)child_pid, title_id, g_power_paused ? 1 : 0,
            in_resume_settle_window() ? 1 : 0);
    if (!wait_until_work_ready()) {
        log_msg("[PATCH] aborted before sandbox lookup pid=%d title=%s\n",
                (int)child_pid, title_id);
        return;
    }

    // Find highest sandbox number
    int sandbox_num = find_highest_sandbox_number(title_id);
    if (sandbox_num == -1) {
        log_msg("[WARNING] No sandbox found for %s\n", title_id);
        return;
    }

    // Build sandbox_id
    char sandbox_id[14];
    snprintf(sandbox_id, sizeof(sandbox_id), "%s_%03d", title_id, sandbox_num);
    log_msg("[PATCH] sandbox selected title=%s sandbox_num=%d sandbox_id=%s\n",
            title_id, sandbox_num, sandbox_id);

    // Check if fakelib exists
    char fakelib_src_path[PATH_MAX];
    snprintf(fakelib_src_path, sizeof(fakelib_src_path), "/mnt/sandbox/%s/app0/fakelib", sandbox_id);
    struct stat st;
    if (stat(fakelib_src_path, &st) != 0) {
        log_msg("[PATCH] no fakelib path=%s errno=%d %s\n",
                fakelib_src_path, errno, strerror(errno));
        return;
    }

    if (!wait_until_work_ready()) {
        return;
    }

    // Find random folder
    char* random_folder = find_random_folder(title_id, sandbox_num);
    if (!random_folder) {
        log_msg("[WARNING] Failed to find random folder for %s\n", title_id);
        return;
    }

	notify("Detected game %s. Patching...", title_id);
    log_msg("[INFO] Detected game %s (pid %d) in sandbox %s. Patching...\n", title_id, child_pid, sandbox_id);

    char src_path[PATH_MAX];
    snprintf(src_path, sizeof(src_path), "/mnt/sandbox/%s/app0", sandbox_id);

    char* fake_mount_path = mount_fakelibs(sandbox_id, src_path, child_pid, random_folder);

    if (fake_mount_path) {
        remember_active_mount(child_pid, title_id, sandbox_id, fake_mount_path);
		notify("Patch successful. Waiting for game to exit...");
        log_msg("[INFO] Patch successful. Waiting for game to exit...\n");
        if (wait_for_pid_exit(child_pid)) {
            cleanup_game(child_pid, sandbox_id, fake_mount_path);
        } else {
            log_msg("[INFO] Stop requested, leaving fakelib mount untouched: %s\n", fake_mount_path);
            free(fake_mount_path);
        }
        if (g_active_mount.valid && g_active_mount.pid == child_pid) {
            clear_active_mount();
        }
    } else {
        log_msg("[PATCH] mount_fakelibs returned NULL pid=%d title=%s sandbox=%s\n",
                (int)child_pid, title_id, sandbox_id);
    }

    free(random_folder);
}

int main() {
    open_log_file();
    log_msg("\n========== BackPork debug build start %s pid=%d ==========\n",
            __DATE__ " " __TIME__, (int)getpid());
    syscall(SYS_thr_set_name, -1, PAYLOAD_NAME);

    int pid;
    while ((pid = find_pid(PAYLOAD_NAME)) > 0) {
        if (kill(pid, SIGKILL)) {
            log_msg("[WARNING] Failed to kill old instance pid=%d: %s\n",
                    pid, strerror(errno));
            close_log_file();
            return -1;
        }
        log_msg("[INFO] Killed old instance\n");
        sleep(1);
    }

    pid_t syscore_pid = find_pid("SceSysCore.elf");
    if (syscore_pid == -1) {
        log_msg("[WARNING] Failed to find SceSysCore.elf pid\n");
        close_log_file();
        return -1;
    }

    int kq = kqueue();
    if (kq == -1) {
        log_msg("[WARNING] kqueue failed for syscore monitor: %s\n", strerror(errno));
        close_log_file();
        return -1;
    }

    struct kevent kev;
    EV_SET(&kev, syscore_pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_FORK | NOTE_EXEC | NOTE_TRACK, 0, NULL);

    int ret = kevent(kq, &kev, 1, NULL, 0, NULL);
    if (ret == -1) {
        log_msg("[WARNING] kevent registration failed for syscore pid %d: %s\n",
                syscore_pid, strerror(errno));
        close(kq);
        close_log_file();
        return -1;
    }

    init_power_state_monitor();

	notify("Welcome To BackPork 0.1 By BestPig 🐷");
    log_msg("[INFO] Monitoring SceSysCore.elf (pid %d) for game launches...\n", syscore_pid);

    pid_t child_pid = -1;

    while (!g_stop_requested) {
        poll_power_state();
        if (should_defer_mount_work()) {
            usleep(REST_POLL_US);
            continue;
        }

        struct kevent event;
        struct timespec timeout = {0, REST_POLL_US * 1000};
        int nev = kevent(kq, NULL, 0, &event, 1, &timeout);

        if (nev < 0) {
            log_msg("[WARNING] syscore kevent wait failed: %s\n", strerror(errno));
            continue;
        }

        if (nev == 0) continue;

        if (event.fflags & NOTE_CHILD) {
            child_pid = event.ident;
        }

        if (event.fflags & NOTE_EXEC && child_pid != -1 && event.ident == child_pid) {
            app_info_t appinfo = {0};
            if (sceKernelGetAppInfo(child_pid, &appinfo) != 0) {
                child_pid = -1;
                continue;
            }

            char title_id[10] = {0};
            memcpy(title_id, appinfo.title_id, 9);

            // Check if it's a PPSA/CUSA game
            if (strncmp(title_id, "PPSA", 4) != 0 && strncmp(title_id, "CUSA", 4) != 0) {
                child_pid = -1;
                continue;
            }

            if (wait_until_work_ready()) {
                patch_game(child_pid, title_id);
            }
            child_pid = -1;
        }
    }

    shutdown_power_state_monitor();
    close(kq);
    log_msg("[INFO] BackPork exiting\n");
    close_log_file();
    return 0;
}

