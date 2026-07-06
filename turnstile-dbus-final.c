/**
 * turnstile-dbus v2.6.5 - Extended version
 * Native org.turnstile.login1 interface
 * Power via D-Bus signals for dinit-dbus
 * Permission check via UID (no polkit dependency)
 * Extended config support
 * New: SetWallMessage, ScheduleShutdown, CancelScheduledShutdown, Inhibit
 *autor @valera https://github.com/yosh781 for MSD Linux based on antiX
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <errno.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <dbus/dbus.h>
#include <turnstile-highlevel.h>
#include <turnstile.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include "seatd-helper.h"

#define BUS_NAME "org.turnstile.login1"
#define LOGIND_BUS_NAME "org.freedesktop.login1"
#define BUS_IFACE "org.turnstile.login1.Manager"
#define BUS_OBJ "/org/turnstile/login1"
#define LOGIND_IFACE "org.freedesktop.login1.Manager"
#define VERSION "2.6.5"

static char *second_bus_name = NULL;

/* New structures for v2.4.0 */
typedef struct {
    time_t scheduled_time;
    char *wall_message;
    int shutdown_type; /* 0=poweroff, 1=reboot */
    int active;
} ScheduledShutdown;

typedef struct {
    char *name;
    char *description;
    int fd;
} InhibitorLock;

static DBusConnection *conn = NULL;
static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t reload_config_flag = 0;
static pthread_mutex_t monitor_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t monitor_cond = PTHREAD_COND_INITIALIZER;
static turnstile *ts_monitor = NULL;
static pthread_t monitor_thread;
static int enable_syslog = 1;

/* Configuration variables */
static int power_management = 1;
static char *suspend_method = NULL;
static char *hibernate_method = NULL;
static char *default_seat = NULL;
static int dbus_timeout = 30000;
static char *shutdown_wall_message = NULL;
static int max_inhibit_delay = 30;

/* Forward declarations */
static void check_inhibitors(void);
static int send_reply_safe(DBusMessage *reply);
static int send_error_safe(DBusMessage *error);
static void wait_for_inhibitors(void);

/* Home edition flags */
static int inhibit_mode = 0;           /* 0=normal, 1=delayed, 2=ignore */
static int inhibit_timeout = 30;
static int idle_session_timeout = 0;
static int kill_user_processes = 0;
static char *handle_lid_switch = NULL; /* suspend/hibernate/lock/ignore/poweroff */
static char *handle_power_key = NULL;  /* poweroff/reboot/suspend/hibernate/ignore */
static char *handle_suspend_key = NULL;

/* Home edition flags */
static int enable_scheduled = 1;

/* Runtime state */
static ScheduledShutdown *sched_shutdown = NULL;
static int inhibitors_count = 0;
static InhibitorLock *inhibitors = NULL;

#define LOG_INFO_MSG(fmt, ...) do { if (enable_syslog) syslog(LOG_INFO, fmt, ##__VA_ARGS__); } while(0)
#define LOG_ERROR_MSG(fmt, ...) do { if (enable_syslog) syslog(LOG_ERR, fmt, ##__VA_ARGS__); } while(0)

static void read_config(void);
static void signal_handler(int sig) {
    if (sig == SIGHUP) {
        reload_config_flag = 1;  /* Только выставляем флаг */
        return;
    }
    LOG_INFO_MSG("Signal %d received, shutting down", sig);

    pthread_mutex_lock(&monitor_mutex);
    running = 0;
    pthread_cond_signal(&monitor_cond);
    pthread_mutex_unlock(&monitor_mutex);
}

static void read_config(void) {
    FILE *f = fopen("/etc/turnstile/turnstile-dbus.conf", "r");
    if (!f) {
        /* Set defaults even if no config file */
        if (!suspend_method) suspend_method = strdup("auto");
        if (!hibernate_method) hibernate_method = strdup("auto");
        if (!default_seat) default_seat = strdup("seat0");
        if (!handle_lid_switch) handle_lid_switch = strdup("suspend");
        if (!handle_power_key) handle_power_key = strdup("poweroff");
        if (!handle_suspend_key) handle_suspend_key = strdup("suspend");
        if (!shutdown_wall_message) shutdown_wall_message = strdup("System is going down for maintenance");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '[') continue;

        char key[128], value[128];
        /* Manual parse: key = value # comment */
        char *eq = strchr(p, '=');
        if (!eq) continue;

        /* Parse key */
        char *kstart = p;
        char *kend = eq - 1;
        while (kend >= kstart && (*kend == ' ' || *kend == '\t')) kend--;
        size_t klen = kend - kstart + 1;
        if (klen >= sizeof(key)) klen = sizeof(key) - 1;
        memcpy(key, kstart, klen);
        key[klen] = '\0';

        /* Parse value */
        char *vstart = eq + 1;
        while (*vstart == ' ' || *vstart == '\t') vstart++;
        char *vend = vstart + strlen(vstart) - 1;
        while (vend >= vstart && (*vend == ' ' || *vend == '\t' || *vend == '\n')) vend--;
        char *comment = strchr(vstart, '#');
        if (comment && comment <= vend) vend = comment - 1;
        while (vend >= vstart && (*vend == ' ' || *vend == '\t')) vend--;
        size_t vlen = vend - vstart + 1;
        if (vlen >= sizeof(value)) vlen = sizeof(value) - 1;
        memcpy(value, vstart, vlen);
        value[vlen] = '\0';

        if (key[0] == '\0' || value[0] == '\0') continue;

        /* Process configuration */
        if (strcmp(key, "ENABLE_SYSLOG") == 0)
            enable_syslog = (strcmp(value, "1") == 0);
        else if (strcmp(key, "power_management") == 0)
            power_management = (strcmp(value, "true") == 0);
        else if (strcmp(key, "suspend_method") == 0) {
            if (suspend_method) free(suspend_method);
            suspend_method = strdup(value);
        }
        else if (strcmp(key, "hibernate_method") == 0) {
            if (hibernate_method) free(hibernate_method);
            hibernate_method = strdup(value);
        }
        else if (strcmp(key, "default_seat") == 0) {
            if (default_seat) free(default_seat);
            default_seat = strdup(value);
        }
        else if (strcmp(key, "dbus_timeout") == 0)
            dbus_timeout = atoi(value);
        else if (strcmp(key, "shutdown_wall_message") == 0) {
            if (shutdown_wall_message) free(shutdown_wall_message);
            shutdown_wall_message = strdup(value);
        }
        else if (strcmp(key, "inhibit_mode") == 0) {
            if (strcmp(value, "ignore") == 0) inhibit_mode = 2;
            else if (strcmp(value, "delayed") == 0) inhibit_mode = 1;
            else inhibit_mode = 0;
        }
        else if (strcmp(key, "inhibit_timeout") == 0)
            inhibit_timeout = atoi(value);
        else if (strcmp(key, "idle_session_timeout") == 0)
            idle_session_timeout = atoi(value);
        else if (strcmp(key, "kill_user_processes_on_logout") == 0)
            kill_user_processes = (strcmp(value, "true") == 0);
        else if (strcmp(key, "handle_lid_switch") == 0) {
            if (handle_lid_switch) free(handle_lid_switch);
            handle_lid_switch = strdup(value);
        }
        else if (strcmp(key, "handle_power_key") == 0) {
            if (handle_power_key) free(handle_power_key);
            handle_power_key = strdup(value);
        }
        else if (strcmp(key, "handle_suspend_key") == 0) {
            if (handle_suspend_key) free(handle_suspend_key);
            handle_suspend_key = strdup(value);
        }
        else if (strcmp(key, "max_inhibit_delay") == 0)
            max_inhibit_delay = atoi(value);
        else if (strcmp(key, "second_bus_name") == 0) {
            if (second_bus_name) free(second_bus_name);
            second_bus_name = strdup(value);
        }
        else if (strcmp(key, "enable_scheduled_shutdown") == 0)
            enable_scheduled = (strcmp(value, "true") == 0);
    }

    fclose(f);  /* Close file AFTER the loop */

    /* Set defaults for unset options - AFTER the loop */
    if (!suspend_method) suspend_method = strdup("auto");
    if (!hibernate_method) hibernate_method = strdup("auto");
    if (!default_seat) default_seat = strdup("seat0");
    if (!handle_lid_switch) handle_lid_switch = strdup("suspend");
    if (!handle_power_key) handle_power_key = strdup("poweroff");
    if (!handle_suspend_key) handle_suspend_key = strdup("suspend");
    if (!shutdown_wall_message) shutdown_wall_message = strdup("System is going down for maintenance");
}

/* Direct system operations */
static void emit_prepare_for_shutdown(int start);
static void emit_prepare_for_sleep(int start);
static void wait_for_inhibitors(void) {
    if (inhibitors_count == 0) return;

    LOG_INFO_MSG("Waiting for %d inhibitor(s) to release...", inhibitors_count);
    time_t start = time(NULL);

    while (inhibitors_count > 0) {
        check_inhibitors();

        if (time(NULL) - start > max_inhibit_delay) {
            LOG_INFO_MSG("Inhibit timeout reached, forcing shutdown");
            break;
        }

        usleep(200000);  /* 200ms */
        dbus_connection_read_write_dispatch(conn, 0);
    }
}

static void do_power_off(void) {
    LOG_INFO_MSG("Power off: stopping sessions");

    /* Check for inhibitors in delayed mode */
    if (inhibit_mode == 1 && inhibitors_count > 0) {
        wait_for_inhibitors();
    }

    if (shutdown_wall_message) {
        pid_t pid = fork();
        if (pid == 0) {
            execl("/usr/bin/wall", "wall", shutdown_wall_message, NULL);
            _exit(1);
        } else if (pid > 0) {
            waitpid(pid, NULL, 0);
        }
    }
    sync();

    pid_t pid = fork();
    if (pid == 0) {
        execl("/usr/bin/dbus-send", "dbus-send", "--system",
              "--dest=org.chimera.dinit", "--print-reply",
              "--type=method_call", "/org/chimera/dinit",
              "org.chimera.dinit.Manager.Shutdown",
              "string:poweroff", NULL);
        /* Fallback to direct shutdown if dbus-send fails */
        sync();
        reboot(RB_POWER_OFF);
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            LOG_ERROR_MSG("dbus-send failed, using direct reboot");
            sync();
            reboot(RB_POWER_OFF);
        }
    }
}

static void do_reboot(void) {
    LOG_INFO_MSG("Reboot: stopping sessions");
    if (shutdown_wall_message) {
        pid_t pid = fork();
        if (pid == 0) {
            execl("/usr/bin/wall", "wall", shutdown_wall_message, NULL);
            _exit(1);
        } else if (pid > 0) {
            waitpid(pid, NULL, 0);
        }
    }
    sync();

    pid_t pid = fork();
    if (pid == 0) {
        execl("/usr/bin/dbus-send", "dbus-send", "--system",
              "--dest=org.chimera.dinit", "--print-reply",
              "--type=method_call", "/org/chimera/dinit",
              "org.chimera.dinit.Manager.Shutdown",
              "string:reboot", NULL);
        /* Fallback to direct reboot if dbus-send fails */
        sync();
        reboot(RB_AUTOBOOT);
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            LOG_ERROR_MSG("dbus-send failed, using direct reboot");
            sync();
            reboot(RB_AUTOBOOT);
        }
    }
}

static void do_suspend(void) {
    LOG_INFO_MSG("Suspend: starting");
    if (suspend_method && strcmp(suspend_method, "external") == 0) {
        LOG_INFO_MSG("Suspend: using external command");
        pid_t pid = fork();
        if (pid == 0) {
            execl("/usr/sbin/pm-suspend", "pm-suspend", NULL);
            /* Fallback */
            int fd = open("/sys/power/state", O_WRONLY);
            if (fd >= 0) {
                write(fd, "mem", 3);
                close(fd);
            }
            _exit(1);
        } else if (pid > 0) {
            waitpid(pid, NULL, 0);
        }
    } else {
        LOG_INFO_MSG("Suspend: writing mem to /sys/power/state");
        int fd = open("/sys/power/state", O_WRONLY);
        if (fd >= 0) {
            write(fd, "mem", 3);
            close(fd);
        } else {
            LOG_ERROR_MSG("Suspend: failed to open /sys/power/state");
        }
    }
}

static void do_hibernate(void) {
    LOG_INFO_MSG("Hibernate: starting");
    if (hibernate_method && strcmp(hibernate_method, "external") == 0) {
        LOG_INFO_MSG("Hibernate: using external command");
        pid_t pid = fork();
        if (pid == 0) {
            execl("/usr/sbin/pm-hibernate", "pm-hibernate", NULL);
            /* Fallback */
            sync();
            int fd = open("/sys/power/state", O_WRONLY);
            if (fd >= 0) {
                write(fd, "disk", 4);
                close(fd);
            }
            _exit(1);
        } else if (pid > 0) {
            waitpid(pid, NULL, 0);
        }
    } else {
        LOG_INFO_MSG("Hibernate: writing disk to /sys/power/state");
        sync();
        int fd = open("/sys/power/state", O_WRONLY);
        if (fd >= 0) {
            write(fd, "disk", 4);
            close(fd);
        } else {
            LOG_ERROR_MSG("Hibernate: failed to open /sys/power/state");
        }
    }
}

static int check_suspend_support(void) {
    /* Check if suspend-to-ram is available */
    char buf[64];
    int fd = open("/sys/power/state", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    return (strstr(buf, "mem") != NULL);
}

static int check_hibernate_support(void) {
    /* Check if hibernate-to-disk is available */
    char buf[64];
    int fd = open("/sys/power/state", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    return (strstr(buf, "disk") != NULL);
}

/* Signal emission */
static void emit_signal(const char *name, const char *arg1, const char *arg2) {
    DBusMessage *signal = dbus_message_new_signal(BUS_OBJ, BUS_IFACE, name);
    if (signal) {
        dbus_message_append_args(signal, DBUS_TYPE_STRING, &arg1,
                                 DBUS_TYPE_OBJECT_PATH, &arg2, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, signal, NULL);
        dbus_message_unref(signal);
    }
}

static void emit_prepare_for_shutdown(int start) {
    dbus_bool_t val = start;
    DBusMessage *signal = dbus_message_new_signal(BUS_OBJ, BUS_IFACE, "PrepareForShutdown");
    if (signal) {
        dbus_message_append_args(signal, DBUS_TYPE_BOOLEAN, &val, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, signal, NULL);
        dbus_message_unref(signal);
    }
}

static void emit_prepare_for_sleep(int start) {
    dbus_bool_t val = start;
    DBusMessage *signal = dbus_message_new_signal(BUS_OBJ, BUS_IFACE, "PrepareForSleep");
    if (signal) {
        dbus_message_append_args(signal, DBUS_TYPE_BOOLEAN, &val, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, signal, NULL);
        dbus_message_unref(signal);
    }
}

/* Permission check via D-Bus UID */
static int check_permission(DBusMessage *msg) {
    const char *sender = dbus_message_get_sender(msg);
    if (!sender) {
        LOG_INFO_MSG("check_permission: no sender");
        return 0;
    }

    DBusError err;
    dbus_error_init(&err);

    unsigned long uid = dbus_bus_get_unix_user(conn, sender, &err);

    if (dbus_error_is_set(&err)) {
        LOG_ERROR_MSG("check_permission: failed to get UID for %s: %s", sender, err.message);
        dbus_error_free(&err);
        return 0;
    }

    /* Root always allowed */
    if (uid == 0) {
        LOG_INFO_MSG("check_permission: root allowed");
        return 1;
    }

    /* Check if user has any session (like logind) */
    turnstile_session *sessions = NULL;
    size_t count = 0;
    if (turnstile_get_user_sessions(uid, &sessions, &count) == 0 && count > 0) {
        LOG_INFO_MSG("check_permission: uid=%lu allowed (has %zu session(s))", uid, count);
        turnstile_free_sessions(sessions, count);
        return 1;
    }

    LOG_INFO_MSG("check_permission: uid=%lu denied (no sessions)", uid);
    return 0;
}

/* New functions for v2.4.0 */
static void handle_set_wall_message(DBusMessage *msg) {
    const char *message;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &message, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected message string");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    if (shutdown_wall_message) free(shutdown_wall_message);
    shutdown_wall_message = strdup(message);
    
    LOG_INFO_MSG("SetWallMessage: %s", message);
    
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static void handle_schedule_shutdown(DBusMessage *msg) {
    const char *type;
    dbus_int64_t usec;
    if (!dbus_message_get_args(msg, NULL,
        DBUS_TYPE_STRING, &type,
        DBUS_TYPE_INT64, &usec,
        DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected type and usec");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    if (sched_shutdown) {
        if (sched_shutdown->wall_message) free(sched_shutdown->wall_message);
        free(sched_shutdown);
    }
    sched_shutdown = calloc(1, sizeof(ScheduledShutdown));
    if (sched_shutdown) {
        sched_shutdown->scheduled_time = time(NULL) + (usec / 1000000);
        sched_shutdown->wall_message = shutdown_wall_message ? strdup(shutdown_wall_message) : NULL;
        sched_shutdown->shutdown_type = (strcmp(type, "reboot") == 0) ? 1 : 0;
        sched_shutdown->active = 1;
        
        LOG_INFO_MSG("Scheduled %s in %ld seconds", type, usec / 1000000);
        
        DBusMessage *reply = dbus_message_new_method_return(msg);
        if (reply) {
            dbus_connection_send(conn, reply, NULL);
            dbus_message_unref(reply);
        }
    }
}

static void handle_cancel_scheduled_shutdown(DBusMessage *msg) {
    if (sched_shutdown) {
        free(sched_shutdown);
        sched_shutdown = NULL;
    }
    
    LOG_INFO_MSG("Cancelled scheduled shutdown");
    
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static void handle_inhibit(DBusMessage *msg) {
    const char *what, *who, *why, *mode;
    if (!dbus_message_get_args(msg, NULL,
        DBUS_TYPE_STRING, &what,
        DBUS_TYPE_STRING, &who,
        DBUS_TYPE_STRING, &why,
        DBUS_TYPE_STRING, &mode,
        DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected what,who,why,mode");
    send_error_safe(err);
    return;
        }

        /* Permission check first */
        if (!check_permission(msg)) {
            DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_ACCESS_DENIED, "Permission denied");
            send_error_safe(err);
            return;
        }

        /* Home edition: check inhibit mode - ignore all inhibitors if mode=2 */
        if (inhibit_mode == 2) {
            LOG_INFO_MSG("Inhibit IGNORED (inhibit_mode=ignore): what=%s who=%s", what, who);

            /* Return a valid fd even in ignore mode - use /dev/null */
            int devnull_fd = open("/dev/null", O_RDONLY);
            if (devnull_fd >= 0) {
                DBusMessage *reply = dbus_message_new_method_return(msg);
                if (reply) {
                    dbus_message_append_args(reply, DBUS_TYPE_UNIX_FD, &devnull_fd, DBUS_TYPE_INVALID);
                    send_reply_safe(reply);
                }
                close(devnull_fd);
            } else {
                DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Failed to create inhibitor fd");
                send_error_safe(err);
            }
            return;
        }

        /* Create pipe for monitoring fd close */
        int pipe_fds[2];
        if (pipe(pipe_fds) < 0) {
            DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Failed to create pipe");
            send_error_safe(err);
            return;
        }

        /* Set non-blocking for the read end */
        int flags = fcntl(pipe_fds[0], F_GETFL, 0);
        if (flags != -1) {
            fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK);
        }

        void *tmp = realloc(inhibitors, (inhibitors_count + 1) * sizeof(InhibitorLock));
        if (!tmp) {
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_NO_MEMORY, "Failed to allocate inhibitor");
            send_error_safe(err);
            return;
        }
        inhibitors = tmp;

        inhibitors[inhibitors_count].name = strdup(who);
        inhibitors[inhibitors_count].description = strdup(why);
        inhibitors[inhibitors_count].fd = pipe_fds[0];  /* Read end for monitoring */
        inhibitors_count++;

        LOG_INFO_MSG("Inhibit: who=%s why=%s what=%s mode=%s (inhibit_mode=%d)",
                     who, why, what, mode, inhibit_mode);

        DBusMessage *reply = dbus_message_new_method_return(msg);
        if (reply) {
            dbus_message_append_args(reply,
                                     DBUS_TYPE_UNIX_FD, &pipe_fds[1],  /* Give write end to client */
                                     DBUS_TYPE_INVALID);
            send_reply_safe(reply);
            /* Don't close pipe_fds[1] here - D-Bus will handle sending it to client */
            /* The client will close their end when done */
        } else {
            close(pipe_fds[1]);  /* Close if we couldn't create reply */
        }
}

/* Turnstile event callback */
static void turnstile_event_cb(turnstile *ts, int event, unsigned long id, void *data) {
    (void)ts;
    (void)data;
    char sid[32], path[64];
    snprintf(sid, sizeof(sid), "%lu", id);
    snprintf(path, sizeof(path), "/org/turnstile/login1/session/%lu", id);
    
    if (event == TURNSTILE_EVENT_SESSION_NEW) {
        LOG_INFO_MSG("New session: %lu", id);
        emit_signal("SessionNew", sid, path);
    } else if (event == TURNSTILE_EVENT_SESSION_REMOVED) {
        LOG_INFO_MSG("Session removed: %lu", id);
        emit_signal("SessionRemoved", sid, path);
    }
}

static void *monitor_thread_func(void *arg) {
    (void)arg;

    while (1) {
        pthread_mutex_lock(&monitor_mutex);

        /* Check exit condition before waiting */
        if (!running || !ts_monitor) {
            pthread_mutex_unlock(&monitor_mutex);
            break;
        }

        /* timeout 50ms */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 50000000;  /* 50ms */
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000;
        }

        pthread_cond_timedwait(&monitor_cond, &monitor_mutex, &ts);

        /* Re-check after wakeup */
        int should_run = running && ts_monitor;
        pthread_mutex_unlock(&monitor_mutex);

        if (!should_run) {
            break;
        }

        if (ts_monitor) {
            turnstile_dispatch(ts_monitor, 100);
        }
    }

    LOG_INFO_MSG("Monitor thread exiting");
    return NULL;
}

static void handle_get_runtime_dir(DBusMessage *msg) {
    dbus_uint32_t uid;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT32, &uid, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected UID");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    char *runtime_dir = NULL;
    if (turnstile_get_runtime_dir(uid, &runtime_dir) < 0 || !runtime_dir) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Failed to get runtime dir");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_message_append_args(reply, DBUS_TYPE_STRING, &runtime_dir, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
    
    free(runtime_dir);
    LOG_INFO_MSG("GetRuntimeDir: uid=%u", uid);
}

static void handle_setup_runtime_dir(DBusMessage *msg) {
    dbus_uint32_t uid;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT32, &uid, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected UID");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    if (turnstile_setup_runtime_dir(uid) < 0) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Failed to setup runtime dir");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
    LOG_INFO_MSG("SetupRuntimeDir: uid=%u", uid);
}

static void handle_cleanup_runtime_dir(DBusMessage *msg) {
    dbus_uint32_t uid;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT32, &uid, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected UID");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    if (turnstile_cleanup_runtime_dir(uid) < 0) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Failed to cleanup runtime dir");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
    LOG_INFO_MSG("CleanupRuntimeDir: uid=%u", uid);
}

static void handle_stop_all_sessions(DBusMessage *msg) {
    LOG_INFO_MSG("StopAllSessions called");
    
    if (turnstile_stop_all_sessions() < 0) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Failed to stop all sessions");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static void handle_terminate_user(DBusMessage *msg) {
    dbus_uint32_t uid;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT32, &uid, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected UID");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    LOG_INFO_MSG("TerminateUser: uid=%u", uid);
    
    turnstile_session *sessions = NULL;
    size_t count = 0;
    
    if (turnstile_get_user_sessions(uid, &sessions, &count) == 0) {
        for (size_t i = 0; i < count; i++) {
            turnstile_stop_session(sessions[i].id);
        }
        turnstile_free_sessions(sessions, count);
    }
    
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static void handle_list_sessions(DBusMessage *msg) {
    turnstile_session *sessions = NULL;
    size_t count = 0;
    
    if (turnstile_get_sessions(&sessions, &count) < 0) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Failed to get sessions");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply) {
        turnstile_free_sessions(sessions, count);
        return;
    }
    
    DBusMessageIter iter, array_iter;
    dbus_message_iter_init_append(reply, &iter);
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(susso)", &array_iter);
    
    for (size_t i = 0; i < count; i++) {
        DBusMessageIter struct_iter;
        dbus_message_iter_open_container(&array_iter, DBUS_TYPE_STRUCT, NULL, &struct_iter);
        
        char sid[32], path[64];
        snprintf(sid, sizeof(sid), "%lu", sessions[i].id);
        snprintf(path, sizeof(path), "/org/turnstile/login1/session/%lu", sessions[i].id);
        
        const char *session_id = sid;
        dbus_uint32_t uid = sessions[i].uid;
        const char *username = sessions[i].username ? sessions[i].username : "";
        const char *seat = sessions[i].seat ? sessions[i].seat : "seat0";
        const char *objpath = path;
        
        dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &session_id);
        dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_UINT32, &uid);
        dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &username);
        dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &seat);
        dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_OBJECT_PATH, &objpath);
        
        dbus_message_iter_close_container(&array_iter, &struct_iter);
    }
    
    dbus_message_iter_close_container(&iter, &array_iter);
    turnstile_free_sessions(sessions, count);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);
}

static void handle_list_users(DBusMessage *msg) {
    turnstile_session *sessions = NULL;
    size_t session_count = 0;
    
    if (turnstile_get_sessions(&sessions, &session_count) < 0) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Failed to get sessions");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    typedef struct { uid_t uid; const char *username; } user_info_t;
    user_info_t users[256];
    int user_count = 0;
    
    for (size_t i = 0; i < session_count; i++) {
        int found = 0;
        for (int j = 0; j < user_count; j++) {
            if (users[j].uid == sessions[i].uid) {
                found = 1;
                break;
            }
        }
        if (!found && user_count < 256) {
            users[user_count].uid = sessions[i].uid;
            users[user_count].username = sessions[i].username;
            user_count++;
        }
    }
    
    DBusMessage *reply = dbus_message_new_method_return(msg);
    DBusMessageIter iter, array_iter;
    dbus_message_iter_init_append(reply, &iter);
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(uso)", &array_iter);
    
    for (int i = 0; i < user_count; i++) {
        DBusMessageIter struct_iter;
        dbus_message_iter_open_container(&array_iter, DBUS_TYPE_STRUCT, NULL, &struct_iter);
        
        char path[64];
        snprintf(path, sizeof(path), "/org/turnstile/login1/user/%u", users[i].uid);
        
        dbus_uint32_t uid = users[i].uid;
        const char *username = users[i].username ? users[i].username : "unknown";
        const char *objpath = path;
        
        dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_UINT32, &uid);
        dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &username);
        dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_OBJECT_PATH, &objpath);
        
        dbus_message_iter_close_container(&array_iter, &struct_iter);
    }
    
    dbus_message_iter_close_container(&iter, &array_iter);
    turnstile_free_sessions(sessions, session_count);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);
}
/* CreateSession for KDE compatibility */
static void handle_create_session(DBusMessage *msg) {
    dbus_uint32_t uid, pid = 0;
    const char *service = "", *type = "unspecified", *class_type = "user";
    const char *desktop = "", *seat_id = "seat0";
    dbus_uint32_t vtnr = 0;
    const char *tty = "", *display = "";
    dbus_bool_t remote = FALSE;
    const char *remote_user = "", *remote_host = "";

    if (!dbus_message_get_args(msg, NULL,
        DBUS_TYPE_UINT32, &uid, DBUS_TYPE_UINT32, &pid,
        DBUS_TYPE_STRING, &service, DBUS_TYPE_STRING, &type,
        DBUS_TYPE_STRING, &class_type, DBUS_TYPE_STRING, &desktop,
        DBUS_TYPE_STRING, &seat_id, DBUS_TYPE_UINT32, &vtnr,
        DBUS_TYPE_STRING, &tty, DBUS_TYPE_STRING, &display,
        DBUS_TYPE_BOOLEAN, &remote, DBUS_TYPE_STRING, &remote_user,
        DBUS_TYPE_STRING, &remote_host, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected uid,pid,...");
    if (err) {
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
    }
    return;
        }

        /* Get existing sessions */
        unsigned long session_id = 0;
        turnstile_session *sessions = NULL;
        size_t count = 0;

        if (turnstile_get_sessions(&sessions, &count) == 0 && count > 0) {
            for (size_t i = 0; i < count; i++) {
                if (sessions[i].uid == uid) {
                    session_id = sessions[i].id;
                    break;
                }
            }
            turnstile_free_sessions(sessions, count);
        }

        if (session_id == 0) {
            turnstile_session session;
            memset(&session, 0, sizeof(session));
            session.uid = uid;

            if (turnstile_create_session(&session, &session_id) < 0 || session_id == 0) {
                DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Failed to create session");
                if (err) {
                    dbus_connection_send(conn, err, NULL);
                    dbus_message_unref(err);
                }
                return;
            }
        }

        /* Get DRM fd from seatd only after successful session creation */
        int drm_fd = seatd_helper_get_drm_fd(session_id);

        char session_path[64], id_buf[32];
        snprintf(session_path, sizeof(session_path), "/org/turnstile/login1/session/%lu", session_id);
        snprintf(id_buf, sizeof(id_buf), "%lu", session_id);
        const char *objpath = session_path, *session_id_str = id_buf;

        DBusMessage *reply = dbus_message_new_method_return(msg);
        if (reply) {
            dbus_message_append_args(reply,
                                     DBUS_TYPE_STRING, &session_id_str,
                                     DBUS_TYPE_OBJECT_PATH, &objpath,
                                     DBUS_TYPE_STRING, &objpath,
                                     DBUS_TYPE_UNIX_FD, &drm_fd,
                                     DBUS_TYPE_STRING, &seat_id,
                                     DBUS_TYPE_UINT32, &vtnr,
                                     DBUS_TYPE_BOOLEAN, &remote,
                                     DBUS_TYPE_STRING, &remote_user,
                                     DBUS_TYPE_STRING, &remote_host,
                                     DBUS_TYPE_INVALID);
            dbus_connection_send(conn, reply, NULL);
            dbus_message_unref(reply);
        }

        /* Close our copy of the fd after sending to client */
        if (drm_fd >= 0) {
            close(drm_fd);
        }

        LOG_INFO_MSG("CreateSession: uid=%u session=%lu drm_fd=%d", uid, session_id, drm_fd);
}

static void handle_release_session(DBusMessage *msg) {
    const char *session_id_str;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &session_id_str, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected session ID");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    unsigned long session_id = strtoul(session_id_str, NULL, 10);
    if (turnstile_release_session(session_id) < 0) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Failed to release session");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) { dbus_connection_send(conn, reply, NULL); dbus_message_unref(reply); }
    LOG_INFO_MSG("ReleaseSession: session=%lu", session_id);
}

/* ActivateSession for session switching */
static void handle_activate_session(DBusMessage *msg) {
    const char *session_id_str;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &session_id_str, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected session ID");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    unsigned long session_id = strtoul(session_id_str, NULL, 10);
    if (turnstile_activate_session(session_id) < 0) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Failed to activate session");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) { dbus_connection_send(conn, reply, NULL); dbus_message_unref(reply); }
    LOG_INFO_MSG("ActivateSession: session=%lu", session_id);
}

/* GetSessionByPID for KDE compatibility */
static void handle_get_session_by_pid(DBusMessage *msg) {
    dbus_uint32_t pid;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT32, &pid, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected PID");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    turnstile_session session;
    memset(&session, 0, sizeof(session));
    if (turnstile_get_session_by_pid(pid, &session) < 0 || session.id == 0) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Session not found for PID");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    char path[64];
    snprintf(path, sizeof(path), "/org/turnstile/login1/session/%lu", session.id);
    const char *objpath = path;
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &objpath, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
    LOG_INFO_MSG("GetSessionByPID: pid=%u session=%lu", pid, session.id);
}

/* SetIdleHint for KDE screen locker */
static void handle_set_session_idle(DBusMessage *msg) {
    const char *session_id_str;
    dbus_bool_t idle;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &session_id_str, DBUS_TYPE_BOOLEAN, &idle, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected session ID and idle");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    unsigned long session_id = strtoul(session_id_str, NULL, 10);
    turnstile_set_session_idle(session_id, idle);
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) { dbus_connection_send(conn, reply, NULL); dbus_message_unref(reply); }
    LOG_INFO_MSG("SetIdleHint: session=%lu idle=%d", session_id, idle);
}

/* SetSessionState for KDE */
static void handle_set_session_state(DBusMessage *msg) {
    const char *session_id_str, *state;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &session_id_str, DBUS_TYPE_STRING, &state, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected session ID and state");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    unsigned long session_id = strtoul(session_id_str, NULL, 10);
    turnstile_set_session_state(session_id, state);
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) { dbus_connection_send(conn, reply, NULL); dbus_message_unref(reply); }
    LOG_INFO_MSG("SetSessionState: session=%lu state=%s", session_id, state);
}


static void handle_get_session(DBusMessage *msg) {
    const char *session_id_str;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &session_id_str, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected session ID");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    unsigned long session_id = strtoul(session_id_str, NULL, 10);
    turnstile_session session;
    memset(&session, 0, sizeof(session));
    if (turnstile_get_session_by_id(session_id, &session) < 0 || session.id == 0) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Session not found");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    char path[64];
    snprintf(path, sizeof(path), "/org/turnstile/login1/session/%lu", session.id);
    const char *objpath = path;
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &objpath, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
    LOG_INFO_MSG("GetSession: %lu", session.id);
}

static void handle_get_user_sessions(DBusMessage *msg) {
    const char *username;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &username, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected username");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    struct passwd *pwd = getpwnam(username);
    if (!pwd) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "User not found");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    turnstile_session *sessions = NULL;
    size_t count = 0;
    if (turnstile_get_user_sessions(pwd->pw_uid, &sessions, &count) < 0) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Failed to get user sessions");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    DBusMessage *reply = dbus_message_new_method_return(msg);
    DBusMessageIter iter, array_iter;
    dbus_message_iter_init_append(reply, &iter);
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(sos)", &array_iter);
    for (size_t i = 0; i < count; i++) {
        DBusMessageIter struct_iter;
        dbus_message_iter_open_container(&array_iter, DBUS_TYPE_STRUCT, NULL, &struct_iter);
        char sid[32], path[64];
        snprintf(sid, sizeof(sid), "%lu", sessions[i].id);
        snprintf(path, sizeof(path), "/org/turnstile/login1/session/%lu", sessions[i].id);
        const char *session_id = sid;
        const char *objpath = path;
        const char *type = sessions[i].type ? sessions[i].type : "unspecified";
        dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &session_id);
        dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_OBJECT_PATH, &objpath);
        dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &type);
        dbus_message_iter_close_container(&array_iter, &struct_iter);
    }
    dbus_message_iter_close_container(&iter, &array_iter);
    turnstile_free_sessions(sessions, count);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);
}
static void handle_get_active_seat(DBusMessage *msg) {
    char *seat_name = NULL;
    
    if (turnstile_get_active_seat(&seat_name) < 0 || seat_name == NULL) {
        seat_name = strdup(default_seat ? default_seat : "seat0");
    }
    
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_message_append_args(reply, DBUS_TYPE_STRING, &seat_name, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
    
    if (seat_name) free(seat_name);
}

static void handle_get_active_vtnr(DBusMessage *msg) {
    unsigned long vtnr = 0;
    turnstile_get_active_vtnr(&vtnr);
    
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_uint32_t vtnr_val = vtnr;
        dbus_message_append_args(reply, DBUS_TYPE_UINT32, &vtnr_val, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static void handle_terminate_session(DBusMessage *msg) {
    const char *session_id_str;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &session_id_str, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected session ID");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    unsigned long session_id = strtoul(session_id_str, NULL, 10);
    
    if (turnstile_stop_session(session_id) < 0) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_FAILED, "Failed to terminate session");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static void handle_power_off(DBusMessage *msg) {
    dbus_bool_t interactive = FALSE;
    dbus_message_get_args(msg, NULL, DBUS_TYPE_BOOLEAN, &interactive, DBUS_TYPE_INVALID);
    (void)interactive;
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
    dbus_connection_flush(conn);
    emit_prepare_for_shutdown(1);
    dbus_connection_flush(conn);
    do_power_off();
}

static void handle_reboot(DBusMessage *msg) {
    dbus_bool_t interactive = FALSE;
    dbus_message_get_args(msg, NULL, DBUS_TYPE_BOOLEAN, &interactive, DBUS_TYPE_INVALID);
    (void)interactive;
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
    dbus_connection_flush(conn);
    emit_prepare_for_shutdown(1);
    dbus_connection_flush(conn);
    do_reboot();
}

static void handle_suspend(DBusMessage *msg) {
    dbus_bool_t interactive = FALSE;
    dbus_message_get_args(msg, NULL, DBUS_TYPE_BOOLEAN, &interactive, DBUS_TYPE_INVALID);
    (void)interactive;

    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }

    dbus_connection_flush(conn);
    emit_prepare_for_sleep(1);
    dbus_connection_flush(conn);
    usleep(500000);
    do_suspend();

    /* Send wake-up signal */
    emit_prepare_for_sleep(0);
    dbus_connection_flush(conn);
}

static void handle_hibernate(DBusMessage *msg) {
    dbus_bool_t interactive = FALSE;
    dbus_message_get_args(msg, NULL, DBUS_TYPE_BOOLEAN, &interactive, DBUS_TYPE_INVALID);
    (void)interactive;

    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }

    dbus_connection_flush(conn);
    emit_prepare_for_sleep(1);
    dbus_connection_flush(conn);
    usleep(500000);
    do_hibernate();

    /* Send wake-up signal */
    emit_prepare_for_sleep(0);
    dbus_connection_flush(conn);
}

static void handle_can_power_off(DBusMessage *msg) {
    const char *result = "yes";
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_message_append_args(reply, DBUS_TYPE_STRING, &result, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static void handle_can_reboot(DBusMessage *msg) {
    const char *result = "yes";
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_message_append_args(reply, DBUS_TYPE_STRING, &result, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static void handle_can_graphical(DBusMessage *msg) {
    const char *result = "yes";
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_message_append_args(reply, DBUS_TYPE_STRING, &result, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static void handle_can_suspend(DBusMessage *msg) {
    const char *result = check_suspend_support() ? "yes" : "no";
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_message_append_args(reply, DBUS_TYPE_STRING, &result, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static void handle_can_hibernate(DBusMessage *msg) {
    const char *result = check_hibernate_support() ? "yes" : "no";
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_message_append_args(reply, DBUS_TYPE_STRING, &result, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static void handle_can_hybrid_sleep(DBusMessage *msg) {
    const char *result = (check_suspend_support() && check_hibernate_support()) ? "yes" : "no";
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_message_append_args(reply, DBUS_TYPE_STRING, &result, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static void handle_can_suspend_then_hibernate(DBusMessage *msg) {
    const char *result = (check_suspend_support() && check_hibernate_support()) ? "yes" : "no";
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_message_append_args(reply, DBUS_TYPE_STRING, &result, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

/* ListSeats for KDE */
static void handle_list_seats(DBusMessage *msg) {
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply) return;
    DBusMessageIter iter, array_iter;
    dbus_message_iter_init_append(reply, &iter);
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(so)", &array_iter);
    DBusMessageIter struct_iter;
    dbus_message_iter_open_container(&array_iter, DBUS_TYPE_STRUCT, NULL, &struct_iter);
    const char *seat_name = "seat0";
    const char *seat_path = "/org/freedesktop/login1/seat/seat0";
    dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &seat_name);
    dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_OBJECT_PATH, &seat_path);
    dbus_message_iter_close_container(&array_iter, &struct_iter);
    dbus_message_iter_close_container(&iter, &array_iter);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);
    LOG_INFO_MSG("ListSeats called");
}

/* TakeControl stub */
static void handle_take_control(DBusMessage *msg) {
    LOG_INFO_MSG("TakeControl called");
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) { dbus_connection_send(conn, reply, NULL); dbus_message_unref(reply); }
}

/* Properties interface */
static void handle_properties_get(DBusMessage *msg) {
    const char *iface, *prop;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &iface, DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected interface and property");
        if (err) {
            dbus_connection_send(conn, err, NULL);
            dbus_message_unref(err);
        }
        return;
    }

    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply) {
        LOG_ERROR_MSG("Failed to create reply message");
        return;
    }

    DBusMessageIter iter;
    dbus_message_iter_init_append(reply, &iter);

    if (strcmp(iface, BUS_IFACE) == 0 || strcmp(iface, LOGIND_IFACE) == 0) {
        if (strcmp(prop, "ActiveVTNr") == 0) {
            /* ActiveVTNr  uint32 */
            DBusMessageIter variant;
            dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, "u", &variant);
            unsigned long vtnr = 0;
            turnstile_get_active_vtnr(&vtnr);
            dbus_uint32_t v = vtnr;
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_UINT32, &v);
            dbus_message_iter_close_container(&iter, &variant);
        } else {
            DBusMessageIter variant;
            dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, "s", &variant);

            if (strcmp(prop, "ActiveSeat") == 0) {
                char *seat = NULL;
                turnstile_get_active_seat(&seat);
                const char *val = seat ? seat : (default_seat ? default_seat : "seat0");
                dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
                if (seat) free(seat);
            } else if (strcmp(prop, "CanPowerOff") == 0) {
                const char *val = "yes";
                dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
            } else if (strcmp(prop, "CanReboot") == 0) {
                const char *val = "yes";
                dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
            } else if (strcmp(prop, "CanSuspend") == 0) {
                const char *val = check_suspend_support() ? "yes" : "no";
                dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
            } else if (strcmp(prop, "CanHibernate") == 0) {
                const char *val = check_hibernate_support() ? "yes" : "no";
                dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
            } else if (strcmp(prop, "RebootToFirmwareSetup") == 0) {
                const char *val = "no";
                dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
            } else if (strcmp(prop, "RebootToBootLoaderMenu") == 0) {
                const char *val = "no";
                dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
            } else if (strcmp(prop, "RebootToBootLoaderEntry") == 0) {
                const char *val = "no";
                dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
            } else {
                const char *empty = "";
                dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &empty);
            }

            dbus_message_iter_close_container(&iter, &variant);
        }
    } else if (strcmp(iface, "org.freedesktop.login1.Seat") == 0 ||
        strcmp(iface, "org.turnstile.login1.Seat") == 0) {
        DBusMessageIter variant;
    dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, "s", &variant);

    if (strcmp(prop, "ActiveSession") == 0) {
        const char *val = "/org/freedesktop/login1/session/1";
        dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
    } else if (strcmp(prop, "CanGraphical") == 0) {
        const char *val = "yes";
        dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
    } else if (strcmp(prop, "Id") == 0) {
        const char *val = "seat0";
        dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
    } else {
        const char *empty = "";
        dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &empty);
    }

    dbus_message_iter_close_container(&iter, &variant);
        } else if (strcmp(iface, "org.freedesktop.login1.Session") == 0 ||
            strcmp(iface, "org.turnstile.login1.Session") == 0) {
            DBusMessageIter variant;
        dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, "s", &variant);

        if (strcmp(prop, "Active") == 0) {
            const char *val = "true";
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
        } else if (strcmp(prop, "State") == 0) {
            const char *val = "active";
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
        } else if (strcmp(prop, "Remote") == 0) {
            const char *val = "false";
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
        } else if (strcmp(prop, "Type") == 0) {
            const char *val = "x11";
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
        } else if (strcmp(prop, "IdleHint") == 0) {
            const char *val = "false";
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
        } else if (strcmp(prop, "Class") == 0) {
            const char *val = "user";
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
        } else {
            const char *empty = "";
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &empty);
        }

        dbus_message_iter_close_container(&iter, &variant);
            } else {
                DBusMessageIter variant;
                dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, "s", &variant);
                const char *empty = "";
                dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &empty);
                dbus_message_iter_close_container(&iter, &variant);
            }

            dbus_connection_send(conn, reply, NULL);
            dbus_message_unref(reply);
}

static void handle_properties_get_all(DBusMessage *msg) {
    const char *iface;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &iface, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected interface");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply) return;
    DBusMessageIter iter, array_iter;
    dbus_message_iter_init_append(reply, &iter);
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &array_iter);
    
    if (strcmp(iface, BUS_IFACE) == 0 || strcmp(iface, LOGIND_IFACE) == 0) {
        /* Manager properties */
        DBusMessageIter entry, variant;
        const char *prop = "ActiveSeat";
        dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
        dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant);
        char *seat = NULL;
        turnstile_get_active_seat(&seat);
        const char *val = seat ? seat : (default_seat ? default_seat : "seat0");
        dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
        dbus_message_iter_close_container(&entry, &variant);
        dbus_message_iter_close_container(&array_iter, &entry);
        if (seat) free(seat);
        
        prop = "ActiveVTNr";
        dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
        dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "u", &variant);
        unsigned long vtnr = 0;
        turnstile_get_active_vtnr(&vtnr);
        dbus_uint32_t v = vtnr;
        dbus_message_iter_append_basic(&variant, DBUS_TYPE_UINT32, &v);
        dbus_message_iter_close_container(&entry, &variant);
        dbus_message_iter_close_container(&array_iter, &entry);
    } else if (strcmp(iface, "org.freedesktop.login1.Seat") == 0 ||
               strcmp(iface, "org.turnstile.login1.Seat") == 0) {
        /* Seat properties */
        DBusMessageIter entry, variant;
        const char *prop = "ActiveSession";
        dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
        dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant);
        const char *val = "/org/freedesktop/login1/session/1";
        dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
        dbus_message_iter_close_container(&entry, &variant);
        dbus_message_iter_close_container(&array_iter, &entry);
        
        prop = "CanGraphical";
        dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
        dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant);
        val = "yes";
        dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
        dbus_message_iter_close_container(&entry, &variant);
        dbus_message_iter_close_container(&array_iter, &entry);
        
        prop = "Id";
        dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
        dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant);
        val = "seat0";
        dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
        dbus_message_iter_close_container(&entry, &variant);
        dbus_message_iter_close_container(&array_iter, &entry);
} else if (strcmp(iface, "org.freedesktop.login1.Session") == 0 ||
           strcmp(iface, "org.turnstile.login1.Session") == 0) {
    /* Session properties - полный набор для polkit */
    DBusMessageIter entry, variant;
    
    /* Active */
    const char *prop = "Active";
    dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "b", &variant);
    dbus_bool_t bval = TRUE;
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, &bval);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(&array_iter, &entry);
    
    /* State */
    prop = "State";
    dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant);
    const char *val = "active";
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(&array_iter, &entry);
    
    /* IdleHint */
    prop = "IdleHint";
    dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "b", &variant);
    bval = FALSE;
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, &bval);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(&array_iter, &entry);
    
    /* Remote - ВАЖНО для polkit! */
    prop = "Remote";
    dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "b", &variant);
    bval = FALSE;
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, &bval);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(&array_iter, &entry);
    
    /* Type */
    prop = "Type";
    dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant);
    val = "x11";
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(&array_iter, &entry);
    
    /* Class */
    prop = "Class";
    dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant);
    val = "user";
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(&array_iter, &entry);
    
    /* Desktop */
    prop = "Desktop";
    dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant);
    val = "xfce";
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &val);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(&array_iter, &entry);
    
    /* Seat  */
    prop = "Seat";
    dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "(so)", &variant);
    DBusMessageIter seat_struct;
    dbus_message_iter_open_container(&variant, DBUS_TYPE_STRUCT, NULL, &seat_struct);
    const char *seat_id = "seat0";
    const char *seat_path = "/org/freedesktop/login1/seat/seat0";
    dbus_message_iter_append_basic(&seat_struct, DBUS_TYPE_STRING, &seat_id);
    dbus_message_iter_append_basic(&seat_struct, DBUS_TYPE_OBJECT_PATH, &seat_path);
    dbus_message_iter_close_container(&variant, &seat_struct);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(&array_iter, &entry);
    
    /* User */
    prop = "User";
    dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "(uo)", &variant);
    DBusMessageIter user_struct;
    dbus_message_iter_open_container(&variant, DBUS_TYPE_STRUCT, NULL, &user_struct);
    dbus_uint32_t uid = 1000;  /* Замените на реальный UID из сессии */
    const char *user_path = "/org/freedesktop/login1/user/1000";
    dbus_message_iter_append_basic(&user_struct, DBUS_TYPE_UINT32, &uid);
    dbus_message_iter_append_basic(&user_struct, DBUS_TYPE_OBJECT_PATH, &user_path);
    dbus_message_iter_close_container(&variant, &user_struct);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(&array_iter, &entry);
}
    
    dbus_message_iter_close_container(&iter, &array_iter);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);
}


static void handle_properties_set(DBusMessage *msg) {
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

/* SwitchToVT */
static void handle_switch_to_vt(DBusMessage *msg) {
    dbus_uint32_t vtnr;
    if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT32, &vtnr, DBUS_TYPE_INVALID)) {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected VT number");
        dbus_connection_send(conn, err, NULL);
        dbus_message_unref(err);
        return;
    }

    LOG_INFO_MSG("SwitchToVT: %u", vtnr);

    /* fork/exec */
    pid_t pid = fork();
    if (pid == 0) {
        char vt_str[16];
        snprintf(vt_str, sizeof(vt_str), "%u", vtnr);
        execl("/bin/chvt", "chvt", vt_str, NULL);
        execl("/bin/openvt", "openvt", "-s", "-c", vt_str, "--", "/bin/true", NULL);

        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            LOG_ERROR_MSG("Failed to switch to VT %u", vtnr);
        }
    } else {
        LOG_ERROR_MSG("Failed to fork for VT switch");
    }

    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

/* ReloadConfig */
static void handle_reload_config(DBusMessage *msg) {
    LOG_INFO_MSG("ReloadConfig called");
    read_config();
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static void handle_introspect(DBusMessage *msg) {
    const char *xml = 
        "<node>"
        "  <interface name='org.turnstile.login1.Manager'>"
        "    <method name='ListSessions'><arg type='a(susso)' direction='out'/></method>"
        "    <method name='ListUsers'><arg type='a(uso)' direction='out'/></method>"
        "    <method name='GetSession'><arg type='s' direction='in'/><arg type='o' direction='out'/></method>"
        "    <method name='GetUserSessions'><arg type='s' direction='in'/><arg type='a(sos)' direction='out'/></method>"
        "    <method name='GetActiveSeat'><arg type='s' direction='out'/></method>"
        "    <method name='GetActiveVTNr'><arg type='u' direction='out'/></method>"
        "    <method name='SwitchToVT'><arg type='u' direction='in'/></method>"
        "    <method name='TerminateSession'><arg type='s' direction='in'/></method>"
        "    <method name='TerminateUser'><arg type='u' direction='in'/></method>"
        "    <method name='GetRuntimeDir'><arg type='u' direction='in'/><arg type='s' direction='out'/></method>"
        "    <method name='SetupRuntimeDir'><arg type='u' direction='in'/></method>"
        "    <method name='CleanupRuntimeDir'><arg type='u' direction='in'/></method>"
        "    <method name='StopAllSessions'/>"
        "    <method name='PowerOff'><arg type='b' direction='in'/></method>"
        "    <method name='Reboot'><arg type='b' direction='in'/></method>"
        "    <method name='Suspend'><arg type='b' direction='in'/></method>"
        "    <method name='Hibernate'><arg type='b' direction='in'/></method>"
        "    <method name='CanPowerOff'><arg type='s' direction='out'/></method>"
        "    <method name='CanReboot'><arg type='s' direction='out'/></method>"
        "    <method name='CanSuspend'><arg type='s' direction='out'/></method>"
        "    <method name='CanHibernate'><arg type='s' direction='out'/></method>"
        "    <method name='CanHybridSleep'><arg type='s' direction='out'/></method>"
        "    <method name='CanSuspendThenHibernate'><arg type='s' direction='out'/></method>"
        "    <method name='SetWallMessage'><arg type='s' direction='in'/></method>"
        "    <method name='ScheduleShutdown'><arg type='s' direction='in'/><arg type='x' direction='in'/></method>"
        "    <method name='CancelScheduledShutdown'/>"
        "    <method name='CreateSession'><arg type='u' direction='in'/><arg type='u' direction='in'/><arg type='s' direction='in'/><arg type='s' direction='in'/><arg type='s' direction='in'/><arg type='s' direction='in'/><arg type='s' direction='in'/><arg type='u' direction='in'/><arg type='s' direction='in'/><arg type='s' direction='in'/><arg type='b' direction='in'/><arg type='s' direction='in'/><arg type='s' direction='in'/><arg type='s' direction='out'/><arg type='o' direction='out'/><arg type='s' direction='out'/><arg type='h' direction='out'/><arg type='s' direction='out'/><arg type='u' direction='out'/><arg type='b' direction='out'/><arg type='s' direction='out'/><arg type='s' direction='out'/></method>"
        "    <method name='ReleaseSession'><arg type='s' direction='in'/></method>"
        "    <method name='ActivateSession'><arg type='s' direction='in'/></method>"
        "    <method name='GetSessionByPID'><arg type='u' direction='in'/><arg type='o' direction='out'/></method>"
        "    <method name='SetIdleHint'><arg type='s' direction='in'/><arg type='b' direction='in'/></method>"
        "    <method name='SetSessionState'><arg type='s' direction='in'/><arg type='s' direction='in'/></method>"
        "    <method name='LockSession'><arg type='s' direction='in'/></method>"
        "    <method name='UnlockSession'><arg type='s' direction='in'/></method>"
        "    <method name='CanGraphical'><arg type='s' direction='out'/></method>"

        "    <method name='Inhibit'><arg type='s' direction='in'/><arg type='s' direction='in'/><arg type='s' direction='in'/><arg type='s' direction='in'/><arg type='h' direction='out'/></method>"
        "    <method name='ReloadConfig'/>"
        "    <signal name='SessionNew'><arg type='s'/><arg type='o'/></signal>"
        "    <signal name='SessionRemoved'><arg type='s'/><arg type='o'/></signal>"
        "    <signal name='PrepareForShutdown'><arg type='b'/></signal>"
        "    <signal name='PrepareForSleep'><arg type='b'/></signal>"
        "  </interface>"
        "  <interface name='org.freedesktop.DBus.Properties'>"
        "    <method name='Get'><arg type='s' direction='in'/><arg type='s' direction='in'/><arg type='v' direction='out'/></method>"
        "    <method name='GetAll'><arg type='s' direction='in'/><arg type='a{sv}' direction='out'/></method>"
        "    <method name='Set'><arg type='s' direction='in'/><arg type='s' direction='in'/><arg type='v' direction='in'/></method>"
        "  </interface>"
        "  <interface name='org.freedesktop.DBus.Introspectable'>"
        "    <method name='Introspect'><arg type='s' direction='out'/></method>"
        "  </interface>"
        "  <interface name='org.freedesktop.login1.Manager'>"
        "    <!-- All methods available via turnstile.login1.Manager -->"
        "  </interface>"
        "</node>";
    
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply) {
        dbus_message_append_args(reply, DBUS_TYPE_STRING, &xml, DBUS_TYPE_INVALID);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }
}

static DBusHandlerResult message_handler(DBusConnection *connection,
                                          DBusMessage *msg, void *user_data) {
    (void)user_data;
    
    if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_METHOD_CALL)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    
    const char *interface = dbus_message_get_interface(msg);
    const char *member = dbus_message_get_member(msg);
    
    LOG_INFO_MSG("D-Bus call: %s.%s from %s", interface?:"?", member?:"?", dbus_message_get_sender(msg)?:"?");
    if (!interface || !member)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    
    
    /* Handle Seat interface for KDE */
    if (strstr(dbus_message_get_path(msg), "/org/freedesktop/login1/seat/") ||
        strstr(dbus_message_get_path(msg), "/org/turnstile/login1/seat/")) {
        if (strcmp(member, "SwitchTo") == 0) { handle_switch_to_vt(msg); return DBUS_HANDLER_RESULT_HANDLED; }
        if (strcmp(member, "ActivateSession") == 0) { handle_activate_session(msg); return DBUS_HANDLER_RESULT_HANDLED; }
    }
    
    /* Handle Session interface for KDE */
    if (strstr(dbus_message_get_path(msg), "/org/freedesktop/login1/session/") ||
        strstr(dbus_message_get_path(msg), "/org/turnstile/login1/session/")) {
        if (strcmp(member, "Lock") == 0 || strcmp(member, "Unlock") == 0) { handle_set_session_state(msg); return DBUS_HANDLER_RESULT_HANDLED; }
        if (strcmp(member, "SetIdleHint") == 0) { handle_set_session_idle(msg); return DBUS_HANDLER_RESULT_HANDLED; }
        if (strcmp(member, "Activate") == 0) { handle_activate_session(msg); return DBUS_HANDLER_RESULT_HANDLED; }
        if (strcmp(member, "TakeControl") == 0) { handle_take_control(msg); return DBUS_HANDLER_RESULT_HANDLED; }
    }

    if (strcmp(interface, "org.freedesktop.DBus.Properties") == 0) {
        if (strcmp(member, "Get") == 0) handle_properties_get(msg);
        else if (strcmp(member, "GetAll") == 0) handle_properties_get_all(msg);
        else if (strcmp(member, "Set") == 0) handle_properties_set(msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    if (strcmp(interface, "org.freedesktop.DBus.Introspectable") == 0) {
        if (strcmp(member, "Introspect") == 0)
            handle_introspect(msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    
    if (strcmp(interface, BUS_IFACE) != 0 && strcmp(interface, LOGIND_IFACE) != 0)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    
    /* Permission check for destructive methods */
    if (strcmp(member, "PowerOff") == 0 || strcmp(member, "Reboot") == 0 ||
        strcmp(member, "Suspend") == 0 || strcmp(member, "Hibernate") == 0 ||
        strcmp(member, "TerminateSession") == 0 ||
        strcmp(member, "TerminateUser") == 0 ||
        strcmp(member, "StopAllSessions") == 0 ||
        strcmp(member, "ScheduleShutdown") == 0 ||
        strcmp(member, "CancelScheduledShutdown") == 0 ||
        strcmp(member, "SwitchToVT") == 0 ||
        strcmp(member, "ReloadConfig") == 0) {
        if (!check_permission(msg)) {
            DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_ACCESS_DENIED, "Permission denied");
            dbus_connection_send(connection, err, NULL);
            dbus_message_unref(err);
            return DBUS_HANDLER_RESULT_HANDLED;
        }
    }
    
    if (strcmp(member, "CreateSession") == 0) handle_create_session(msg);
    else if (strcmp(member, "ReleaseSession") == 0) handle_release_session(msg);
    else if (strcmp(member, "ActivateSession") == 0) handle_activate_session(msg);
    else if (strcmp(member, "GetSessionByPID") == 0) handle_get_session_by_pid(msg);
    else if (strcmp(member, "SetIdleHint") == 0) handle_set_session_idle(msg);
    else if (strcmp(member, "SetSessionState") == 0) handle_set_session_state(msg);
    else if (strcmp(member, "LockSession") == 0) handle_set_session_state(msg);
    else if (strcmp(member, "UnlockSession") == 0) handle_set_session_state(msg);
    else if (strcmp(member, "CanGraphical") == 0) handle_can_graphical(msg);
    else if (strcmp(member, "ListSeats") == 0) handle_list_seats(msg);
    else 
    if (strcmp(member, "ListSessions") == 0) handle_list_sessions(msg);
    else if (strcmp(member, "ListUsers") == 0) handle_list_users(msg);
    else if (strcmp(member, "GetSession") == 0) handle_get_session(msg);
    else if (strcmp(member, "GetUserSessions") == 0) handle_get_user_sessions(msg);
    else if (strcmp(member, "GetActiveSeat") == 0) handle_get_active_seat(msg);
    else if (strcmp(member, "GetActiveVTNr") == 0) handle_get_active_vtnr(msg);
    else if (strcmp(member, "TerminateSession") == 0) handle_terminate_session(msg);
    else if (strcmp(member, "TerminateUser") == 0) handle_terminate_user(msg);
    else if (strcmp(member, "GetRuntimeDir") == 0) handle_get_runtime_dir(msg);
    else if (strcmp(member, "SetupRuntimeDir") == 0) handle_setup_runtime_dir(msg);
    else if (strcmp(member, "CleanupRuntimeDir") == 0) handle_cleanup_runtime_dir(msg);
    else if (strcmp(member, "StopAllSessions") == 0) handle_stop_all_sessions(msg);
    else if (strcmp(member, "PowerOff") == 0) handle_power_off(msg);
    else if (strcmp(member, "Reboot") == 0) handle_reboot(msg);
    else if (strcmp(member, "Suspend") == 0) handle_suspend(msg);
    else if (strcmp(member, "Hibernate") == 0) handle_hibernate(msg);
    else if (strcmp(member, "CanPowerOff") == 0) handle_can_power_off(msg);
    else if (strcmp(member, "CanReboot") == 0) handle_can_reboot(msg);
    else if (strcmp(member, "CanSuspend") == 0) handle_can_suspend(msg);
    else if (strcmp(member, "CanHibernate") == 0) handle_can_hibernate(msg);
    else if (strcmp(member, "CanHybridSleep") == 0) handle_can_hybrid_sleep(msg);
    else if (strcmp(member, "CanSuspendThenHibernate") == 0) handle_can_suspend_then_hibernate(msg);
    else if (strcmp(member, "SetWallMessage") == 0) handle_set_wall_message(msg);
    else if (strcmp(member, "ScheduleShutdown") == 0) handle_schedule_shutdown(msg);
    else if (strcmp(member, "CancelScheduledShutdown") == 0) handle_cancel_scheduled_shutdown(msg);
    else if (strcmp(member, "SwitchToVT") == 0) handle_switch_to_vt(msg);
    else if (strcmp(member, "ReloadConfig") == 0) handle_reload_config(msg);
    else if (strcmp(member, "Inhibit") == 0) handle_inhibit(msg);
    else {
        DBusMessage *err = dbus_message_new_error(msg, DBUS_ERROR_UNKNOWN_METHOD, "Unknown method");
        if (err) {
            dbus_connection_send(connection, err, NULL);
            dbus_message_unref(err);
        }
    }
    
    return DBUS_HANDLER_RESULT_HANDLED;
}

/* ====== Helper Functions (must be before main) ====== */

static void check_inhibitors(void) {
    if (inhibitors_count == 0) return;

    int removed = 0;

    for (int i = inhibitors_count - 1; i >= 0; i--) {
        /* Check if fd is still valid by trying to read */
        char buf[1];
        ssize_t n = read(inhibitors[i].fd, buf, sizeof(buf));

        if (n == 0) {
            /* Client closed the fd - inhibitor released */
            LOG_INFO_MSG("Inhibitor released: %s (fd=%d)",
                         inhibitors[i].name ? inhibitors[i].name : "unknown",
                         inhibitors[i].fd);

            /* Close our monitoring fd */
            close(inhibitors[i].fd);

            /* Free strings */
            if (inhibitors[i].name) {
                free(inhibitors[i].name);
            }
            if (inhibitors[i].description) {
                free(inhibitors[i].description);
            }

            /* Mark as removed */
            inhibitors[i].fd = -1;
            inhibitors[i].name = NULL;
            inhibitors[i].description = NULL;
            removed++;
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            /* Error reading - fd might be invalid */
            LOG_ERROR_MSG("Error checking inhibitor fd %d: %s",
                          inhibitors[i].fd, strerror(errno));

            close(inhibitors[i].fd);
            if (inhibitors[i].name) free(inhibitors[i].name);
            if (inhibitors[i].description) free(inhibitors[i].description);

            inhibitors[i].fd = -1;
            inhibitors[i].name = NULL;
            inhibitors[i].description = NULL;
            removed++;
        }
    }

    /* Compact the array if any inhibitors were removed */
    if (removed > 0) {
        int write_idx = 0;
        for (int i = 0; i < inhibitors_count; i++) {
            if (inhibitors[i].fd >= 0) {
                if (write_idx != i) {
                    inhibitors[write_idx] = inhibitors[i];
                }
                write_idx++;
            }
        }

        inhibitors_count = write_idx;

        if (inhibitors_count > 0) {
            void *tmp = realloc(inhibitors, inhibitors_count * sizeof(InhibitorLock));
            if (tmp) {
                inhibitors = tmp;
            }
        } else {
            free(inhibitors);
            inhibitors = NULL;
        }

        LOG_INFO_MSG("Compacted inhibitors array: removed %d, remaining %d",
                     removed, inhibitors_count);
    }
}

static void cleanup_all_inhibitors(void) {
    if (inhibitors_count == 0) return;

    LOG_INFO_MSG("Cleaning up %d inhibitors during shutdown", inhibitors_count);

    for (int i = 0; i < inhibitors_count; i++) {
        if (inhibitors[i].fd >= 0) {
            close(inhibitors[i].fd);
        }
        if (inhibitors[i].name) {
            free(inhibitors[i].name);
        }
        if (inhibitors[i].description) {
            free(inhibitors[i].description);
        }
    }

    free(inhibitors);
    inhibitors = NULL;
    inhibitors_count = 0;
}

static int send_reply_safe(DBusMessage *reply) {
    if (!reply) return 0;
    dbus_bool_t ret = dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);
    if (!ret) {
        LOG_ERROR_MSG("Failed to send D-Bus reply: out of memory or connection lost");
    }
    return ret;
}

static int send_error_safe(DBusMessage *error) {
    if (!error) return 0;
    dbus_bool_t ret = dbus_connection_send(conn, error, NULL);
    dbus_message_unref(error);
    if (!ret) {
        LOG_ERROR_MSG("Failed to send D-Bus error: out of memory or connection lost");
    }
    return ret;
}
/* ====== End of Helper Functions ====== */

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    read_config();
    if (enable_syslog) {
        openlog("turnstile-dbus", LOG_PID | LOG_CONS, LOG_DAEMON);
    }


    LOG_INFO_MSG("Starting turnstile-dbus v%s", VERSION);
    LOG_INFO_MSG("Config: power=%d, scheduled=%d, inhibit_mode=%d, idle_timeout=%d",
                 power_management, enable_scheduled, inhibit_mode, idle_session_timeout);

    if (geteuid() != 0) {
        LOG_ERROR_MSG("Must be run as root!");
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);

    DBusError dbus_err;
    dbus_error_init(&dbus_err);

    conn = dbus_bus_get(DBUS_BUS_SYSTEM, &dbus_err);
    if (!conn) {
        LOG_ERROR_MSG("Failed to connect to D-Bus: %s", dbus_err.message);
        dbus_error_free(&dbus_err);
        return 1;
    }

    int ret = dbus_bus_request_name(conn, BUS_NAME, DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE, &dbus_err);
    if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        LOG_ERROR_MSG("Failed to acquire name %s: %s", BUS_NAME,
                      dbus_error_is_set(&dbus_err) ? dbus_err.message : "unknown error");
        if (dbus_error_is_set(&dbus_err)) dbus_error_free(&dbus_err);
        dbus_connection_unref(conn);
        conn = NULL;
        return 1;
    }

    /* Clear any leftover error state */
    if (dbus_error_is_set(&dbus_err)) {
        dbus_error_free(&dbus_err);
    }
    dbus_error_init(&dbus_err);

    DBusObjectPathVTable vtable = {0};
    vtable.message_function = message_handler;
    dbus_connection_register_object_path(conn, BUS_OBJ, &vtable, NULL);
    /* Also register on logind-compatible object path */
    /* Register Seat objects for KDE */
    dbus_connection_register_object_path(conn, "/org/freedesktop/login1/seat/seat0", &vtable, NULL);
    dbus_connection_register_object_path(conn, "/org/freedesktop/login1/seat/auto", &vtable, NULL);

    dbus_connection_register_object_path(conn, "/org/freedesktop/login1", &vtable, NULL);
    dbus_connection_register_fallback(conn, "/org/freedesktop/login1/session", &vtable, NULL);
    dbus_connection_register_fallback(conn, "/org/turnstile/login1/session", &vtable, NULL);

    LOG_INFO_MSG("Service registered as %s", BUS_NAME);

    /* Register optional second bus name for logind compatibility */
    if (second_bus_name && second_bus_name[0] != '\0') {
        DBusError dbus_err2;
        dbus_error_init(&dbus_err2);

        int ret2 = dbus_bus_request_name(conn, second_bus_name,
                                         DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                         &dbus_err2);
        if (ret2 == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
            LOG_INFO_MSG("Also registered as %s", second_bus_name);
        } else {
            LOG_ERROR_MSG("Failed to acquire %s: %s", second_bus_name,
                          dbus_error_is_set(&dbus_err2) ? dbus_err2.message : "unknown");
        }

        if (dbus_error_is_set(&dbus_err2)) {
            dbus_error_free(&dbus_err2);
        }
    }

    ts_monitor = turnstile_new();
    if (ts_monitor) {
        turnstile_watch_events(ts_monitor, turnstile_event_cb, NULL);
        pthread_create(&monitor_thread, NULL, monitor_thread_func, NULL);
        /* Will be joined in cleanup */
        LOG_INFO_MSG("Event monitoring active");
    }

    LOG_INFO_MSG("Ready to handle requests (v%s)", VERSION);

    while (running) {
        if (reload_config_flag) {
            reload_config_flag = 0;
            LOG_INFO_MSG("Reloading config...");
            read_config();
            LOG_INFO_MSG("Config reloaded");
        }

        dbus_connection_read_write_dispatch(conn, 50);

            check_inhibitors();

        /* Check scheduled shutdown */
        if (sched_shutdown && sched_shutdown->active && enable_scheduled) {
            time_t now = time(NULL);
            if (now >= sched_shutdown->scheduled_time) {
                LOG_INFO_MSG("Executing scheduled shutdown");
                emit_prepare_for_shutdown(1);
                dbus_connection_flush(conn);
                sleep(1);
                if (sched_shutdown->shutdown_type == 1) {
                    do_reboot();
                } else {
                    do_power_off();
                }
                if (sched_shutdown->wall_message) free(sched_shutdown->wall_message);
                free(sched_shutdown);
                sched_shutdown = NULL;
            }
        }
    }

    LOG_INFO_MSG("Shutting down...");

    running = 0;  /* Ensure flag is set for thread */

    if (ts_monitor) {
        pthread_join(monitor_thread, NULL);
        turnstile_free(ts_monitor);
        ts_monitor = NULL;
    }

    if (conn) {
        dbus_bus_release_name(conn, BUS_NAME, NULL);
        if (second_bus_name) {
            dbus_bus_release_name(conn, second_bus_name, NULL);
        }
        dbus_connection_flush(conn);
        dbus_connection_unref(conn);
        conn = NULL;
    }
    if (handle_lid_switch) {
        free(handle_lid_switch);
        handle_lid_switch = NULL;
    }
    if (handle_power_key) {
        free(handle_power_key);
        handle_power_key = NULL;
    }
    if (handle_suspend_key) {
        free(handle_suspend_key);
        handle_suspend_key = NULL;
    }
    /* Cleanup */
    if (sched_shutdown) {
        if (sched_shutdown->wall_message) free(sched_shutdown->wall_message);
        free(sched_shutdown);
        sched_shutdown = NULL;
    }
    if (second_bus_name) {
        free(second_bus_name);
        second_bus_name = NULL;
    }
    if (shutdown_wall_message) {
        free(shutdown_wall_message);
        shutdown_wall_message = NULL;
    }
    if (suspend_method) {
        free(suspend_method);
        suspend_method = NULL;
    }
    if (hibernate_method) {
        free(hibernate_method);
        hibernate_method = NULL;
    }
    if (default_seat) {
        free(default_seat);
        default_seat = NULL;
    }
    /* Clean up inhibitors properly */
    cleanup_all_inhibitors();

    if (enable_syslog) closelog();
    return 0;
}
