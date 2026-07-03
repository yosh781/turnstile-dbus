# turnstile-dbus

**D-Bus service for Turnstile — full logind replacement without systemd**

turnstile-dbus implements the `org.turnstile.login1` D-Bus interface for session and power management, using **Turnstile + Seatd + Dinit** as the init/seat stack. It provides a logind-compatible API for desktop environments, display managers, and applications.

Provides `org.freedesktop.login1` compatibility for KDE, LXQt, and other desktop environments that expect logind over D-Bus.

---

## Features

### Session Management
| Method | Description |
|--------|-------------|
| `ListSessions` | List all active sessions `a(susso)` |
| `ListUsers` | List unique users with sessions `a(uso)` |
| `GetSession` | Get session object path by ID |
| `GetUserSessions` | Get all sessions for a user `a(sos)` |
| `TerminateSession` | Stop a session by ID |
| `TerminateUser` | Stop all sessions for a UID |
| `StopAllSessions` | Stop every active session |

### Power Management
| Method | Description |
|--------|-------------|
| `PowerOff` | Shut down the system |
| `Reboot` | Reboot the system |
| `Suspend` | Suspend-to-RAM (write `mem` to `/sys/power/state`) |
| `Hibernate` | Hibernate-to-disk (write `disk` to `/sys/power/state`) |
| `CanPowerOff` / `CanReboot` / `CanSuspend` / `CanHibernate` / `CanHybridSleep` | Query capabilities |

Suspend/hibernate use the kernel's `/sys/power/state` interface directly. Configurable via `suspend_method` and `hibernate_method` (`kernel` for sysfs, `external` for pm-utils).

### Shutdown Scheduling
| Method | Description |
|--------|-------------|
| `SetWallMessage` | Set wall message for shutdown |
| `ScheduleShutdown` | Schedule poweroff/reboot in microseconds |
| `CancelScheduledShutdown` | Cancel pending scheduled shutdown |

### Inhibitors
| Method | Description |
|--------|-------------|
| `Inhibit` | Create an inhibitor lock (returns fd) |

All power operations check for active inhibitors. If inhibitors are present, the daemon sends `PrepareForShutdown(true)`, waits `max_inhibit_delay` seconds, and cancels if inhibitors remain.

### VT & Seat
| Method | Description |
|--------|-------------|
| `GetActiveSeat` | Get active seat name |
| `GetActiveVTNr` | Get active virtual terminal number |
| `SwitchToVT` | Switch to a virtual terminal |

### Runtime Directory
| Method | Description |
|--------|-------------|
| `GetRuntimeDir` | Get runtime directory for UID |
| `SetupRuntimeDir` | Create runtime directory |
| `CleanupRuntimeDir` | Remove runtime directory |

### D-Bus Properties
Full `org.freedesktop.DBus.Properties` support:
- `Get` / `GetAll` / `Set`
- Properties: `ActiveSeat`, `ActiveVTNr`

### Signals
| Signal | Description |
|--------|-------------|
| `SessionNew` | Emitted when a session is created |
| `SessionRemoved` | Emitted when a session is removed |
| `PrepareForShutdown` | Emitted before/after shutdown attempts |
| `PrepareForSleep` | Emitted before/after sleep attempts |

### Configuration
| Method | Description |
|--------|-------------|
| `ReloadConfig` | Reload configuration at runtime |
| `SIGHUP` | Same as ReloadConfig |

---

## Architecture
Linux kernel
↓
Seatd (device access)
↓
Turnstile (session tracking, VT management)
↓
turnstile-dbus (D-Bus API) ← this project
↓
┌───────────┬──────────────┬─────────────────┐
↓ ↓ ↓ ↓
Dinit-dbus Polkit-agent DE logout dialogs Apps (inhibit)

text

- **No systemd, no elogind** — uses Turnstile + Dinit instead
- **No polkit dependency** — UID-based permission check (polkit optional via config)
- **Native /sys/power/state** — no external power management tools required

---
📋 Compatibility

DE	            Status
KDE Plasma	    ✅ Full support
LXQt	        ✅ Full support
XFCE	        ✅ Should work
GNOME	        ⚠️ Requires systemd, incompatible
Sway/Hyprland	⚠️ Needs testing

## Dependencies

- `libdbus-1-3` (>= 1.12.0)
- `libturnstile-highlevel` — Turnstile high-level C library
- `libturnstile0` — Turnstile low-level library
- `libturnstile-dev`
- `dinit` — init system
- `seatd` — seat management daemon
- `gcc`  
**Conflicts:** `systemd`, `elogind`

---

## Build

```bash
# Install build dependencies
sudo apt install libdbus-1-dev libturnstile-dev

Build from source

bash
git clone https://github.com/yosh781/Turnstile-dbus.git
cd turnstile-dbus
./build-v2.6.sh
sudo cp turnstile-dbus /usr/sbin/
sudo dinitctl start turnstile-dbus


# Run
sudo ./turnstile-dbus
Build script (build-v2.6.sh)
bash
gcc -o turnstile-dbus src/turnstile-dbus-final.c \
    -I/usr/include/dbus-1.0 \
    -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include \
    -I/usr/include/turnstile \
    -ldbus-1 \
    -lturnstile-highlevel \
    -lturnstile \
    -lpthread
Configuration
File: /etc/turnstile/turnstile-dbus.conf

ini
[General]
ENABLE_SYSLOG = 1
dbus_timeout = 30000
auto_activate_sessions = true
default_seat = seat0

[PowerManagement]
power_management = true
suspend_method = kernel       # kernel | external
hibernate_method = kernel     # kernel | external
fallback_enabled = false
enable_scheduled_shutdown = true
shutdown_wall_message = System will shut down for maintenance

[Inhibitors]
inhibitors_enabled = true
max_inhibit_delay = 30

[Security]
polkit_enabled = false
D-Bus API
Bus: org.turnstile.login1
Object: /org/turnstile/login1
Interface: org.turnstile.login1.Manager

Test examples
bash
# List sessions
dbus-send --system --print-reply \
  --dest=org.turnstile.login1 \
  /org/turnstile/login1 \
  org.turnstile.login1.Manager.ListSessions

# Get property
dbus-send --system --print-reply \
  --dest=org.turnstile.login1 \
  /org/turnstile/login1 \
  org.freedesktop.DBus.Properties.Get \
  string:"org.turnstile.login1.Manager" string:"ActiveSeat"

# Suspend
sudo dbus-send --system --print-reply \
  --dest=org.turnstile.login1 \
  /org/turnstile/login1 \
  org.turnstile.login1.Manager.Suspend boolean:false

# Inhibit shutdown
dbus-send --system --print-reply \
  --dest=org.turnstile.login1 \
  /org/turnstile/login1 \
  org.turnstile.login1.Manager.Inhibit \
  string:"shutdown" string:"updater" \
  string:"System update in progress" string:"block"

# Switch to VT 2
sudo dbus-send --system --print-reply \
  --dest=org.turnstile.login1 \
  /org/turnstile/login1 \
  org.turnstile.login1.Manager.SwitchToVT uint32:2

# Reload config
sudo dbus-send --system --print-reply \
  --dest=org.turnstile.login1 \
  /org/turnstile/login1 \
  org.turnstile.login1.Manager.ReloadConfig
D-Bus Policy
File: /usr/share/dbus-1/system.d/org.turnstile.login1.conf

Root has full access. Regular users can query sessions, check power capabilities, and create inhibitors. Destructive operations (PowerOff, Reboot, etc.) require root.

xml
<policy user="root">
    <allow own="org.turnstile.login1"/>
    <allow send_destination="org.turnstile.login1"/>
</policy>
<policy context="default">
    <allow send_interface="org.freedesktop.DBus.Properties"/>
    <allow send_interface="org.turnstile.login1.Manager"
           send_member="ListSessions|GetActiveSeat|CanPowerOff|Inhibit|..."/>
</policy>
Integration with Desktop Environments
turnstile-dbus is tested with:

DE/WM	Integration
LXQt	lxqt-leave wrapper → /usr/bin/lxqt-leave-turnstile
XFCE	xfsm-shutdown-helper wrapper
Sway	Uses logind protocol directly
Wrapper scripts are included in the Debian package and installed automatically.

Service (Dinit)
File: /etc/dinit.d/turnstile-dbus

text
type = process
command = /usr/sbin/turnstile-dbus
logfile = /var/log/turnstile-dbus.log
depends-on = dbus
depends-ms = turnstiled
smooth-recovery = true
restart = true
bash
sudo dinitctl start turnstile-dbus
sudo dinitctl status turnstile-dbus
sudo dinitctl restart turnstile-dbus
Installation
bash
# From .deb package
sudo dpkg -i turnstile-dbus_2.5.0_amd64.deb
sudo dinitctl restart turnstile-dbus

# Test
/usr/share/turnstile/test-api-v2.4.sh


Changelog

v2.6.4

### Added
- Disable unnecessary functions in /etc/turnstile/turnstile-dbus.conf
### Fixed
- Memory leaks
- Inhibitors are correctly created and released

v2.6.3

### Added
- **Integration with seatd via libseat** to pass DRM of devices to Wayland composers
- New module 'seatd-helper.c/h' with support for libseat API v0.8+
- Automatically fetch DRM fd via seatd when calling 'CreateSession'
- Fallback to open devices directly if seatd is not available
- **'CreateSession' now returns Unix FD** to the device '/dev/dri/card0'
- Full compatibility with logind API for Wayland sessions
- KWin,  Mutter, wlroots-composers get devices via D-Bus
- **Registering session objects via 'dbus_connection_register_fallback'***
- 'GetAll' and 'Get' for Properties now work on '/org/freedesktop/login1/session/*'
- 'Introspect' correctly displays interfaces for session paths

### Fixed
- 'handle_create_session': replaced 'turnstile_get_user_sessions' with 'turnstile_get_sessions'
to correctly search for existing sessions
- 'ActiveSession' now returns '/org/freedesktop/login1/session/1' instead of 'auto'
- 'handle_properties_get_all': added support for 'Session' and 'Seat' interfaces
- Fixed passing 'DBUS_TYPE_UNIX_FD' in the 'CreateSession' response

### Dependencies
- Added: 'libseat-dev' (≥ 0.8) to integrate with seatd
- Retained: 'libturnstile-dev', 'libturnstile-highlevel', 'libdbus-1-dev'

### Assembly
- Updated 'build-v2.6.sh' with pkg-config support for libseat
- Added compilation 'seatd-helper.c' in the build process

 v2.6.2  — Bugfix Release

* **Fixed race condition**: `pthread_detach` → `pthread_join` prevents use-after-free crash on daemon shutdown
* **Fixed `GetUserSessions` no-reply bug**: Added missing `dbus_connection_send()` — method now returns proper response
* **Fixed memory leak**: `turnstile_free_sessions()` now called in `GetUserSessions`
* **Fixed memory leak**: `wall_message` properly freed before overwriting in `ScheduleShutdown`
* **Fixed D-Bus type error**: `DBUS_TYPE_UNIX_FD` → `DBUS_TYPE_UINT32` in `CreateSession` response (was sending `unsigned long` as file descriptor)
* **Removed duplicate logging**: Double `LOG_INFO_MSG` on every D-Bus call reduced to single line
* **Improved stability**: Proper thread cleanup prevents zombie threads on service restart

turnstile-dbus (2.6.0) stable; urgency=medium

  * Fixed deadlock in check_permission - replaced blocking
    dbus_connection_send_with_reply_and_block with non-blocking
    dbus_bus_get_unix_user
  * Fixed bug: SwitchToVT, ReloadConfig, CancelScheduledShutdown
    were incorrectly merged into one handler
  * Added automatic D-Bus name release before request to fix
    stale name registrations after crash
  * Added DBUS_NAME_FLAG_DO_NOT_QUEUE for aggressive name takeover
  * Added KDE compatibility:
    - CreateSession, ReleaseSession, ActivateSession
    - GetSessionByPID, SetIdleHint, SetSessionState
    - LockSession, UnlockSession, CanGraphical
    - CanSuspendThenHibernate, RebootTo*
    - Seat/Session object paths for properties
  * Registered /org/freedesktop/login1/seat/seat0 and auto
  * Inhibitor disabled for all power operations

v2.5.0
D-Bus Properties interface (Get, GetAll, Set)

SwitchToVT method

ReloadConfig method + SIGHUP support

Inhibitor checks before all power operations

Updated D-Bus security policy

v2.4.1
Fixed read_config() before openlog() for correct syslog

Fixed memory leak in handle_inhibit realloc

Improved config parser (spaces, inline comments)

Real suspend/hibernate via /sys/power/state

v2.4.0
SetWallMessage, ScheduleShutdown, CancelScheduledShutdown

Inhibit with fd return

GetSession by ID

Extended config (14 parameters)

v2.3.0
28 D-Bus methods

Signal-based power management

UID permission check

Session/seat/user management

License
Part of the Turnstile project. See main repository for license details.

Links
Turnstile: https://github.com/turnstile/turnstile

Dinit: https://github.com/davmac314/dinit

Seatd: https://git.sr.ht/~kennylevinsen/seatd

