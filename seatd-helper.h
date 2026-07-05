/* seatd-helper.h - turnstile-dbus & seatd */
#ifndef SEATD_HELPER_H
#define SEATD_HELPER_H

#include <libseat.h>

int seatd_helper_init(void);

int seatd_helper_get_drm_fd(unsigned long session_id);

int seatd_helper_get_input_fds(int **fds, int *count, unsigned long session_id);

void seatd_helper_cleanup(void);

#endif
