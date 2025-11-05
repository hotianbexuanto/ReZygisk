#ifndef KERNELSU_H
#define KERNELSU_H

#include "../constants.h"

enum kernelsu_variants {
  KOfficial,
  KNext
};

/* KernelSU API methods */
enum ksu_api_method {
  KSU_API_PRCTL,   /* Legacy prctl-based API */
  KSU_API_IOCTL    /* Modern ioctl-based API */
};

void ksu_get_existence(struct root_impl_state *state);

bool ksu_uid_granted_root(uid_t uid);

bool ksu_uid_should_umount(uid_t uid);

bool ksu_uid_is_manager(uid_t uid);

/* Get current API method being used */
enum ksu_api_method ksu_get_api_method(void);

#endif
