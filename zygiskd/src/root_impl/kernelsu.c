#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>

#include "../constants.h"
#include "../utils.h"
#include "common.h"

#include "kernelsu.h"

/* ============================================================================
 * Legacy prctl-based API definitions
 * ============================================================================ */

/* INFO: It would be presumed it is a unsigned int,
           so we need to cast it to signed int to
           avoid any potential UB.
*/
#define KERNEL_SU_OPTION (int)0xdeadbeef

#define CMD_GET_VERSION 2
#define CMD_UID_GRANTED_ROOT 12
#define CMD_UID_SHOULD_UMOUNT 13
#define CMD_GET_MANAGER_UID 16
#define CMD_HOOK_MODE 0xC0DEAD1A

/* ============================================================================
 * Modern ioctl-based API definitions
 * ============================================================================ */

#define KSU_IOCTL_GRANT_ROOT     0x00004b01  /* _IOC(_IOC_NONE, 'K', 1, 0) */
#define KSU_IOCTL_GET_INFO       0x80004b02  /* _IOC(_IOC_READ, 'K', 2, 0) */
#define KSU_IOCTL_REPORT_EVENT   0x40004b03  /* _IOC(_IOC_WRITE, 'K', 3, 0) */
#define KSU_IOCTL_SET_SEPOLICY   0xc0004b04  /* _IOC(_IOC_READ|_IOC_WRITE, 'K', 4, 0) */
#define KSU_IOCTL_CHECK_SAFEMODE 0x80004b05  /* _IOC(_IOC_READ, 'K', 5, 0) */
#define KSU_IOCTL_GET_FEATURE    0xc0004b0d  /* _IOC(_IOC_READ|_IOC_WRITE, 'K', 13, 0) */
#define KSU_IOCTL_SET_FEATURE    0x40004b0e  /* _IOC(_IOC_WRITE, 'K', 14, 0) */

#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define KSU_INSTALL_MAGIC2 0xCAFEBABE

struct ksu_get_info_cmd {
  uint32_t version;
  uint32_t flags;
};

struct ksu_check_safemode_cmd {
  uint8_t in_safe_mode;
};

/* ============================================================================
 * State variables
 * ============================================================================ */

static enum kernelsu_variants variant = KOfficial;
static enum ksu_api_method api_method = KSU_API_PRCTL;
static int driver_fd = -1;
static bool supports_manager_uid_retrieval = false;

/* ============================================================================
 * Modern ioctl API helper functions
 * ============================================================================ */

/* Scan /proc/self/fd to find existing driver fd */
static int scan_driver_fd(void) {
  DIR *fd_dir = opendir("/proc/self/fd");
  if (!fd_dir) return -1;

  struct dirent *entry;
  while ((entry = readdir(fd_dir)) != NULL) {
    if (entry->d_name[0] == '.') continue;

    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%s", entry->d_name);

    char target[256];
    ssize_t len = readlink(link_path, target, sizeof(target) - 1);
    if (len > 0) {
      target[len] = '\0';
      if (strstr(target, "[ksu_driver]")) {
        int fd = atoi(entry->d_name);
        closedir(fd_dir);
        return fd;
      }
    }
  }

  closedir(fd_dir);
  return -1;
}

/* Initialize driver fd for ioctl API */
static int init_driver_fd(void) {
  /* First try to scan existing fds */
  int fd = scan_driver_fd();
  if (fd >= 0) {
    LOGI("Found existing KSU driver fd: %d\n", fd);
    return fd;
  }

  /* Try to get fd via syscall */
  fd = -1;
  syscall(__NR_reboot, KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &fd);

  if (fd >= 0) {
    LOGI("Obtained KSU driver fd via syscall: %d\n", fd);
    return fd;
  }

  return -1;
}

/* Execute ioctl command */
static int ksuctl(unsigned long request, void *arg) {
  if (driver_fd < 0) return -1;

  int ret = ioctl(driver_fd, request, arg);
  if (ret < 0) {
    return -1;
  }
  return ret;
}

/* ============================================================================
 * API version detection and initialization
 * ============================================================================ */

/* Try to detect which API is available */
static bool try_ioctl_api(int *version) {
  int fd = init_driver_fd();
  if (fd < 0) return false;

  driver_fd = fd;

  struct ksu_get_info_cmd cmd = {0};
  int ret = ksuctl(KSU_IOCTL_GET_INFO, &cmd);

  if (ret >= 0 && cmd.version > 0) {
    *version = (int)cmd.version;
    LOGI("KSU ioctl API detected, version: %d\n", *version);
    return true;
  }

  /* Failed to use ioctl API */
  if (driver_fd >= 0) {
    close(driver_fd);
    driver_fd = -1;
  }
  return false;
}

static bool try_prctl_api(int *version) {
  int reply_ok = 0;
  prctl((signed int)KERNEL_SU_OPTION, CMD_GET_VERSION, version, 0, &reply_ok);

  if (*version > 0) {
    LOGI("KSU prctl API detected, version: %d\n", *version);
    return true;
  }
  return false;
}

/* ============================================================================
 * Public API implementations
 * ============================================================================ */

void ksu_get_existence(struct root_impl_state *state) {
  int version = 0;
  bool api_detected = false;

  /* Try modern ioctl API first */
  if (try_ioctl_api(&version)) {
    api_method = KSU_API_IOCTL;
    api_detected = true;
    LOGI("Using modern ioctl-based KSU API\n");
  }
  /* Fallback to legacy prctl API */
  else if (try_prctl_api(&version)) {
    api_method = KSU_API_PRCTL;
    api_detected = true;
    LOGI("Using legacy prctl-based KSU API\n");
  }

  if (!api_detected || version == 0) {
    state->state = Abnormal;
    return;
  }

  if (version >= MIN_KSU_VERSION && version <= MAX_KSU_VERSION) {
    /* INFO: Some custom kernels for custom ROMs have pre-installed KernelSU.
            Some users don't want to use KernelSU, but, for example, Magisk.
            This if allows this to happen, as it checks if "ksud" exists,
            which in case it doesn't, it won't be considered as supported. */
    struct stat s;
    if (stat("/data/adb/ksud", &s) == -1) {
      if (errno != ENOENT) {
        LOGE("Failed to stat KSU daemon: %s\n", strerror(errno));
      }
      errno = 0;
      state->state = Abnormal;

      return;
    }

    state->state = Supported;

    /* Detect variant (Official vs Next) - only works with prctl API */
    if (api_method == KSU_API_PRCTL) {
      int reply_ok = 0;
      char mode[16] = { 0 };
      prctl((signed int)KERNEL_SU_OPTION, CMD_HOOK_MODE, mode, NULL, &reply_ok);

      if (mode[0] != '\0') state->variant = KNext;
      else state->variant = KOfficial;
    } else {
      /* For ioctl API, default to KOfficial
         TODO: Add proper detection method if available in future */
      state->variant = KOfficial;
    }

    variant = state->variant;

    /* Check if CMD_GET_MANAGER_UID is supported (prctl API only) */
    if (api_method == KSU_API_PRCTL) {
      int reply_ok = 0;
      prctl((signed int)KERNEL_SU_OPTION, CMD_GET_MANAGER_UID, NULL, NULL, &reply_ok);

      if (reply_ok == KERNEL_SU_OPTION) {
        LOGI("KernelSU implementation supports CMD_GET_MANAGER_UID.\n");
        supports_manager_uid_retrieval = true;
      }
    }
  }
  else if (version >= 1 && version <= MIN_KSU_VERSION - 1) {
    state->state = TooOld;
  }
  else {
    state->state = Abnormal;
  }
}

bool ksu_uid_granted_root(uid_t uid) {
  if (api_method == KSU_API_IOCTL) {
    /* Modern ioctl API doesn't have a direct UID check command
       We need to rely on other mechanisms or return a conservative result
       For now, return false as this needs proper implementation */
    return false;
  }
  else {
    /* Legacy prctl API */
    uint32_t result = 0;
    bool granted = false;
    prctl(KERNEL_SU_OPTION, CMD_UID_GRANTED_ROOT, uid, &granted, &result);

    if ((int)result != KERNEL_SU_OPTION) return false;

    return granted;
  }
}

bool ksu_uid_should_umount(uid_t uid) {
  if (api_method == KSU_API_IOCTL) {
    /* Modern ioctl API doesn't have a direct UID umount check command
       We need to rely on other mechanisms or return a conservative result
       For now, return false as this needs proper implementation */
    return false;
  }
  else {
    /* Legacy prctl API */
    uint32_t result = 0;
    bool umount = false;
    prctl(KERNEL_SU_OPTION, CMD_UID_SHOULD_UMOUNT, uid, &umount, &result);

    if ((int)result != KERNEL_SU_OPTION) return false;

    return umount;
  }
}

bool ksu_uid_is_manager(uid_t uid) {
  /* If the manager UID retrieval is supported (prctl API), use it */
  if (api_method == KSU_API_PRCTL && supports_manager_uid_retrieval) {
    int reply_ok = 0;

    uid_t manager_uid = 0;
    prctl(KERNEL_SU_OPTION, CMD_GET_MANAGER_UID, &manager_uid, NULL, &reply_ok);

    return uid == manager_uid;
  }

  /* Fallback to filesystem check for both APIs */
  const char *manager_path = NULL;
  if (variant == KOfficial) manager_path = "/data/user_de/0/me.weishu.kernelsu";
  else if (variant == KNext) manager_path = "/data/user_de/0/com.rifsxd.ksunext";

  struct stat s;
  if (stat(manager_path, &s) == -1) {
    if (errno != ENOENT) {
      LOGE("Failed to stat KSU manager data directory: %s\n", strerror(errno));
    }
    errno = 0;

    return false;
  }

  return s.st_uid == uid;
}

enum ksu_api_method ksu_get_api_method(void) {
  return api_method;
}
