#ifndef GELHOOK_H
#define GELHOOK_H

/*
  GelHook - single-header minimal x86_64 hook library (pure C)
  MIT License or other license to be chosen.
*/

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(_WIN64)
  #define GH_PLATFORM_WINDOWS 1
#else
  #define GH_PLATFORM_POSIX 1
#endif

#if defined(__x86_64__) || defined(_M_X64)
  #define GH_ARCH_X64 1
#else
  #error "GelHook currently supports x86_64 only."
#endif

#ifndef GELHOOK_API
  #define GELHOOK_API
#endif

#define GH_PATCH_SIZE 12

typedef enum gh_status {
  GH_OK = 0,
  GH_ERR_INVALID_ARG = -1,
  GH_ERR_UNSUPPORTED = -2,
  GH_ERR_ALLOC = -3,
  GH_ERR_PROTECT = -4,
  GH_ERR_STATE = -5
} gh_status;

typedef struct gh_hook {
  void *target;
  void *replacement;
  void *trampoline;
  size_t patch_size;
  unsigned char original[GH_PATCH_SIZE];
  int enabled;
} gh_hook;

GELHOOK_API gh_status gh_init_hook(gh_hook *hook, void *target, void *replacement);
GELHOOK_API gh_status gh_enable_hook(gh_hook *hook);
GELHOOK_API gh_status gh_disable_hook(gh_hook *hook);
GELHOOK_API gh_status gh_destroy_hook(gh_hook *hook);
GELHOOK_API const char *gh_last_error(void);

#ifdef __cplusplus
}
#endif

#ifdef GELHOOK_IMPLEMENTATION

#if GH_PLATFORM_WINDOWS
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#else
  #include <sys/mman.h>
  #include <unistd.h>
#endif

static char g_gh_last_error[128];

static void gh_set_error(const char *msg) {
  size_t n = strlen(msg);
  if (n >= sizeof(g_gh_last_error)) n = sizeof(g_gh_last_error) - 1;
  memcpy(g_gh_last_error, msg, n);
  g_gh_last_error[n] = '\0';
}

const char *gh_last_error(void) {
  return g_gh_last_error;
}

static void gh_write_abs_jump(void *at, void *to, unsigned char out[GH_PATCH_SIZE]) {
  unsigned char *p = out;
  /* mov rax, imm64 */
  p[0] = 0x48; p[1] = 0xB8;
  *(uint64_t *)(p + 2) = (uint64_t)(uintptr_t)to;
  /* jmp rax */
  p[10] = 0xFF; p[11] = 0xE0;
  if (at) {
    memcpy(at, p, GH_PATCH_SIZE);
  }
}

static gh_status gh_protect_rwxa(void *addr, size_t size, int *old_prot_out) {
#if GH_PLATFORM_WINDOWS
  DWORD old_prot = 0;
  if (!VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old_prot)) {
    gh_set_error("VirtualProtect failed");
    return GH_ERR_PROTECT;
  }
  if (old_prot_out) *old_prot_out = (int)old_prot;
  return GH_OK;
#else
  long page_size = sysconf(_SC_PAGESIZE);
  uintptr_t start = (uintptr_t)addr & ~(uintptr_t)(page_size - 1);
  uintptr_t end = ((uintptr_t)addr + size + (uintptr_t)(page_size - 1)) & ~(uintptr_t)(page_size - 1);
  if (mprotect((void *)start, (size_t)(end - start), PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    gh_set_error("mprotect failed");
    return GH_ERR_PROTECT;
  }
  (void)old_prot_out;
  return GH_OK;
#endif
}

static gh_status gh_restore_prot(void *addr, size_t size, int old_prot) {
#if GH_PLATFORM_WINDOWS
  DWORD tmp = 0;
  if (!VirtualProtect(addr, size, (DWORD)old_prot, &tmp)) {
    gh_set_error("VirtualProtect restore failed");
    return GH_ERR_PROTECT;
  }
  return GH_OK;
#else
  (void)addr; (void)size; (void)old_prot;
  return GH_OK;
#endif
}

static void *gh_alloc_exec(size_t size) {
#if GH_PLATFORM_WINDOWS
  return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
  void *p = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (p == MAP_FAILED) return NULL;
  return p;
#endif
}

static void gh_free_exec(void *p, size_t size) {
#if GH_PLATFORM_WINDOWS
  (void)size;
  VirtualFree(p, 0, MEM_RELEASE);
#else
  munmap(p, size);
#endif
}

gh_status gh_init_hook(gh_hook *hook, void *target, void *replacement) {
  if (!hook || !target || !replacement) {
    gh_set_error("invalid args");
    return GH_ERR_INVALID_ARG;
  }

  memset(hook, 0, sizeof(*hook));
  hook->target = target;
  hook->replacement = replacement;
  hook->patch_size = GH_PATCH_SIZE;

  memcpy(hook->original, target, hook->patch_size);

  hook->trampoline = gh_alloc_exec(hook->patch_size + GH_PATCH_SIZE);
  if (!hook->trampoline) {
    gh_set_error("trampoline alloc failed");
    return GH_ERR_ALLOC;
  }

  memcpy(hook->trampoline, hook->original, hook->patch_size);
  gh_write_abs_jump((unsigned char *)hook->trampoline + hook->patch_size,
                    (unsigned char *)hook->target + hook->patch_size,
                    (unsigned char *)hook->trampoline + hook->patch_size);

  return GH_OK;
}

gh_status gh_enable_hook(gh_hook *hook) {
  if (!hook || !hook->target || !hook->replacement) {
    gh_set_error("invalid args");
    return GH_ERR_INVALID_ARG;
  }
  if (hook->enabled) {
    gh_set_error("already enabled");
    return GH_ERR_STATE;
  }

  unsigned char patch[GH_PATCH_SIZE];
  gh_write_abs_jump(NULL, hook->replacement, patch);

  int old_prot = 0;
  gh_status st = gh_protect_rwxa(hook->target, hook->patch_size, &old_prot);
  if (st != GH_OK) return st;

  memcpy(hook->target, patch, hook->patch_size);

  st = gh_restore_prot(hook->target, hook->patch_size, old_prot);
  if (st != GH_OK) return st;

  hook->enabled = 1;
  return GH_OK;
}

gh_status gh_disable_hook(gh_hook *hook) {
  if (!hook || !hook->target) {
    gh_set_error("invalid args");
    return GH_ERR_INVALID_ARG;
  }
  if (!hook->enabled) {
    gh_set_error("not enabled");
    return GH_ERR_STATE;
  }

  int old_prot = 0;
  gh_status st = gh_protect_rwxa(hook->target, hook->patch_size, &old_prot);
  if (st != GH_OK) return st;

  memcpy(hook->target, hook->original, hook->patch_size);

  st = gh_restore_prot(hook->target, hook->patch_size, old_prot);
  if (st != GH_OK) return st;

  hook->enabled = 0;
  return GH_OK;
}

gh_status gh_destroy_hook(gh_hook *hook) {
  if (!hook) {
    gh_set_error("invalid args");
    return GH_ERR_INVALID_ARG;
  }
  if (hook->enabled) {
    gh_status st = gh_disable_hook(hook);
    if (st != GH_OK) return st;
  }
  if (hook->trampoline) {
    gh_free_exec(hook->trampoline, hook->patch_size + GH_PATCH_SIZE);
    hook->trampoline = NULL;
  }
  return GH_OK;
}

#endif /* GELHOOK_IMPLEMENTATION */

#endif /* GELHOOK_H */
