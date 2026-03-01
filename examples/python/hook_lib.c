#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
  #include <windows.h>
  #define GH_EXPORT __declspec(dllexport)
#else
  #include <sys/mman.h>
  #include <unistd.h>
  #define GH_EXPORT __attribute__((visibility("default")))
#endif

#define GELHOOK_IMPLEMENTATION
#include "../../gelhook.h"

#if defined(_MSC_VER)
  #pragma comment(lib, "dbghelp.lib")
#endif

#if defined(_MSC_VER)
  #define GH_NOINLINE __declspec(noinline)
#else
  #define GH_NOINLINE __attribute__((noinline))
#endif

typedef int (*target_fn)(int);

static gh_hook g_inline_hook;
static gh_hook g_site_hook;
static target_fn g_trampoline_a = NULL;
static target_fn g_trampoline_b = NULL;

static GH_NOINLINE int ghpy_target_a(int x) { return x + 1; }
static GH_NOINLINE int ghpy_target_b(int x) { return x + 2; }

static int ghpy_replacement_a(int x) {
  if (g_trampoline_a) return g_trampoline_a(x) + 10;
  return x;
}

static int ghpy_replacement_b(int x) {
  if (g_trampoline_b) return g_trampoline_b(x) + 20;
  return x;
}

static void ghpy_make_writable(void *addr, size_t size) {
#if defined(_WIN32)
  DWORD oldp = 0;
  VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldp);
#else
  long ps = sysconf(_SC_PAGESIZE);
  uintptr_t start = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
  uintptr_t end = ((uintptr_t)addr + size + (uintptr_t)(ps - 1)) & ~(uintptr_t)(ps - 1);
  mprotect((void *)start, (size_t)(end - start), PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
}

GH_EXPORT void ghpy_init(int log_level) {
  gh_set_log_level((gh_log_level)log_level);
}

GH_EXPORT int ghpy_call_a(int x) { return ghpy_target_a(x); }
GH_EXPORT int ghpy_call_b(int x) { return ghpy_target_b(x); }

GH_EXPORT int ghpy_install_inline(void) {
  gh_hook_options opts = {1, 1, 1, 1, GH_MAX_STOLEN};
  if (gh_init_hook_ex(&g_inline_hook, (void *)ghpy_target_a, (void *)ghpy_replacement_a, &opts) != GH_OK) {
    return -1;
  }
  g_trampoline_a = (target_fn)gh_get_trampoline(&g_inline_hook);
  if (gh_enable_hook(&g_inline_hook) != GH_OK) return -2;
  return 0;
}

GH_EXPORT int ghpy_install_site(void) {
  gh_hook_options opts = {1, 1, 1, 1, GH_MAX_STOLEN};
  if (gh_init_hook_at(&g_site_hook, (void *)ghpy_target_b, (void *)ghpy_replacement_b, GH_REL_JMP_SIZE, &opts) != GH_OK) {
    return -1;
  }
  g_trampoline_b = (target_fn)gh_get_trampoline(&g_site_hook);
  if (gh_enable_hook(&g_site_hook) != GH_OK) return -2;
  return 0;
}

GH_EXPORT int ghpy_rehook_inline(void) {
  if (!g_inline_hook.enabled) return -1;
  ghpy_make_writable((void *)g_inline_hook.target, g_inline_hook.stolen_len);
  memcpy((void *)g_inline_hook.target, g_inline_hook.original, g_inline_hook.stolen_len);
  return (gh_rehook(&g_inline_hook) == GH_OK) ? 0 : -2;
}

GH_EXPORT int ghpy_uninstall_all(void) {
  if (g_inline_hook.enabled) {
    gh_disable_hook(&g_inline_hook);
    gh_destroy_hook(&g_inline_hook);
  }
  if (g_site_hook.enabled) {
    gh_disable_hook(&g_site_hook);
    gh_destroy_hook(&g_site_hook);
  }
  g_trampoline_a = NULL;
  g_trampoline_b = NULL;
  return 0;
}
