#include <stdio.h>

#if defined(_WIN32)
  #include <windows.h>
  #define GH_EXPORT __declspec(dllexport)
#else
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
static gh_hook g_hook;
static target_fn g_trampoline = NULL;

static GH_NOINLINE int ghpy_target(int x) {
  return x + 1;
}

static int ghpy_replacement(int x) {
  if (g_trampoline) return g_trampoline(x) + 10;
  return x;
}

GH_EXPORT int ghpy_call(int x) {
  return ghpy_target(x);
}

GH_EXPORT int ghpy_install_hook(void) {
  if (gh_init_hook(&g_hook, (void *)ghpy_target, (void *)ghpy_replacement) != GH_OK) {
    return -1;
  }
  g_trampoline = (target_fn)gh_get_trampoline(&g_hook);
  if (gh_enable_hook(&g_hook) != GH_OK) {
    return -2;
  }
  return 0;
}

GH_EXPORT int ghpy_uninstall_hook(void) {
  gh_disable_hook(&g_hook);
  gh_destroy_hook(&g_hook);
  return 0;
}
