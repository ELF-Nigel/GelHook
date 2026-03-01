#include <stdio.h>

#define GELHOOK_IMPLEMENTATION
#include "../gelhook.h"

#if defined(_MSC_VER)
  #define GH_NOINLINE __declspec(noinline)
#else
  #define GH_NOINLINE __attribute__((noinline))
#endif

typedef int (*target_fn)(int);
static target_fn g_trampoline = NULL;

static GH_NOINLINE int target(int x) {
  return x + 1;
}

static int replacement(int x) {
  printf("replacement(%d)\n", x);
  if (g_trampoline) {
    int orig = g_trampoline(x);
    return orig + 10;
  }
  return x;
}

int main(void) {
  gh_set_log_level(GH_LOG_DEBUG);
  gh_hook hook;
  if (gh_init_hook(&hook, (void *)target, (void *)replacement) != GH_OK) {
    printf("init failed: %s\n", gh_last_error());
    return 1;
  }

  g_trampoline = (target_fn)hook.trampoline;

  if (gh_enable_hook(&hook) != GH_OK) {
    printf("enable failed: %s\n", gh_last_error());
    return 1;
  }

  printf("target(5) => %d\n", target(5));

  gh_disable_hook(&hook);
  gh_destroy_hook(&hook);
  return 0;
}
