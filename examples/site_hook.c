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
  return x + 2;
}

static int replacement(int x) {
  if (g_trampoline) return g_trampoline(x) + 20;
  return x;
}

int main(void) {
  gh_hook hook;
  gh_hook_options opts = {1, 1, 1, 1, GH_MAX_STOLEN};

  if (gh_init_hook_at(&hook, (void *)target, (void *)replacement, GH_REL_JMP_SIZE, &opts) != GH_OK) {
    printf("init failed: %s\n", gh_last_error());
    return 1;
  }

  g_trampoline = (target_fn)gh_get_trampoline(&hook);

  if (gh_enable_hook(&hook) != GH_OK) {
    printf("enable failed: %s\n", gh_last_error());
    return 1;
  }

  printf("target(5) => %d\n", target(5));

  gh_disable_hook(&hook);
  gh_destroy_hook(&hook);
  return 0;
}
