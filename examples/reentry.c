#include <stdio.h>

#define GELHOOK_IMPLEMENTATION
#include "../gelhook.h"


typedef int (*target_fn)(int);
static target_fn g_trampoline = NULL;
static gh_reentry_guard g_guard = {1};

static int target(int x) { return x + 1; }

static int replacement(int x) {
  if (!gh_reentry_enter(&g_guard)) return x;
  int r = g_trampoline ? g_trampoline(x) + 5 : x;
  gh_reentry_leave(&g_guard);
  return r;
}

int main(void) {
  gh_set_log_level(GH_LOG_DEBUG);
  gh_hook hook;
  if (gh_init_hook(&hook, (void *)target, (void *)replacement) != GH_OK) {
    printf("init failed: %s\n", gh_last_error());
    return 1;
  }
  g_trampoline = (target_fn)gh_get_trampoline(&hook);
  gh_enable_hook(&hook);
  printf("target(5) => %d\n", target(5));
  gh_disable_hook(&hook);
  gh_destroy_hook(&hook);
  return 0;
}
