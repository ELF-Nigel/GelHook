#include <windows.h>
#include <stdio.h>

#define GELHOOK_IMPLEMENTATION
#include "../gelhook.h"


static int target(int x) {
  return x + 7;
}

static void on_guard(void *ip, void *user) {
  (void)user;
  printf("guard hook hit at %p\n", ip);
}

int main(void) {
  gh_set_log_level(GH_LOG_DEBUG);
  gh_guard_hook hook;
  if (gh_guard_hook_add(&hook, (void *)target, 32, on_guard, NULL) != GH_OK) {
    printf("guard hook add failed: %s\n", gh_last_error());
    return 1;
  }

  printf("target(5) => %d\n", target(5));

  gh_guard_hook_remove(&hook);
  return 0;
}
