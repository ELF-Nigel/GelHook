#include <stdio.h>

#define GELHOOK_IMPLEMENTATION
#include "../gelhook.h"


#if defined(_MSC_VER)
  #define GH_NOINLINE __declspec(noinline)
#else
  #define GH_NOINLINE __attribute__((noinline))
#endif

static GH_NOINLINE int target(int x) {
  return x * 2;
}

static void on_break(void *ip, void *user) {
  (void)user;
  printf("breakpoint hit at %p\n", ip);
}

int main(void) {
  gh_set_log_level(GH_LOG_DEBUG);
  gh_breakpoint bp;
  if (gh_breakpoint_add(&bp, (void *)target, on_break, NULL) != GH_OK) {
    printf("bp add failed: %s\n", gh_last_error());
    return 1;
  }

  int v = target(7);
  printf("target(7) => %d\n", v);

  gh_breakpoint_remove(&bp);
  return 0;
}
