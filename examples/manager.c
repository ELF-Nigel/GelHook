#include <stdio.h>

#define GELHOOK_IMPLEMENTATION
#include "../gelhook.h"

static int a(int x) { return x + 1; }
static int b(int x) { return x + 2; }

static int ra(int x) { return x + 10; }
static int rb(int x) { return x + 20; }

int main(void) {
  gh_hook ha, hb;
  gh_hook_options opts = {1, 1, 1, 1, GH_MAX_STOLEN};

  if (gh_init_hook_ex(&ha, (void *)a, (void *)ra, &opts) != GH_OK) {
    printf("init a failed: %s\n", gh_last_error());
    return 1;
  }
  if (gh_init_hook_ex(&hb, (void *)b, (void *)rb, &opts) != GH_OK) {
    printf("init b failed: %s\n", gh_last_error());
    return 1;
  }

  gh_hook_manager mgr;
  if (gh_manager_init(&mgr, 2) != GH_OK) {
    printf("mgr init failed\n");
    return 1;
  }
  gh_manager_add(&mgr, &ha);
  gh_manager_add(&mgr, &hb);

  if (gh_manager_enable_all_atomic(&mgr, &opts) != GH_OK) {
    printf("enable atomic failed: %s\n", gh_last_error());
    return 1;
  }

  printf("a(1) => %d, b(1) => %d\n", a(1), b(1));

  gh_manager_disable_all(&mgr);
  gh_manager_destroy(&mgr);
  return 0;
}
