#include <stdio.h>

#define GELHOOK_IMPLEMENTATION
#include "../gelhook.h"

typedef int (*puts_fn)(const char *);
static puts_fn g_puts = NULL;

static int replacement_puts(const char *s) {
  if (g_puts) {
    g_puts("[hooked] " );
    return g_puts(s);
  }
  return 0;
}

int main(void) {
  if (gh_plt_hook("puts", (void *)replacement_puts, (void **)&g_puts) != GH_OK) {
    printf("plt hook failed: %s\n", gh_last_error());
    return 1;
  }

  puts("hello from plt hook");
  return 0;
}
