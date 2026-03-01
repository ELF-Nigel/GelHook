#include <windows.h>
#include <stdio.h>

#define GELHOOK_IMPLEMENTATION
#include "../gelhook.h"

__declspec(dllexport) int exported_add(int x) {
  return x + 3;
}

static int replacement_add(int x) {
  return x + 300;
}

int main(void) {
  void *orig = NULL;
  if (gh_eat_hook(NULL, "exported_add", (void *)replacement_add, &orig) != GH_OK) {
    printf("eat hook failed: %s\n", gh_last_error());
    return 1;
  }

  HMODULE h = GetModuleHandleA(NULL);
  int (*fn)(int) = (int (*)(int))GetProcAddress(h, "exported_add");
  if (!fn) {
    printf("GetProcAddress failed\n");
    return 1;
  }

  printf("exported_add(5) => %d\n", fn(5));
  return 0;
}
