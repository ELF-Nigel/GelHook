#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
  #include <windows.h>
#else
  #include <sys/mman.h>
  #include <unistd.h>
#endif

#define GELHOOK_IMPLEMENTATION
#include "../gelhook.h"

#if defined(_MSC_VER)
  #define GH_NOINLINE __declspec(noinline)
#else
  #define GH_NOINLINE __attribute__((noinline))
#endif

static GH_NOINLINE int target(int x) {
  return x + 1;
}

typedef int (*target_fn)(int);
static target_fn g_trampoline = NULL;

static int replacement(int x) {
  if (g_trampoline) return g_trampoline(x) + 10;
  return x;
}

static void gh_make_writable(void *addr, size_t size) {
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

int main(void) {
  gh_hook hook;
  if (gh_init_hook(&hook, (void *)target, (void *)replacement) != GH_OK) {
    printf("init failed: %s\n", gh_last_error());
    return 1;
  }

  g_trampoline = (target_fn)gh_get_trampoline(&hook);

  if (gh_enable_hook(&hook) != GH_OK) {
    printf("enable failed: %s\n", gh_last_error());
    return 1;
  }

  printf("hooked target(5) => %d\n", target(5));

  gh_make_writable((void *)target, hook.stolen_len);
  memcpy((void *)target, hook.original, hook.stolen_len);

  printf("after overwrite target(5) => %d\n", target(5));

  if (gh_rehook(&hook) != GH_OK) {
    printf("rehook failed: %s\n", gh_last_error());
    return 1;
  }

  printf("rehooked target(5) => %d\n", target(5));

  gh_disable_hook(&hook);
  gh_destroy_hook(&hook);
  return 0;
}
