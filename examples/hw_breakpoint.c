#include <windows.h>
#include <stdio.h>

#define GELHOOK_IMPLEMENTATION
#include "../gelhook.h"


static volatile LONG g_hits = 0;
static HANDLE g_start_evt = NULL;

static int target(int x) {
  return x + 42;
}

static void on_hw_break(void *ip, void *user) {
  (void)user;
  InterlockedIncrement(&g_hits);
  printf("hw breakpoint hit at %p (hits=%ld)\n", ip, g_hits);
}

static DWORD WINAPI worker_thread(LPVOID param) {
  (void)param;
  WaitForSingleObject(g_start_evt, INFINITE);
  for (int i = 0; i < 5; ++i) {
    int v = target(i);
    printf("worker target(%d) => %d\n", i, v);
    Sleep(100);
  }
  return 0;
}

int main(void) {
  gh_set_log_level(GH_LOG_DEBUG);
  g_start_evt = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (!g_start_evt) return 1;

  HANDLE th = CreateThread(NULL, 0, worker_thread, NULL, 0, NULL);
  if (!th) return 1;

  gh_hw_breakpoint bp;
  if (gh_hw_breakpoint_add(&bp, (void *)target, th, on_hw_break, NULL) != GH_OK) {
    printf("hw breakpoint add failed: %s\n", gh_last_error());
    return 1;
  }

  SetEvent(g_start_evt);
  WaitForSingleObject(th, INFINITE);

  gh_hw_breakpoint_remove(&bp);
  CloseHandle(th);
  CloseHandle(g_start_evt);
  return 0;
}
