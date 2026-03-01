#include <windows.h>
#include <stdio.h>

#define GELHOOK_IMPLEMENTATION
#include "../gelhook.h"


typedef int (WINAPI *msgbox_fn)(HWND, LPCSTR, LPCSTR, UINT);
static msgbox_fn g_msgbox = NULL;

static int WINAPI replacement_msgbox(HWND hWnd, LPCSTR text, LPCSTR caption, UINT type) {
  if (g_msgbox) {
    return g_msgbox(hWnd, "[hooked]", caption, type);
  }
  return 0;
}

int main(void) {
  gh_set_log_level(GH_LOG_DEBUG);
  if (gh_iat_hook(NULL, "user32.dll", "MessageBoxA", (void *)replacement_msgbox, (void **)&g_msgbox) != GH_OK) {
    printf("iat hook failed: %s\n", gh_last_error());
    return 1;
  }

  MessageBoxA(NULL, "original", "GelHook", MB_OK);
  return 0;
}
