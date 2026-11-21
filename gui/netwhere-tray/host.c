// Win32 pieces the tray library does not cover: a single-instance guard, a
// hidden top-level window that receives the 5-second timer and Explorer's
// "TaskbarCreated" broadcast (the library's message-only window gets no
// broadcasts, so its icon would vanish when Explorer restarts), and small
// helpers around the UI window.
#include <moonbit.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static UINT taskbar_created = 0;
static int32_t pending = 0; // 1: timer, 2: taskbar re-created, 4: end session
static HANDLE instance_mutex = NULL;

static WCHAR *to_wide(moonbit_string_t s) {
  int32_t n = Moonbit_array_length(s);
  WCHAR *w = (WCHAR *)malloc(((size_t)n + 1) * sizeof(WCHAR));
  if (!w) return NULL;
  memcpy(w, s, (size_t)n * sizeof(WCHAR));
  w[n] = 0;
  return w;
}

static LRESULT CALLBACK host_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  if (taskbar_created != 0 && msg == taskbar_created) {
    pending |= 2;
    return 0;
  }
  switch (msg) {
  case WM_TIMER:
    pending |= 1;
    return 0;
  case WM_ENDSESSION:
    if (wp) pending |= 4;
    return 0;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

// 1 when this is the only tray of this user session, 0 otherwise.
MOONBIT_FFI_EXPORT int32_t nwt_single_instance(void) {
  instance_mutex = CreateMutexW(NULL, TRUE, L"Local\\netwhere-tray");
  if (instance_mutex == NULL) return 1;
  return GetLastError() == ERROR_ALREADY_EXISTS ? 0 : 1;
}

// Hidden top-level window with a periodic timer. Returns 1 on success.
MOONBIT_FFI_EXPORT int32_t nwt_host_create(int32_t timer_ms) {
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
  WNDCLASSW wc = {0};
  wc.hInstance = GetModuleHandleW(NULL);
  wc.lpszClassName = L"NetwhereTrayHost";
  wc.lpfnWndProc = host_proc;
  RegisterClassW(&wc);
  HWND hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, wc.lpszClassName, L"netwhere tray", WS_POPUP,
                              0, 0, 0, 0, NULL, NULL, wc.hInstance, NULL);
  if (!hwnd) return 0;
  // Elevated windows may not send to us; Explorer is not elevated, but be
  // explicit so the broadcast passes UIPI either way.
  ChangeWindowMessageFilterEx(hwnd, taskbar_created, MSGFLT_ALLOW, NULL);
  SetTimer(hwnd, 1, (UINT)timer_ms, NULL);
  return 1;
}

// Flags set since the last call (see `pending`).
MOONBIT_FFI_EXPORT int32_t nwt_take_pending(void) {
  int32_t p = pending;
  pending = 0;
  return p;
}

// Lets the process we are about to start bring its window to the front.
MOONBIT_FFI_EXPORT void nwt_allow_foreground(void) { AllowSetForegroundWindow(ASFW_ANY); }

// Asks an open UI window to close. Returns 1 when one was found.
MOONBIT_FFI_EXPORT int32_t nwt_close_ui(void) {
  HWND h = FindWindowW(L"NetwhereUiWindow", NULL);
  if (!h) return 0;
  PostMessageW(h, WM_CLOSE, 0, 0);
  return 1;
}

MOONBIT_FFI_EXPORT void nwt_message_box(moonbit_string_t text) {
  WCHAR *w = to_wide(text);
  if (!w) return;
  MessageBoxW(NULL, w, L"netwhere", MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
  free(w);
}
