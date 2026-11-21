// Top-level window for the WebView probe. The message loop is pumped from
// MoonBit one message at a time so it can react to resize and close.
#include <moonbit.h>
#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static HWND host_window = NULL;
static int32_t host_resize_w = 0, host_resize_h = 0, host_resize_pending = 0;
static int32_t host_close_pending = 0;

static LRESULT CALLBACK host_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
  case WM_SIZE:
    host_resize_w = LOWORD(lp);
    host_resize_h = HIWORD(lp);
    host_resize_pending = 1;
    return 0;
  case WM_TIMER:
  case WM_CLOSE:
    // MoonBit destroys the WebView first, then the window.
    host_close_pending = 1;
    return 0;
  case WM_DESTROY:
    host_window = NULL;
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

MOONBIT_FFI_EXPORT uint64_t nwp_host_create(int32_t width, int32_t height,
                                             int32_t auto_close_ms) {
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  HINSTANCE inst = GetModuleHandleW(NULL);
  WNDCLASSW wc = {0};
  wc.hInstance = inst;
  wc.lpszClassName = L"NetwhereProbeHost";
  wc.lpfnWndProc = host_wndproc;
  wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
  wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
  RegisterClassW(&wc);
  HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"netwhere 探针",
                              WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                              width, height, NULL, NULL, inst, NULL);
  if (!hwnd) return 0;
  host_window = hwnd;
  ShowWindow(hwnd, SW_SHOW);
  if (auto_close_ms > 0) SetTimer(hwnd, 1, (UINT)auto_close_ms, NULL);
  return (uint64_t)(uintptr_t)hwnd;
}

// Client size packed as (w << 16) | h.
MOONBIT_FFI_EXPORT int32_t nwp_host_client_size(void) {
  RECT r = {0};
  if (host_window) GetClientRect(host_window, &r);
  return ((r.right - r.left) << 16) | ((r.bottom - r.top) & 0xffff);
}

// Pumps one message. Returns 0 after WM_QUIT.
MOONBIT_FFI_EXPORT int32_t nwp_host_pump(void) {
  MSG m;
  if (GetMessageW(&m, NULL, 0, 0) <= 0) return 0;
  TranslateMessage(&m);
  DispatchMessageW(&m);
  return 1;
}

// Pending resize packed like nwp_host_client_size, or -1.
MOONBIT_FFI_EXPORT int32_t nwp_host_take_resize(void) {
  if (!host_resize_pending) return -1;
  host_resize_pending = 0;
  return (host_resize_w << 16) | (host_resize_h & 0xffff);
}

MOONBIT_FFI_EXPORT int32_t nwp_host_take_close(void) {
  int32_t c = host_close_pending;
  host_close_pending = 0;
  return c;
}

MOONBIT_FFI_EXPORT void nwp_host_destroy(void) {
  if (host_window) {
    KillTimer(host_window, 1);
    DestroyWindow(host_window);
  }
}

MOONBIT_FFI_EXPORT uint64_t nwp_now_us(void) {
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&c);
  return (uint64_t)(c.QuadPart * 1000000 / f.QuadPart);
}
