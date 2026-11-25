// The UI's top-level window. The message loop is pumped from MoonBit one
// message at a time so it can resize the WebView and close it before the
// window goes away. One window per user session: a second start brings the
// first to the front and exits.
#include <moonbit.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dwmapi.h>

static HWND ui_window = NULL;
static int32_t resize_w = 0, resize_h = 0, resize_pending = 0;
static int32_t close_pending = 0;
static int32_t min_w = 860, min_h = 560;
static const WCHAR *ui_class = L"NetwhereUiWindow";

static WCHAR *to_wide(moonbit_string_t s) {
  int32_t n = Moonbit_array_length(s);
  WCHAR *w = (WCHAR *)malloc(((size_t)n + 1) * sizeof(WCHAR));
  if (!w) return NULL;
  memcpy(w, s, (size_t)n * sizeof(WCHAR));
  w[n] = 0;
  return w;
}

static int system_dark(void) {
  DWORD v = 1, size = sizeof v;
  if (RegGetValueW(HKEY_CURRENT_USER,
                   L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                   L"AppsUseLightTheme", RRF_RT_REG_DWORD, NULL, &v, &size) != ERROR_SUCCESS)
    return 0;
  return v == 0;
}

static void apply_title_theme(HWND hwnd) {
  BOOL dark = system_dark() ? TRUE : FALSE;
  // DWMWA_USE_IMMERSIVE_DARK_MODE
  DwmSetWindowAttribute(hwnd, 20, &dark, sizeof dark);
}

static LRESULT CALLBACK ui_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
  case WM_SIZE:
    resize_w = LOWORD(lp);
    resize_h = HIWORD(lp);
    resize_pending = 1;
    return 0;
  case WM_GETMINMAXINFO: {
    UINT dpi = GetDpiForWindow(hwnd);
    MINMAXINFO *mm = (MINMAXINFO *)lp;
    mm->ptMinTrackSize.x = MulDiv(min_w, dpi ? dpi : 96, 96);
    mm->ptMinTrackSize.y = MulDiv(min_h, dpi ? dpi : 96, 96);
    return 0;
  }
  case WM_SETTINGCHANGE:
    apply_title_theme(hwnd);
    break;
  case WM_CLOSE:
    // MoonBit destroys the WebView first, then the window.
    close_pending = 1;
    return 0;
  case WM_DESTROY:
    ui_window = NULL;
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

// Brings an existing UI window to the front. 1 when there was one.
MOONBIT_FFI_EXPORT int32_t nwu_activate_existing(void) {
  HANDLE m = CreateMutexW(NULL, TRUE, L"Local\\netwhere-ui");
  if (m == NULL || GetLastError() != ERROR_ALREADY_EXISTS) return 0;
  for (int i = 0; i < 20; i++) {
    HWND h = FindWindowW(ui_class, NULL);
    if (h) {
      if (IsIconic(h)) ShowWindow(h, SW_RESTORE);
      SetForegroundWindow(h);
      return 1;
    }
    Sleep(100); // the first instance may still be creating its window
  }
  return 1;
}

// Creates and shows the window, centred, `width` × `height` at 96 dpi.
MOONBIT_FFI_EXPORT uint64_t nwu_create(int32_t width, int32_t height, moonbit_string_t icon_path) {
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  HINSTANCE inst = GetModuleHandleW(NULL);
  int dark = system_dark();
  WCHAR *icon = to_wide(icon_path);
  HICON icon_big = NULL, icon_small = NULL;
  if (icon && icon[0]) {
    icon_big = (HICON)LoadImageW(NULL, icon, IMAGE_ICON, GetSystemMetrics(SM_CXICON),
                            GetSystemMetrics(SM_CYICON), LR_LOADFROMFILE);
    icon_small = (HICON)LoadImageW(NULL, icon, IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),
                              GetSystemMetrics(SM_CYSMICON), LR_LOADFROMFILE);
  }
  free(icon);
  WNDCLASSEXW wc = {0};
  wc.cbSize = sizeof wc;
  wc.hInstance = inst;
  wc.lpszClassName = ui_class;
  wc.lpfnWndProc = ui_proc;
  wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
  wc.hbrBackground = CreateSolidBrush(dark ? RGB(0x14, 0x14, 0x13) : RGB(0xf6, 0xf6, 0xf4));
  wc.hIcon = icon_big;
  wc.hIconSm = icon_small;
  RegisterClassExW(&wc);
  UINT dpi = GetDpiForSystem();
  int w = MulDiv(width, dpi, 96), h = MulDiv(height, dpi, 96);
  RECT work;
  SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
  int ww = work.right - work.left, wh = work.bottom - work.top;
  if (w > ww) w = ww;
  if (h > wh) h = wh;
  HWND hwnd = CreateWindowExW(0, ui_class, L"netwhere", WS_OVERLAPPEDWINDOW,
                              work.left + (ww - w) / 2, work.top + (wh - h) / 2, w, h,
                              NULL, NULL, inst, NULL);
  if (!hwnd) return 0;
  ui_window = hwnd;
  apply_title_theme(hwnd);
  ShowWindow(hwnd, SW_SHOW);
  SetForegroundWindow(hwnd);
  return (uint64_t)(uintptr_t)hwnd;
}

// Client size packed as (w << 16) | h.
MOONBIT_FFI_EXPORT int32_t nwu_client_size(void) {
  RECT r = {0};
  if (ui_window) GetClientRect(ui_window, &r);
  return ((r.right - r.left) << 16) | ((r.bottom - r.top) & 0xffff);
}

// Pumps one message. Returns 0 after WM_QUIT, -1 when GetMessage fails.
MOONBIT_FFI_EXPORT int32_t nwu_pump(void) {
  MSG m;
  BOOL r = GetMessageW(&m, NULL, 0, 0);
  if (r == 0) return 0;
  if (r < 0) return -1;
  TranslateMessage(&m);
  DispatchMessageW(&m);
  return 1;
}

// Pending resize packed like nwu_client_size, or -1.
MOONBIT_FFI_EXPORT int32_t nwu_take_resize(void) {
  if (!resize_pending) return -1;
  resize_pending = 0;
  return (resize_w << 16) | (resize_h & 0xffff);
}

MOONBIT_FFI_EXPORT int32_t nwu_take_close(void) {
  int32_t c = close_pending;
  close_pending = 0;
  return c;
}

MOONBIT_FFI_EXPORT void nwu_destroy(void) {
  if (ui_window) DestroyWindow(ui_window);
}

MOONBIT_FFI_EXPORT void nwu_message_box(moonbit_string_t text) {
  WCHAR *w = to_wide(text);
  if (!w) return;
  MessageBoxW(ui_window, w, L"netwhere", MB_OK | MB_ICONWARNING);
  free(w);
}
