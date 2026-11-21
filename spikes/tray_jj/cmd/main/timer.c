// A thread timer so a blocking tray pump wakes up periodically without
// polling: WM_TIMER with a NULL hwnd lands in this thread's queue.
#include <moonbit.h>
#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

MOONBIT_FFI_EXPORT void nwt_start_timer(int32_t ms) { SetTimer(NULL, 0, (UINT)ms, NULL); }

MOONBIT_FFI_EXPORT uint64_t nwt_now_ms(void) { return GetTickCount64(); }
