// Process and clock helpers for netwhere (Win32, no elevation required).
#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <sddl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "moonbit.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

static moonbit_string_t wide_to_mbt(const WCHAR *s, int n) {
  moonbit_string_t m = moonbit_make_string(n, 0);
  memcpy(m, s, (size_t)n * 2);
  return m;
}

static WCHAR *mbt_to_wide(moonbit_string_t s) {
  int32_t n = Moonbit_array_length(s);
  WCHAR *buf = (WCHAR *)malloc(((size_t)n + 1) * 2);
  if (!buf) return NULL;
  memcpy(buf, s, (size_t)n * 2);
  buf[n] = 0;
  return buf;
}

// Drive-letter image path of a process, or "" when it cannot be opened.
moonbit_string_t nw_image_path(int32_t pid) {
  WCHAR buf[1024];
  DWORD n = 1024;
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
  if (!h) return moonbit_make_string(0, 0);
  BOOL ok = QueryFullProcessImageNameW(h, 0, buf, &n);
  CloseHandle(h);
  return ok ? wide_to_mbt(buf, (int)n) : moonbit_make_string(0, 0);
}

static int token_info(HANDLE proc, int *elevated, WCHAR *sid_out, size_t sid_cap) {
  HANDLE tok;
  if (!OpenProcessToken(proc, TOKEN_QUERY, &tok)) return 0;
  int ok = 1;
  if (elevated) {
    TOKEN_ELEVATION e;
    DWORD n;
    if (GetTokenInformation(tok, TokenElevation, &e, sizeof e, &n)) *elevated = e.TokenIsElevated ? 1 : 0;
    else ok = 0;
  }
  if (sid_out) {
    BYTE buf[256];
    DWORD n;
    sid_out[0] = 0;
    if (GetTokenInformation(tok, TokenUser, buf, sizeof buf, &n)) {
      LPWSTR s = NULL;
      if (ConvertSidToStringSidW(((TOKEN_USER *)buf)->User.Sid, &s)) {
        wcsncpy(sid_out, s, sid_cap - 1);
        sid_out[sid_cap - 1] = 0;
        LocalFree(s);
      } else ok = 0;
    } else ok = 0;
  }
  CloseHandle(tok);
  return ok;
}

// 1 elevated, 0 not, -1 unknown.
int32_t nw_is_elevated(void) {
  int e = -1;
  return token_info(GetCurrentProcess(), &e, NULL, 0) ? e : -1;
}

// 1 elevated, 0 not, -1 cannot open the process or its token.
int32_t nw_process_elevated(int32_t pid) {
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
  if (!h) return -1;
  int e = -1;
  int ok = token_info(h, &e, NULL, 0);
  CloseHandle(h);
  return ok ? e : -1;
}

// String SID of the process owner ("S-1-5-21-..."), or "".
moonbit_string_t nw_process_user_sid(int32_t pid) {
  HANDLE h = pid == 0 ? GetCurrentProcess()
                      : OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
  if (!h) return moonbit_make_string(0, 0);
  WCHAR sid[256];
  int ok = token_info(h, NULL, sid, 256);
  if (pid != 0) CloseHandle(h);
  return ok ? wide_to_mbt(sid, (int)wcslen(sid)) : moonbit_make_string(0, 0);
}

// Process creation time (FILETIME ticks), or 0.
int64_t nw_process_create_time(int32_t pid) {
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
  if (!h) return 0;
  FILETIME c, x, k, u;
  int64_t r = 0;
  if (GetProcessTimes(h, &c, &x, &k, &u)) r = ((int64_t)c.dwHighDateTime << 32) | c.dwLowDateTime;
  CloseHandle(h);
  return r;
}

int32_t nw_current_pid(void) { return (int32_t)GetCurrentProcessId(); }

// Current UTC time as FILETIME ticks (100 ns since 1601).
int64_t nw_now_filetime(void) {
  FILETIME ft;
  GetSystemTimePreciseAsFileTime(&ft);
  return ((int64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

// Offset of local time from UTC in minutes (for display only).
int32_t nw_utc_offset_minutes(void) {
  TIME_ZONE_INFORMATION tz;
  DWORD r = GetTimeZoneInformation(&tz);
  LONG bias = tz.Bias;
  if (r == TIME_ZONE_ID_DAYLIGHT) bias += tz.DaylightBias;
  else if (r == TIME_ZONE_ID_STANDARD) bias += tz.StandardBias;
  return (int32_t)-bias;
}

void nw_sleep_ms(int32_t ms) { Sleep((DWORD)ms); }

// out: cpu ms (user+kernel), private bytes, working set, peak working set
void nw_self_usage(int64_t *out) {
  FILETIME c, x, k, u;
  GetProcessTimes(GetCurrentProcess(), &c, &x, &k, &u);
  ULARGE_INTEGER kk, uu;
  kk.LowPart = k.dwLowDateTime; kk.HighPart = k.dwHighDateTime;
  uu.LowPart = u.dwLowDateTime; uu.HighPart = u.dwHighDateTime;
  out[0] = (int64_t)((kk.QuadPart + uu.QuadPart) / 10000);
  PROCESS_MEMORY_COUNTERS_EX pmc;
  memset(&pmc, 0, sizeof pmc);
  GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pmc, sizeof pmc);
  out[1] = (int64_t)pmc.PrivateUsage;
  out[2] = (int64_t)pmc.WorkingSetSize;
  out[3] = (int64_t)pmc.PeakWorkingSetSize;
}

// ---------------------------------------------------------------- child process
// One child at a time (trace runs one command). The child inherits this
// process's environment and console, and starts suspended so the collector
// can be told its pid before it makes any connection.

static HANDLE g_child = NULL;
static HANDLE g_child_thread = NULL;

// Returns the child pid, or -(Win32 error).
int32_t nw_spawn_suspended(moonbit_string_t cmdline) {
  WCHAR *buf = mbt_to_wide(cmdline);
  if (!buf) return -(int32_t)ERROR_OUTOFMEMORY;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof si);
  si.cb = sizeof si;
  memset(&pi, 0, sizeof pi);
  BOOL ok = CreateProcessW(NULL, buf, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
  free(buf);
  if (!ok) return -(int32_t)GetLastError();
  if (g_child) CloseHandle(g_child);
  if (g_child_thread) CloseHandle(g_child_thread);
  g_child = pi.hProcess;
  g_child_thread = pi.hThread;
  return (int32_t)pi.dwProcessId;
}

int32_t nw_resume_child(void) {
  if (!g_child_thread) return -1;
  DWORD r = ResumeThread(g_child_thread);
  CloseHandle(g_child_thread);
  g_child_thread = NULL;
  return r == (DWORD)-1 ? -(int32_t)GetLastError() : 0;
}

void nw_kill_child(void) {
  if (g_child) TerminateProcess(g_child, 1);
}

// 0 = exited, 1 = still running (after waiting up to ms)
int32_t nw_child_wait(int32_t ms) {
  if (!g_child) return 0;
  return WaitForSingleObject(g_child, (DWORD)ms) == WAIT_OBJECT_0 ? 0 : 1;
}

int32_t nw_child_exit_code(void) {
  DWORD code = 0;
  if (g_child) GetExitCodeProcess(g_child, &code);
  return (int32_t)code;
}

// Returns the raw command line of this process (for argument re-quoting).
moonbit_string_t nw_command_line(void) {
  LPWSTR s = GetCommandLineW();
  return wide_to_mbt(s, (int)wcslen(s));
}

// Value of an environment variable, or "" if unset.
moonbit_string_t nw_getenv(moonbit_string_t name) {
  WCHAR *n = mbt_to_wide(name);
  if (!n) return moonbit_make_string(0, 0);
  WCHAR buf[4096];
  DWORD r = GetEnvironmentVariableW(n, buf, 4096);
  free(n);
  if (r == 0 || r >= 4096) return moonbit_make_string(0, 0);
  return wide_to_mbt(buf, (int)r);
}
