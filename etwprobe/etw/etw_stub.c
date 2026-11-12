// etwprobe: real-time ETW consumer stub for the MoonBit C backend (MSVC, plain C).
//
// Threading model: ProcessTrace() blocks and invokes on_event() on its own thread.
// MoonBit's native runtime must not be entered from that thread, so the callback
// only decodes the event (TDH) into a compact binary record and appends it to a
// lock-protected byte queue. MoonBit polls etwprobe_drain() from its own thread.
//
// Record layout (little-endian), each prefixed by u32 payload length:
//   u8 provider (1 net, 2 dns, 3 process)  u8 version  u16 event id
//   u8 opcode  u8 flags (bit0: schema names follow)  u16 property count
//   u32 pid  u32 tid  i64 timestamp (FILETIME, 100 ns)
//   [flags&1] str16 task name, str16 opcode name, nprops x str16 property name
//   nprops x { u8 tag, u16 len, len bytes }
// Schema names are sent only with the first successfully queued record of each
// (provider, id, version); later records carry values in the same order.
#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <psapi.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "moonbit.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "psapi.lib")

#ifndef INVALID_PROCESSTRACE_HANDLE
#define INVALID_PROCESSTRACE_HANDLE ((TRACEHANDLE)INVALID_HANDLE_VALUE)
#endif

// Microsoft-Windows-Kernel-Network
static const GUID kNet = {0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};
// Microsoft-Windows-DNS-Client
static const GUID kDns = {0x1c95126e, 0x7eea, 0x49a9, {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};
// Microsoft-Windows-Kernel-Process
static const GUID kProc = {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

enum { TAG_UINT = 0, TAG_INT = 1, TAG_STR = 2, TAG_RAW = 3, TAG_IPV4 = 4, TAG_IPV6 = 5,
       TAG_PORT = 6, TAG_BOOL = 7, TAG_FILETIME = 8, TAG_GUID = 9, TAG_SOCKADDR = 10,
       TAG_TOO_BIG = 254, TAG_STRUCT = 255 };

enum { ST_EVENTS, ST_NET, ST_DNS, ST_PROC, ST_DROPPED, ST_BYTES, ST_CB_NS, ST_MAX_QUEUE,
       ST_DECODE_FAIL, ST_STALE, ST_OTHER, ST_COUNT };

static TRACEHANDLE g_session = 0;
static TRACEHANDLE g_consumer = INVALID_PROCESSTRACE_HANDLE;
static HANDLE g_thread = NULL;
static WCHAR g_name[128];
static int g_running = 0;
static ULONG g_last_error = 0;
static const char *g_stage = "";
static unsigned char g_props_buf[sizeof(EVENT_TRACE_PROPERTIES) + 2048];

static SRWLOCK g_lock = SRWLOCK_INIT;
static uint8_t *g_queue = NULL;
static size_t g_queue_len = 0;
static size_t g_queue_cap = 0;
static volatile int64_t g_stats[ST_COUNT];
static LARGE_INTEGER g_qpf;

// ---------------------------------------------------------------- schema cache

typedef struct {
  uint32_t key;
  int failed;
  int names_sent;
  TRACE_EVENT_INFO *info;
} cache_ent;

#define CACHE_SIZE 1024
static cache_ent g_cache[CACHE_SIZE];

static cache_ent *cache_get(uint32_t key, PEVENT_RECORD r) {
  uint32_t h = (key * 2654435761u) & (CACHE_SIZE - 1);
  for (int i = 0; i < CACHE_SIZE; i++) {
    cache_ent *e = &g_cache[(h + i) & (CACHE_SIZE - 1)];
    if (e->key == key) return e;
    if (e->key == 0) {
      e->key = key;
      ULONG sz = 0;
      TDHSTATUS st = TdhGetEventInformation(r, 0, NULL, NULL, &sz);
      if (st == ERROR_INSUFFICIENT_BUFFER) {
        e->info = (TRACE_EVENT_INFO *)malloc(sz);
        st = e->info ? TdhGetEventInformation(r, 0, NULL, e->info, &sz) : ERROR_OUTOFMEMORY;
      }
      if (st != ERROR_SUCCESS) {
        free(e->info);
        e->info = NULL;
        e->failed = 1;
      }
      return e;
    }
  }
  return NULL;
}

// ---------------------------------------------------------------- record writer

typedef struct {
  uint8_t *p;
  size_t len, cap;
  int overflow;
} wbuf;

static void put(wbuf *w, const void *src, size_t n) {
  if (w->len + n > w->cap) { w->overflow = 1; return; }
  memcpy(w->p + w->len, src, n);
  w->len += n;
}
static void put_u8(wbuf *w, uint8_t v) { put(w, &v, 1); }
static void put_u16(wbuf *w, uint16_t v) { put(w, &v, 2); }
static void put_u32(wbuf *w, uint32_t v) { put(w, &v, 4); }
static void put_i64(wbuf *w, int64_t v) { put(w, &v, 8); }

// UTF-16 (n code units, may contain a trailing NUL) -> UTF-8 as u16 length + bytes.
static void put_wstr16(wbuf *w, const WCHAR *s, int n) {
  while (n > 0 && s[n - 1] == 0) n--;
  char tmp[2048];
  int m = n > 0 ? WideCharToMultiByte(CP_UTF8, 0, s, n, tmp, sizeof tmp, NULL, NULL) : 0;
  if (m < 0) m = 0;
  put_u16(w, (uint16_t)m);
  put(w, tmp, (size_t)m);
}

static const WCHAR *info_str(TRACE_EVENT_INFO *info, ULONG off) {
  return off ? (const WCHAR *)((BYTE *)info + off) : L"";
}

static uint8_t classify(USHORT in, USHORT out) {
  if (out == TDH_OUTTYPE_IPV4) return TAG_IPV4;
  if (out == TDH_OUTTYPE_IPV6) return TAG_IPV6;
  if (out == TDH_OUTTYPE_PORT) return TAG_PORT;
  if (out == TDH_OUTTYPE_SOCKETADDRESS) return TAG_SOCKADDR;
  switch (in) {
  case TDH_INTYPE_UNICODESTRING:
  case TDH_INTYPE_ANSISTRING: return TAG_STR;
  case TDH_INTYPE_INT8: case TDH_INTYPE_INT16: case TDH_INTYPE_INT32: case TDH_INTYPE_INT64:
    return TAG_INT;
  case TDH_INTYPE_UINT8: case TDH_INTYPE_UINT16: case TDH_INTYPE_UINT32: case TDH_INTYPE_UINT64:
  case TDH_INTYPE_HEXINT32: case TDH_INTYPE_HEXINT64: case TDH_INTYPE_POINTER:
  case TDH_INTYPE_SIZET:
    return TAG_UINT;
  case TDH_INTYPE_BOOLEAN: return TAG_BOOL;
  case TDH_INTYPE_FILETIME: return TAG_FILETIME;
  case TDH_INTYPE_GUID: return TAG_GUID;
  default: return TAG_RAW;
  }
}

static void enqueue(const uint8_t *rec, size_t n, int *ok) {
  *ok = 0;
  AcquireSRWLockExclusive(&g_lock);
  if (g_queue && g_queue_len + 4 + n <= g_queue_cap) {
    uint32_t len32 = (uint32_t)n;
    memcpy(g_queue + g_queue_len, &len32, 4);
    memcpy(g_queue + g_queue_len + 4, rec, n);
    g_queue_len += 4 + n;
    if ((int64_t)g_queue_len > g_stats[ST_MAX_QUEUE]) g_stats[ST_MAX_QUEUE] = (int64_t)g_queue_len;
    g_stats[ST_BYTES] += (int64_t)(4 + n);
    *ok = 1;
  } else {
    g_stats[ST_DROPPED]++;
  }
  ReleaseSRWLockExclusive(&g_lock);
}

static uint8_t g_rec[64 * 1024];
static uint8_t g_val[8 * 1024];

static VOID WINAPI on_event(PEVENT_RECORD r) {
  LARGE_INTEGER t0, t1;
  QueryPerformanceCounter(&t0);
  const GUID *pg = &r->EventHeader.ProviderId;
  int prov = memcmp(pg, &kNet, sizeof(GUID)) == 0 ? 1
           : memcmp(pg, &kDns, sizeof(GUID)) == 0 ? 2
           : memcmp(pg, &kProc, sizeof(GUID)) == 0 ? 3 : 0;
  if (prov == 0) { g_stats[ST_OTHER]++; return; }
  g_stats[ST_EVENTS]++;
  g_stats[prov == 1 ? ST_NET : prov == 2 ? ST_DNS : ST_PROC]++;

  const EVENT_DESCRIPTOR *d = &r->EventHeader.EventDescriptor;
  uint32_t key = ((uint32_t)prov << 24) | ((uint32_t)d->Id << 8) | d->Version;
  cache_ent *ce = cache_get(key, r);
  if (ce == NULL || ce->failed) { g_stats[ST_DECODE_FAIL]++; return; }
  TRACE_EVENT_INFO *info = ce->info;
  ULONG nprops = info->TopLevelPropertyCount;
  int with_names = !ce->names_sent;

  wbuf w = {g_rec, 0, sizeof g_rec, 0};
  put_u8(&w, (uint8_t)prov);
  put_u8(&w, d->Version);
  put_u16(&w, d->Id);
  put_u8(&w, d->Opcode);
  put_u8(&w, (uint8_t)(with_names ? 1 : 0));
  put_u16(&w, (uint16_t)nprops);
  put_u32(&w, r->EventHeader.ProcessId);
  put_u32(&w, r->EventHeader.ThreadId);
  put_i64(&w, r->EventHeader.TimeStamp.QuadPart);
  if (with_names) {
    const WCHAR *s = info_str(info, info->TaskNameOffset);
    put_wstr16(&w, s, (int)wcslen(s));
    s = info_str(info, info->OpcodeNameOffset);
    put_wstr16(&w, s, (int)wcslen(s));
    for (ULONG i = 0; i < nprops; i++) {
      s = info_str(info, info->EventPropertyInfoArray[i].NameOffset);
      put_wstr16(&w, s, (int)wcslen(s));
    }
  }
  for (ULONG i = 0; i < nprops; i++) {
    EVENT_PROPERTY_INFO *pi = &info->EventPropertyInfoArray[i];
    if (pi->Flags & PropertyStruct) { put_u8(&w, TAG_STRUCT); put_u16(&w, 0); continue; }
    PROPERTY_DATA_DESCRIPTOR pd;
    pd.PropertyName = (ULONGLONG)(ULONG_PTR)info_str(info, pi->NameOffset);
    pd.ArrayIndex = ULONG_MAX;
    pd.Reserved = 0;
    ULONG psz = 0;
    if (TdhGetPropertySize(r, 0, NULL, 1, &pd, &psz) != ERROR_SUCCESS || psz > sizeof g_val) {
      put_u8(&w, TAG_TOO_BIG); put_u16(&w, 0); continue;
    }
    if (psz > 0 && TdhGetProperty(r, 0, NULL, 1, &pd, psz, g_val) != ERROR_SUCCESS) {
      put_u8(&w, TAG_TOO_BIG); put_u16(&w, 0); continue;
    }
    uint8_t tag = classify(pi->nonStructType.InType, pi->nonStructType.OutType);
    if (tag == TAG_STR && pi->nonStructType.InType == TDH_INTYPE_UNICODESTRING) {
      put_u8(&w, TAG_STR);
      put_wstr16(&w, (const WCHAR *)g_val, (int)(psz / 2));
    } else {
      if (tag == TAG_STR) { while (psz > 0 && g_val[psz - 1] == 0) psz--; }
      put_u8(&w, tag);
      put_u16(&w, (uint16_t)psz);
      put(&w, g_val, psz);
    }
  }
  if (w.overflow) { g_stats[ST_DROPPED]++; return; }
  int ok;
  enqueue(w.p, w.len, &ok);
  if (ok && with_names) ce->names_sent = 1;
  QueryPerformanceCounter(&t1);
  g_stats[ST_CB_NS] += (t1.QuadPart - t0.QuadPart) * 1000000000LL / g_qpf.QuadPart;
}

// ---------------------------------------------------------------- session control

static EVENT_TRACE_PROPERTIES *init_props(void) {
  memset(g_props_buf, 0, sizeof g_props_buf);
  EVENT_TRACE_PROPERTIES *p = (EVENT_TRACE_PROPERTIES *)g_props_buf;
  p->Wnode.BufferSize = sizeof g_props_buf;
  p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  p->Wnode.ClientContext = 1; // QPC resolution, delivered as FILETIME
  p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  p->BufferSize = 64; // KB
  p->MinimumBuffers = 4;
  p->MaximumBuffers = 64;
  p->FlushTimer = 1; // seconds
  p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
  return p;
}

static DWORD WINAPI consumer_thread(LPVOID arg) {
  (void)arg;
  ULONG st = ProcessTrace(&g_consumer, 1, NULL, NULL);
  (void)st;
  return 0;
}

static BOOL WINAPI ctrl_handler(DWORD type) {
  (void)type;
  if (g_running) ControlTraceW(0, g_name, init_props(), EVENT_TRACE_CONTROL_STOP);
  return FALSE;
}

static void copy_name(moonbit_string_t name) {
  int32_t n = Moonbit_array_length(name);
  if (n > 120) n = 120;
  memcpy(g_name, name, (size_t)n * 2);
  g_name[n] = 0;
}

static int fail(const char *stage, ULONG err) {
  g_stage = stage;
  g_last_error = err;
  return (int)err;
}

static ULONG enable(const GUID *g, ULONGLONG any) {
  return EnableTraceEx2(g_session, g, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
                        any, 0, 0, NULL);
}

// flags: bit0 Kernel-Network, bit1 DNS-Client, bit2 Kernel-Process
int32_t etwprobe_start(moonbit_string_t name, int32_t flags) {
  if (g_running) return fail("already running", ERROR_ALREADY_EXISTS);
  QueryPerformanceFrequency(&g_qpf);
  copy_name(name);
  if (!g_queue) {
    g_queue_cap = 32u * 1024 * 1024;
    g_queue = (uint8_t *)malloc(g_queue_cap);
    if (!g_queue) return fail("malloc", ERROR_OUTOFMEMORY);
  }
  ULONG st = StartTraceW(&g_session, g_name, init_props());
  if (st == ERROR_ALREADY_EXISTS) {
    // A session survives the process that created it; stop the stale one.
    ControlTraceW(0, g_name, init_props(), EVENT_TRACE_CONTROL_STOP);
    g_stats[ST_STALE]++;
    st = StartTraceW(&g_session, g_name, init_props());
  }
  if (st != ERROR_SUCCESS) return fail("StartTrace", st);
  g_running = 1;
  SetConsoleCtrlHandler(ctrl_handler, TRUE);
  if ((flags & 1) && (st = enable(&kNet, 0xFFFFFFFFFFFFFFFFull)) != ERROR_SUCCESS)
    return fail("EnableTraceEx2(Kernel-Network)", st);
  if ((flags & 2) && (st = enable(&kDns, 0xFFFFFFFFFFFFFFFFull)) != ERROR_SUCCESS)
    return fail("EnableTraceEx2(DNS-Client)", st);
  // 0x10 = WINEVENT_KEYWORD_PROCESS; thread/image keywords would flood the queue.
  if ((flags & 4) && (st = enable(&kProc, 0x10)) != ERROR_SUCCESS)
    return fail("EnableTraceEx2(Kernel-Process)", st);
  EVENT_TRACE_LOGFILEW lf;
  memset(&lf, 0, sizeof lf);
  lf.LoggerName = g_name;
  lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
  lf.EventRecordCallback = on_event;
  g_consumer = OpenTraceW(&lf);
  if (g_consumer == INVALID_PROCESSTRACE_HANDLE) return fail("OpenTrace", GetLastError());
  g_thread = CreateThread(NULL, 0, consumer_thread, NULL, 0, NULL);
  if (!g_thread) return fail("CreateThread", GetLastError());
  g_stage = "";
  g_last_error = 0;
  return 0;
}

int32_t etwprobe_stop(void) {
  ULONG st = ERROR_SUCCESS;
  if (g_running) {
    st = ControlTraceW(g_session, NULL, init_props(), EVENT_TRACE_CONTROL_STOP);
    g_running = 0;
  }
  if (g_consumer != INVALID_PROCESSTRACE_HANDLE) {
    CloseTrace(g_consumer);
    g_consumer = INVALID_PROCESSTRACE_HANDLE;
  }
  if (g_thread) {
    WaitForSingleObject(g_thread, 5000);
    CloseHandle(g_thread);
    g_thread = NULL;
  }
  return (int32_t)st;
}

// Leaves the session running on purpose (used to show sessions outlive processes).
void etwprobe_abandon(void) { g_running = 0; }

int32_t etwprobe_session_exists(moonbit_string_t name) {
  WCHAR saved[128];
  memcpy(saved, g_name, sizeof saved);
  copy_name(name);
  ULONG st = ControlTraceW(0, g_name, init_props(), EVENT_TRACE_CONTROL_QUERY);
  memcpy(g_name, saved, sizeof saved);
  return st == ERROR_SUCCESS ? 1 : (st == ERROR_WMI_INSTANCE_NOT_FOUND ? 0 : -(int32_t)st);
}

moonbit_string_t etwprobe_stage(void) {
  int32_t n = (int32_t)strlen(g_stage);
  moonbit_string_t s = moonbit_make_string(n, 0);
  for (int32_t i = 0; i < n; i++) s[i] = (uint16_t)(unsigned char)g_stage[i];
  return s;
}

int32_t etwprobe_last_error(void) { return (int32_t)g_last_error; }

// Copies whole queued records (with their u32 length prefixes) into out.
int32_t etwprobe_drain(uint8_t *out, int32_t cap) {
  size_t used = 0;
  AcquireSRWLockExclusive(&g_lock);
  while (used + 4 <= g_queue_len) {
    uint32_t n;
    memcpy(&n, g_queue + used, 4);
    if (used + 4 + n > (size_t)cap) break;
    used += 4 + n;
  }
  if (used > 0) {
    memcpy(out, g_queue, used);
    memmove(g_queue, g_queue + used, g_queue_len - used);
    g_queue_len -= used;
  }
  ReleaseSRWLockExclusive(&g_lock);
  return (int32_t)used;
}

void etwprobe_stats(int64_t *out) {
  for (int i = 0; i < ST_COUNT; i++) out[i] = g_stats[i];
}

// out: EventsLost, BuffersWritten, LogBuffersLost, RealTimeBuffersLost, NumberOfBuffers, FreeBuffers
int32_t etwprobe_query(int64_t *out) {
  if (!g_running) return -1;
  EVENT_TRACE_PROPERTIES *p = init_props();
  ULONG st = ControlTraceW(g_session, NULL, p, EVENT_TRACE_CONTROL_QUERY);
  if (st != ERROR_SUCCESS) return (int32_t)st;
  out[0] = p->EventsLost;
  out[1] = p->BuffersWritten;
  out[2] = p->LogBuffersLost;
  out[3] = p->RealTimeBuffersLost;
  out[4] = p->NumberOfBuffers;
  out[5] = p->FreeBuffers;
  return 0;
}

// ---------------------------------------------------------------- process helpers

static moonbit_string_t wide_to_mbt(const WCHAR *s, int n) {
  moonbit_string_t m = moonbit_make_string(n, 0);
  memcpy(m, s, (size_t)n * 2);
  return m;
}

moonbit_string_t etwprobe_image_name(int32_t pid) {
  WCHAR buf[1024];
  DWORD n = 1024;
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
  if (!h) return moonbit_make_string(0, 0);
  BOOL ok = QueryFullProcessImageNameW(h, 0, buf, &n);
  CloseHandle(h);
  return ok ? wide_to_mbt(buf, (int)n) : moonbit_make_string(0, 0);
}

static HANDLE g_child = NULL;

int32_t etwprobe_spawn(moonbit_string_t cmdline) {
  int32_t n = Moonbit_array_length(cmdline);
  WCHAR *buf = (WCHAR *)malloc(((size_t)n + 1) * 2);
  if (!buf) return -1;
  memcpy(buf, cmdline, (size_t)n * 2);
  buf[n] = 0;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof si);
  si.cb = sizeof si;
  memset(&pi, 0, sizeof pi);
  BOOL ok = CreateProcessW(NULL, buf, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
  free(buf);
  if (!ok) return -(int32_t)GetLastError();
  CloseHandle(pi.hThread);
  if (g_child) CloseHandle(g_child);
  g_child = pi.hProcess;
  return (int32_t)pi.dwProcessId;
}

// 0 = exited, 1 = still running
int32_t etwprobe_child_wait(int32_t ms) {
  if (!g_child) return 0;
  return WaitForSingleObject(g_child, (DWORD)ms) == WAIT_OBJECT_0 ? 0 : 1;
}

int32_t etwprobe_child_exit_code(void) {
  DWORD code = 0;
  if (g_child) GetExitCodeProcess(g_child, &code);
  return (int32_t)code;
}

int32_t etwprobe_is_elevated(void) {
  HANDLE tok;
  TOKEN_ELEVATION e;
  DWORD n;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return -1;
  BOOL ok = GetTokenInformation(tok, TokenElevation, &e, sizeof e, &n);
  CloseHandle(tok);
  return ok ? (e.TokenIsElevated ? 1 : 0) : -1;
}

// out: cpu ms (user+kernel), private bytes, working set, peak working set
void etwprobe_self_usage(int64_t *out) {
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

void etwprobe_sleep_ms(int32_t ms) { Sleep((DWORD)ms); }

double etwprobe_now_ms(void) {
  LARGE_INTEGER t, f;
  QueryPerformanceCounter(&t);
  QueryPerformanceFrequency(&f);
  return (double)t.QuadPart * 1000.0 / (double)f.QuadPart;
}
