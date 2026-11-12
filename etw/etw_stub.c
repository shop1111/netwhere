// netwhere ETW consumer: Kernel-Network, DNS-Client and Kernel-Process only.
//
// Threading: ProcessTrace() calls on_event() on its own thread. The MoonBit
// runtime is never entered from that thread; the callback extracts the few
// fields netwhere needs into a compact record and appends it to a locked
// byte queue that MoonBit drains from its own thread.
//
// Field extraction, per (provider, event id, version, pointer size):
//   * the schema comes from TdhGetEventInformation once;
//   * "fast": when every property before a needed field has a fixed size, the
//     field's offset in UserData is computed once and read with memcpy;
//   * "tdh": TdhGetProperty by property name (what the M0 probe verified);
//   * "shadow": fast where possible, and also tdh, comparing the bytes.
// Fields are always looked up by name, never by hard-coded offsets.
//
// Output records (little-endian), each prefixed by its u32 length:
//   u8 kind, u8 version, u16 id, u32 header pid, i64 timestamp (FILETIME)
//   kind 1 net:    u32 pid, u32 size, u8 family, u8[16] saddr, u8[16] daddr,
//                  u16 sport, u16 dport          (ports in host order)
//   kind 2 dns:    i32 client pid (-1 none), u32 status, str name, str results
//   kind 3 pstart: u32 pid, u32 ppid, i64 create time, str image
//   kind 4 pstop:  u32 pid, i64 create time, u32 exit code
//   str = u16 byte length + UTF-8
#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "moonbit.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

#ifndef INVALID_PROCESSTRACE_HANDLE
#define INVALID_PROCESSTRACE_HANDLE ((TRACEHANDLE)INVALID_HANDLE_VALUE)
#endif

// Microsoft-Windows-Kernel-Network
static const GUID kNet = {0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};
// Microsoft-Windows-DNS-Client
static const GUID kDns = {0x1c95126e, 0x7eea, 0x49a9, {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};
// Microsoft-Windows-Kernel-Process
static const GUID kProc = {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

enum { K_NET = 1, K_DNS = 2, K_PSTART = 3, K_PSTOP = 4 };
enum { MODE_TDH = 0, MODE_FAST = 1, MODE_SHADOW = 2 };

enum { ST_EVENTS, ST_NET, ST_DNS, ST_PROC, ST_DROPPED, ST_BYTES, ST_CB_NS, ST_MAX_QUEUE,
       ST_DECODE_FAIL, ST_STALE, ST_OTHER, ST_FAST, ST_SLOW, ST_SHADOW_CHECKED,
       ST_SHADOW_MISMATCH, ST_SKIPPED, ST_COUNT };

static TRACEHANDLE g_session = 0;
static TRACEHANDLE g_consumer = INVALID_PROCESSTRACE_HANDLE;
static HANDLE g_thread = NULL;
static WCHAR g_name[128];
static int g_running = 0;
static int g_mode = MODE_SHADOW;
static ULONG g_last_error = 0;
static const char *g_stage = "";
static unsigned char g_props_buf[sizeof(EVENT_TRACE_PROPERTIES) + 2048];

static SRWLOCK g_lock = SRWLOCK_INIT;
static uint8_t *g_queue = NULL;
static size_t g_queue_len = 0;
static size_t g_queue_cap = 0;
static volatile int64_t g_stats[ST_COUNT];
static LARGE_INTEGER g_qpf;

// ---------------------------------------------------------------- field plans

#define MAXF 6
static const WCHAR *kNetFields[] = {L"PID", L"size", L"saddr", L"daddr", L"sport", L"dport"};
static const WCHAR *kDnsFields[] = {L"QueryName", L"QueryStatus", L"QueryResults", L"ClientPID"};
static const WCHAR *kDnsAlt[] = {NULL, L"Status", NULL, NULL};
static const WCHAR *kStartFields[] = {L"ProcessID", L"ParentProcessID", L"CreateTime", L"ImageName"};
static const WCHAR *kStopFields[] = {L"ProcessID", L"CreateTime", L"ExitCode"};

typedef struct {
  uint32_t key;      // 0 = empty slot
  int failed;
  TRACE_EVENT_INFO *info;
  int nf;
  int idx[MAXF];     // property index or -1 (missing)
  int off[MAXF];     // byte offset in UserData or -1 (not fixed)
  int size[MAXF];
} plan_t;

#define PLAN_SLOTS 256
static plan_t g_plans[PLAN_SLOTS];

static int kind_of(int prov, USHORT id) {
  switch (prov) {
  case 1:
    switch (id) {
    case 10: case 11: case 12: case 13: case 14: case 15: case 16:
    case 26: case 27: case 28: case 29: case 30: case 31: case 32:
    case 42: case 43: case 58: case 59:
      return K_NET;
    }
    return 0;
  case 2: return (id == 3008 || id == 3020) ? K_DNS : 0;
  case 3: return id == 1 ? K_PSTART : id == 2 ? K_PSTOP : 0;
  }
  return 0;
}

static const WCHAR *info_str(TRACE_EVENT_INFO *info, ULONG off) {
  return off ? (const WCHAR *)((BYTE *)info + off) : L"";
}

// Size of a property when it is fixed, else -1.
static int fixed_size(const EVENT_PROPERTY_INFO *pi, int ptrsize) {
  if (pi->Flags & (PropertyStruct | PropertyParamLength | PropertyParamCount)) return -1;
  if (pi->count != 1) return -1;
  switch (pi->nonStructType.InType) {
  case TDH_INTYPE_INT8: case TDH_INTYPE_UINT8: case TDH_INTYPE_ANSICHAR: return 1;
  case TDH_INTYPE_INT16: case TDH_INTYPE_UINT16: case TDH_INTYPE_UNICODECHAR: return 2;
  case TDH_INTYPE_INT32: case TDH_INTYPE_UINT32: case TDH_INTYPE_HEXINT32:
  case TDH_INTYPE_FLOAT: case TDH_INTYPE_BOOLEAN: return 4;
  case TDH_INTYPE_INT64: case TDH_INTYPE_UINT64: case TDH_INTYPE_HEXINT64:
  case TDH_INTYPE_DOUBLE: case TDH_INTYPE_FILETIME: return 8;
  case TDH_INTYPE_GUID: case TDH_INTYPE_SYSTEMTIME: return 16;
  case TDH_INTYPE_POINTER: case TDH_INTYPE_SIZET: return ptrsize;
  case TDH_INTYPE_BINARY: return pi->length > 0 ? (int)pi->length : -1;
  default: return -1;
  }
}

static plan_t *plan_get(PEVENT_RECORD r, int prov, int kind) {
  const EVENT_DESCRIPTOR *d = &r->EventHeader.EventDescriptor;
  int ptrsize = (r->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
  uint32_t key = ((uint32_t)prov << 28) | ((uint32_t)(ptrsize == 8) << 27) |
                 ((uint32_t)d->Id << 8) | d->Version;
  uint32_t h = (key * 2654435761u) & (PLAN_SLOTS - 1);
  for (int i = 0; i < PLAN_SLOTS; i++) {
    plan_t *p = &g_plans[(h + i) & (PLAN_SLOTS - 1)];
    if (p->key == key) return p;
    if (p->key != 0) continue;
    p->key = key;
    ULONG sz = 0;
    TDHSTATUS st = TdhGetEventInformation(r, 0, NULL, NULL, &sz);
    if (st == ERROR_INSUFFICIENT_BUFFER) {
      p->info = (TRACE_EVENT_INFO *)malloc(sz);
      st = p->info ? TdhGetEventInformation(r, 0, NULL, p->info, &sz) : ERROR_OUTOFMEMORY;
    }
    if (st != ERROR_SUCCESS) {
      free(p->info);
      p->info = NULL;
      p->failed = 1;
      return p;
    }
    const WCHAR **names, **alts = NULL;
    switch (kind) {
    case K_NET: names = kNetFields; p->nf = 6; break;
    case K_DNS: names = kDnsFields; alts = kDnsAlt; p->nf = 4; break;
    case K_PSTART: names = kStartFields; p->nf = 4; break;
    default: names = kStopFields; p->nf = 3; break;
    }
    ULONG n = p->info->TopLevelPropertyCount;
    for (int f = 0; f < p->nf; f++) {
      p->idx[f] = -1; p->off[f] = -1; p->size[f] = -1;
      int off = 0;
      for (ULONG k = 0; k < n; k++) {
        const EVENT_PROPERTY_INFO *pi = &p->info->EventPropertyInfoArray[k];
        const WCHAR *pn = info_str(p->info, pi->NameOffset);
        if (wcscmp(pn, names[f]) == 0 || (alts && alts[f] && wcscmp(pn, alts[f]) == 0)) {
          p->idx[f] = (int)k;
          int fs = fixed_size(pi, ptrsize);
          if (off >= 0 && fs > 0) { p->off[f] = off; p->size[f] = fs; }
          break;
        }
        int fs = fixed_size(pi, ptrsize);
        off = (off >= 0 && fs > 0) ? off + fs : -1;
      }
    }
    return p;
  }
  return NULL;
}

static uint8_t g_tdh_buf[8 * 1024];

// TdhGetProperty by name into out; returns size or -1.
static int fetch_tdh(PEVENT_RECORD r, plan_t *p, int f, uint8_t *out, int cap) {
  if (p->idx[f] < 0) return -1;
  const EVENT_PROPERTY_INFO *pi = &p->info->EventPropertyInfoArray[p->idx[f]];
  PROPERTY_DATA_DESCRIPTOR pd;
  pd.PropertyName = (ULONGLONG)(ULONG_PTR)info_str(p->info, pi->NameOffset);
  pd.ArrayIndex = ULONG_MAX;
  pd.Reserved = 0;
  ULONG psz = 0;
  if (TdhGetPropertySize(r, 0, NULL, 1, &pd, &psz) != ERROR_SUCCESS || psz > (ULONG)cap) return -1;
  if (psz > 0 && TdhGetProperty(r, 0, NULL, 1, &pd, psz, out) != ERROR_SUCCESS) return -1;
  return (int)psz;
}

// Fast path where possible (per mode); returns size or -1.
static int fetch(PEVENT_RECORD r, plan_t *p, int f, uint8_t *out, int cap) {
  if (g_mode != MODE_TDH && p->off[f] >= 0) {
    int off = p->off[f], sz = p->size[f];
    if (sz > cap || off + sz > (int)r->UserDataLength) return -1;
    memcpy(out, (const uint8_t *)r->UserData + off, (size_t)sz);
    g_stats[ST_FAST]++;
    if (g_mode == MODE_SHADOW) {
      int n = fetch_tdh(r, p, f, g_tdh_buf, sizeof g_tdh_buf);
      g_stats[ST_SHADOW_CHECKED]++;
      if (n != sz || memcmp(g_tdh_buf, out, (size_t)sz) != 0) g_stats[ST_SHADOW_MISMATCH]++;
    }
    return sz;
  }
  g_stats[ST_SLOW]++;
  return fetch_tdh(r, p, f, out, cap);
}

static uint64_t le_uint(const uint8_t *b, int n) {
  uint64_t v = 0;
  for (int i = n - 1; i >= 0; i--) v = (v << 8) | b[i];
  return v;
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

// UTF-16 bytes (may end with NUL) -> u16 length + UTF-8.
static void put_wbytes(wbuf *w, const uint8_t *b, int nbytes) {
  const WCHAR *s = (const WCHAR *)b;
  int n = nbytes > 0 ? nbytes / 2 : 0;
  while (n > 0 && s[n - 1] == 0) n--;
  char tmp[4096];
  int m = n > 0 ? WideCharToMultiByte(CP_UTF8, 0, s, n, tmp, sizeof tmp, NULL, NULL) : 0;
  if (m < 0) m = 0;
  put_u16(w, (uint16_t)m);
  put(w, tmp, (size_t)m);
}

static void enqueue(const uint8_t *rec, size_t n) {
  AcquireSRWLockExclusive(&g_lock);
  if (g_queue && g_queue_len + 4 + n <= g_queue_cap) {
    uint32_t len32 = (uint32_t)n;
    memcpy(g_queue + g_queue_len, &len32, 4);
    memcpy(g_queue + g_queue_len + 4, rec, n);
    g_queue_len += 4 + n;
    if ((int64_t)g_queue_len > g_stats[ST_MAX_QUEUE]) g_stats[ST_MAX_QUEUE] = (int64_t)g_queue_len;
    g_stats[ST_BYTES] += (int64_t)(4 + n);
  } else {
    g_stats[ST_DROPPED]++;
  }
  ReleaseSRWLockExclusive(&g_lock);
}

static uint8_t g_rec[16 * 1024];
static uint8_t g_val[8 * 1024];

static int decode(PEVENT_RECORD r, plan_t *p, int kind, wbuf *w) {
  int n;
  switch (kind) {
  case K_NET: {
    uint8_t v[6][16];
    int sz[6];
    for (int f = 0; f < 6; f++) {
      sz[f] = fetch(r, p, f, v[f], 16);
      if (sz[f] <= 0) return 0;
    }
    int fam = sz[2] == 4 ? 4 : sz[2] == 16 ? 6 : 0;
    if (fam == 0 || sz[3] != sz[2] || sz[4] != 2 || sz[5] != 2) return 0;
    put_u32(w, (uint32_t)le_uint(v[0], sz[0] > 4 ? 4 : sz[0]));
    put_u32(w, (uint32_t)le_uint(v[1], sz[1] > 4 ? 4 : sz[1]));
    put_u8(w, (uint8_t)fam);
    uint8_t a[16];
    memset(a, 0, 16); memcpy(a, v[2], (size_t)sz[2]); put(w, a, 16);
    memset(a, 0, 16); memcpy(a, v[3], (size_t)sz[3]); put(w, a, 16);
    // TDH_OUTTYPE_PORT: network byte order
    put_u16(w, (uint16_t)((v[4][0] << 8) | v[4][1]));
    put_u16(w, (uint16_t)((v[5][0] << 8) | v[5][1]));
    return 1;
  }
  case K_DNS: {
    uint8_t num[8];
    n = fetch(r, p, 3, num, 8);
    put_u32(w, n > 0 ? (uint32_t)le_uint(num, n > 4 ? 4 : n) : 0xffffffffu);
    n = fetch(r, p, 1, num, 8);
    if (n <= 0) return 0;
    put_u32(w, (uint32_t)le_uint(num, n > 4 ? 4 : n));
    n = fetch(r, p, 0, g_val, sizeof g_val);
    if (n < 0) return 0;
    put_wbytes(w, g_val, n);
    n = fetch(r, p, 2, g_val, sizeof g_val);
    put_wbytes(w, g_val, n < 0 ? 0 : n);
    return 1;
  }
  case K_PSTART: {
    uint8_t num[8];
    n = fetch(r, p, 0, num, 8); if (n <= 0) return 0;
    put_u32(w, (uint32_t)le_uint(num, n > 4 ? 4 : n));
    n = fetch(r, p, 1, num, 8); if (n <= 0) return 0;
    put_u32(w, (uint32_t)le_uint(num, n > 4 ? 4 : n));
    n = fetch(r, p, 2, num, 8); if (n != 8) return 0;
    put_i64(w, (int64_t)le_uint(num, 8));
    n = fetch(r, p, 3, g_val, sizeof g_val);
    put_wbytes(w, g_val, n < 0 ? 0 : n);
    return 1;
  }
  case K_PSTOP: {
    uint8_t num[8];
    n = fetch(r, p, 0, num, 8); if (n <= 0) return 0;
    put_u32(w, (uint32_t)le_uint(num, n > 4 ? 4 : n));
    n = fetch(r, p, 1, num, 8); if (n != 8) return 0;
    put_i64(w, (int64_t)le_uint(num, 8));
    n = fetch(r, p, 2, num, 8);
    put_u32(w, n > 0 ? (uint32_t)le_uint(num, n > 4 ? 4 : n) : 0);
    return 1;
  }
  }
  return 0;
}

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
  int kind = kind_of(prov, d->Id);
  if (kind == 0) { g_stats[ST_SKIPPED]++; return; }
  plan_t *p = plan_get(r, prov, kind);
  if (p == NULL || p->failed) { g_stats[ST_DECODE_FAIL]++; return; }
  wbuf w = {g_rec, 0, sizeof g_rec, 0};
  put_u8(&w, (uint8_t)kind);
  put_u8(&w, d->Version);
  put_u16(&w, d->Id);
  put_u32(&w, r->EventHeader.ProcessId);
  put_i64(&w, r->EventHeader.TimeStamp.QuadPart);
  if (!decode(r, p, kind, &w) || w.overflow) { g_stats[ST_DECODE_FAIL]++; return; }
  enqueue(w.p, w.len);
  QueryPerformanceCounter(&t1);
  g_stats[ST_CB_NS] += (t1.QuadPart - t0.QuadPart) * 1000000000LL / g_qpf.QuadPart;
}

// ---------------------------------------------------------------- session control

static EVENT_TRACE_PROPERTIES *init_props(void) {
  memset(g_props_buf, 0, sizeof g_props_buf);
  EVENT_TRACE_PROPERTIES *p = (EVENT_TRACE_PROPERTIES *)g_props_buf;
  p->Wnode.BufferSize = sizeof g_props_buf;
  p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  p->Wnode.ClientContext = 1;  // QPC resolution, delivered as FILETIME
  p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  p->BufferSize = 64;  // KB
  p->MinimumBuffers = 4;
  p->MaximumBuffers = 64;
  p->FlushTimer = 1;  // seconds
  p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
  return p;
}

static DWORD WINAPI consumer_thread(LPVOID arg) {
  (void)arg;
  ProcessTrace(&g_consumer, 1, NULL, NULL);
  return 0;
}

static void copy_name(WCHAR *dst, moonbit_string_t name) {
  int32_t n = Moonbit_array_length(name);
  if (n > 120) n = 120;
  memcpy(dst, name, (size_t)n * 2);
  dst[n] = 0;
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
// mode: 0 tdh, 1 fast, 2 shadow
int32_t nw_etw_start(moonbit_string_t name, int32_t flags, int32_t mode, int32_t queue_kb) {
  if (g_running) return fail("already running", ERROR_ALREADY_EXISTS);
  QueryPerformanceFrequency(&g_qpf);
  copy_name(g_name, name);
  g_mode = mode;
  size_t cap = (size_t)(queue_kb > 0 ? queue_kb : 1024) * 1024;
  if (!g_queue || g_queue_cap != cap) {
    free(g_queue);
    g_queue = (uint8_t *)malloc(cap);
    if (!g_queue) return fail("malloc", ERROR_OUTOFMEMORY);
    g_queue_cap = cap;
    g_queue_len = 0;
  }
  ULONG st = StartTraceW(&g_session, g_name, init_props());
  if (st == ERROR_ALREADY_EXISTS) {
    // A session outlives the process that created it; stop the stale one.
    ControlTraceW(0, g_name, init_props(), EVENT_TRACE_CONTROL_STOP);
    g_stats[ST_STALE]++;
    st = StartTraceW(&g_session, g_name, init_props());
  }
  if (st != ERROR_SUCCESS) return fail("StartTrace", st);
  g_running = 1;
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

int32_t nw_etw_stop(void) {
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

// 1 = running, 0 = not found, negative = -(Win32 error)
int32_t nw_etw_session_exists(moonbit_string_t name) {
  WCHAR n[128];
  copy_name(n, name);
  ULONG st = ControlTraceW(0, n, init_props(), EVENT_TRACE_CONTROL_QUERY);
  return st == ERROR_SUCCESS ? 1 : (st == ERROR_WMI_INSTANCE_NOT_FOUND ? 0 : -(int32_t)st);
}

// Stops a session by name (stale-session cleanup). 0 or Win32 error.
int32_t nw_etw_stop_session(moonbit_string_t name) {
  WCHAR n[128];
  copy_name(n, name);
  return (int32_t)ControlTraceW(0, n, init_props(), EVENT_TRACE_CONTROL_STOP);
}

moonbit_string_t nw_etw_stage(void) {
  int32_t n = (int32_t)strlen(g_stage);
  moonbit_string_t s = moonbit_make_string(n, 0);
  for (int32_t i = 0; i < n; i++) s[i] = (uint16_t)(unsigned char)g_stage[i];
  return s;
}

// Copies whole queued records (with u32 length prefixes) into out.
int32_t nw_etw_drain(uint8_t *out, int32_t cap) {
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

void nw_etw_stats(int64_t *out) {
  for (int i = 0; i < ST_COUNT; i++) out[i] = g_stats[i];
}

// out: EventsLost, BuffersWritten, LogBuffersLost, RealTimeBuffersLost
int32_t nw_etw_query(int64_t *out) {
  if (!g_running) return -1;
  EVENT_TRACE_PROPERTIES *p = init_props();
  ULONG st = ControlTraceW(g_session, NULL, p, EVENT_TRACE_CONTROL_QUERY);
  if (st != ERROR_SUCCESS) return (int32_t)st;
  out[0] = p->EventsLost;
  out[1] = p->BuffersWritten;
  out[2] = p->LogBuffersLost;
  out[3] = p->RealTimeBuffersLost;
  return 0;
}
