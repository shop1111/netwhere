// IP Helper queries that need no elevation. Every function fills a
// caller-owned byte buffer (little-endian, layouts documented per function)
// and returns the number of bytes written, or a negative Win32 error code.
#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "moonbit.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

typedef struct {
  uint8_t *p;
  int32_t len, cap;
  int overflow;
} wbuf;

static void put(wbuf *w, const void *src, int32_t n) {
  if (w->len + n > w->cap) { w->overflow = 1; return; }
  memcpy(w->p + w->len, src, (size_t)n);
  w->len += n;
}
static void put_u8(wbuf *w, uint8_t v) { put(w, &v, 1); }
static void put_u16(wbuf *w, uint16_t v) { put(w, &v, 2); }
static void put_u32(wbuf *w, uint32_t v) { put(w, &v, 4); }

// u16 byte length + UTF-8 bytes.
static void put_wstr(wbuf *w, const WCHAR *s) {
  char tmp[1024];
  int n = s ? (int)wcslen(s) : 0;
  int m = n > 0 ? WideCharToMultiByte(CP_UTF8, 0, s, n, tmp, sizeof tmp, NULL, NULL) : 0;
  if (m < 0) m = 0;
  put_u16(w, (uint16_t)m);
  put(w, tmp, m);
}

// family (4 or 6) + 16 address bytes (IPv4 in the first 4, network order).
static void put_addr(wbuf *w, const SOCKADDR_INET *a) {
  uint8_t bytes[16];
  memset(bytes, 0, sizeof bytes);
  if (a->si_family == AF_INET) {
    put_u8(w, 4);
    memcpy(bytes, &a->Ipv4.sin_addr, 4);
  } else if (a->si_family == AF_INET6) {
    put_u8(w, 6);
    memcpy(bytes, &a->Ipv6.sin6_addr, 16);
  } else {
    put_u8(w, 0);
  }
  put(w, bytes, 16);
}

static int32_t finish(wbuf *w) {
  return w->overflow ? -(int32_t)ERROR_INSUFFICIENT_BUFFER : w->len;
}

static void alias_of(NET_IFINDEX idx, WCHAR *out, size_t n) {
  NET_LUID luid;
  out[0] = 0;
  if (ConvertInterfaceIndexToLuid(idx, &luid) == NO_ERROR)
    ConvertInterfaceLuidToAlias(&luid, out, n);
}

// GetBestRoute2 for one destination.
// in:  family (4|6), addr (16 bytes, network order)
// out: u32 if_index, u8 prefix_len, addr next_hop (17 bytes), addr source
//      (17 bytes), str alias
int32_t nw_best_route(int32_t family, uint8_t *addr, uint8_t *out, int32_t cap) {
  SOCKADDR_INET dst;
  memset(&dst, 0, sizeof dst);
  if (family == 4) {
    dst.Ipv4.sin_family = AF_INET;
    memcpy(&dst.Ipv4.sin_addr, addr, 4);
  } else if (family == 6) {
    dst.Ipv6.sin6_family = AF_INET6;
    memcpy(&dst.Ipv6.sin6_addr, addr, 16);
  } else {
    return -(int32_t)ERROR_INVALID_PARAMETER;
  }
  MIB_IPFORWARD_ROW2 row;
  SOCKADDR_INET src;
  memset(&row, 0, sizeof row);
  memset(&src, 0, sizeof src);
  DWORD st = GetBestRoute2(NULL, 0, NULL, &dst, 0, &row, &src);
  if (st != NO_ERROR) return -(int32_t)st;
  WCHAR alias[IF_MAX_STRING_SIZE + 1];
  alias_of(row.InterfaceIndex, alias, IF_MAX_STRING_SIZE + 1);
  wbuf w = {out, 0, cap, 0};
  put_u32(&w, row.InterfaceIndex);
  put_u8(&w, row.DestinationPrefix.PrefixLength);
  put_addr(&w, &row.NextHop);
  put_addr(&w, &src);
  put_wstr(&w, alias);
  return finish(&w);
}

// TCP listening sockets with owning pid, IPv4 and IPv6.
// out: u32 count, then count x { addr (17 bytes), u16 port, u32 pid }
int32_t nw_tcp_listeners(uint8_t *out, int32_t cap) {
  wbuf w = {out, 0, cap, 0};
  uint32_t count = 0;
  put_u32(&w, 0);
  int families[2] = {AF_INET, AF_INET6};
  for (int f = 0; f < 2; f++) {
    DWORD size = 0;
    DWORD st = GetExtendedTcpTable(NULL, &size, FALSE, families[f], TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (st != ERROR_INSUFFICIENT_BUFFER && st != NO_ERROR) return -(int32_t)st;
    void *table = NULL;
    for (int attempt = 0; attempt < 4; attempt++) {
      size += 4096;
      free(table);
      table = malloc(size);
      if (!table) return -(int32_t)ERROR_OUTOFMEMORY;
      st = GetExtendedTcpTable(table, &size, FALSE, families[f], TCP_TABLE_OWNER_PID_LISTENER, 0);
      if (st != ERROR_INSUFFICIENT_BUFFER) break;
    }
    if (st != NO_ERROR) { free(table); return -(int32_t)st; }
    if (families[f] == AF_INET) {
      MIB_TCPTABLE_OWNER_PID *t = (MIB_TCPTABLE_OWNER_PID *)table;
      for (DWORD i = 0; i < t->dwNumEntries; i++) {
        SOCKADDR_INET a;
        memset(&a, 0, sizeof a);
        a.Ipv4.sin_family = AF_INET;
        a.Ipv4.sin_addr.s_addr = t->table[i].dwLocalAddr;
        put_addr(&w, &a);
        put_u16(&w, ntohs((u_short)t->table[i].dwLocalPort));
        put_u32(&w, t->table[i].dwOwningPid);
        count++;
      }
    } else {
      MIB_TCP6TABLE_OWNER_PID *t = (MIB_TCP6TABLE_OWNER_PID *)table;
      for (DWORD i = 0; i < t->dwNumEntries; i++) {
        SOCKADDR_INET a;
        memset(&a, 0, sizeof a);
        a.Ipv6.sin6_family = AF_INET6;
        memcpy(&a.Ipv6.sin6_addr, t->table[i].ucLocalAddr, 16);
        put_addr(&w, &a);
        put_u16(&w, ntohs((u_short)t->table[i].dwLocalPort));
        put_u32(&w, t->table[i].dwOwningPid);
        count++;
      }
    }
    free(table);
  }
  if (!w.overflow) memcpy(out, &count, 4);
  return finish(&w);
}

// Interfaces with their unicast prefixes.
// out: u32 count, then count x { u32 if_index (IPv4 index, else IPv6),
//      u32 if_type, u8 oper_up, str alias, str description,
//      u8 n, n x { addr (17 bytes), u8 prefix_len } }
int32_t nw_interfaces(uint8_t *out, int32_t cap) {
  ULONG size = 32 * 1024;
  IP_ADAPTER_ADDRESSES *list = NULL;
  ULONG st = ERROR_BUFFER_OVERFLOW;
  for (int attempt = 0; attempt < 4 && st == ERROR_BUFFER_OVERFLOW; attempt++) {
    free(list);
    list = (IP_ADAPTER_ADDRESSES *)malloc(size);
    if (!list) return -(int32_t)ERROR_OUTOFMEMORY;
    st = GetAdaptersAddresses(AF_UNSPEC,
                              GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                              NULL, list, &size);
  }
  if (st != NO_ERROR) { free(list); return -(int32_t)st; }
  wbuf w = {out, 0, cap, 0};
  uint32_t count = 0;
  put_u32(&w, 0);
  for (IP_ADAPTER_ADDRESSES *a = list; a; a = a->Next) {
    put_u32(&w, a->IfIndex ? a->IfIndex : a->Ipv6IfIndex);
    put_u32(&w, a->IfType);
    put_u8(&w, a->OperStatus == IfOperStatusUp ? 1 : 0);
    put_wstr(&w, a->FriendlyName);
    put_wstr(&w, a->Description);
    uint8_t n = 0;
    for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u && n < 255; u = u->Next) n++;
    put_u8(&w, n);
    uint8_t k = 0;
    for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u && k < n; u = u->Next, k++) {
      SOCKADDR_INET s;
      memset(&s, 0, sizeof s);
      memcpy(&s, u->Address.lpSockaddr,
             u->Address.iSockaddrLength < (INT)sizeof s ? (size_t)u->Address.iSockaddrLength : sizeof s);
      put_addr(&w, &s);
      put_u8(&w, u->OnLinkPrefixLength);
    }
    count++;
  }
  free(list);
  if (!w.overflow) memcpy(out, &count, 4);
  return finish(&w);
}

// Drive letters and the NT device each maps to ("C:" -> "\Device\HarddiskVolume3").
// out: u32 count, then count x { u8 letter, str device }
int32_t nw_dos_devices(uint8_t *out, int32_t cap) {
  wbuf w = {out, 0, cap, 0};
  uint32_t count = 0;
  put_u32(&w, 0);
  DWORD drives = GetLogicalDrives();
  for (int i = 0; i < 26; i++) {
    if (!(drives & (1u << i))) continue;
    WCHAR name[3] = {(WCHAR)(L'A' + i), L':', 0};
    WCHAR target[1024];
    if (QueryDosDeviceW(name, target, 1024) == 0) continue;
    put_u8(&w, (uint8_t)('A' + i));
    put_wstr(&w, target);  // first string of the multi-string is the current mapping
    count++;
  }
  if (!w.overflow) memcpy(out, &count, 4);
  return finish(&w);
}
