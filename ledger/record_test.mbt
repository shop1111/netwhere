///|
fn sample_recording() -> @ledger.Recording {
  let t0 = 134389774848293434L
  let ip = fn(s : String) { @netaddr.IpAddr::parse(s).unwrap() }
  {
    header: {
      version: 1,
      t0,
      note: "unit test",
      devices: @ledger.DeviceMap::new([("\\Device\\HarddiskVolume3", "C:")]),
      cores: [{ pid: 14948, name: "FlClashCore.exe", }],
      tun: [
        {
          if_index: 42,
          if_name: "FlClash",
          prefixes: [@netaddr.Cidr::parse("198.18.0.1/30").unwrap()],
        },
      ],
      listeners: [{ addr: ip("127.0.0.1"), port: 7890, pid: 14948, }],
    },
    records: [
      ProcStart({
        t: t0 + 10L,
        pid: 17716,
        ppid: 20008,
        create_time: t0 + 9L,
        image: "\\Device\\HarddiskVolume3\\Windows\\System32\\curl.exe",
      }),
      Dns({
        t: t0 + 20L,
        id: 3020,
        header_pid: 2504,
        client_pid: Some(17716),
        name: "speed.cloudflare.com",
        status: 0,
        results: "198.18.0.13;",
      }),
      Dns({
        t: t0 + 21L,
        id: 3008,
        header_pid: 17716,
        client_pid: None,
        name: "x.test",
        status: 87,
        results: "",
      }),
      Net({
        t: t0 + 30L,
        id: 11,
        pid: 17716,
        size: 4380,
        saddr: "10.0.0.5",
        sport: 50211,
        daddr: "198.18.0.13",
        dport: 443,
      }),
      Route({
        t: t0 + 31L,
        dst: ip("198.18.0.13"),
        if_index: 42,
        if_name: "FlClash",
        via_tun: true,
      }),
      MihomoSnapshot(t0 + 40L, { "connections": [], "downloadTotal": 5 }),
      MihomoLog(
        t0 + 41L,
        "[TCP] 127.0.0.1:63010(curl.exe) --> www.baidu.com:443 match DomainSuffix(baidu.com) using DIRECT",
      ),
      Listeners(t0 + 50L, [{ addr: ip("::1"), port: 9090, pid: 14948, }]),
      ProcStop({ t: t0 + 60L, pid: 17716, create_time: t0 + 9L, exit_code: 0, }),
    ],
  }
}

///|
test "recording round trip" {
  let rec = sample_recording()
  let text = rec.to_text()
  let back = @ledger.parse_recording(text)
  assert_eq(back.header, rec.header)
  assert_eq(back.records, rec.records)
  // Absolute ticks stay exact: t0 is a string, times are small offsets.
  inspect(
    text.split("\n").collect()[4],
    content=(
      #|{"k":"net","t":30,"id":11,"pid":17716,"size":4380,"sa":"10.0.0.5","sp":50211,"da":"198.18.0.13","dp":443}
    ),
  )
}

///|
fn parse_error(text : String) -> String {
  try {
    let _ = @ledger.parse_recording(text)
    "parsed without error"
  } catch {
    e => e.to_string()
  }
}

///|
test "recording errors name the line" {
  let header = sample_recording().header.to_line()
  let bad_kind = header + "\n\n{\"k\":\"weird\",\"t\":1}\n"
  let e1 = parse_error(bad_kind)
  inspect(e1, content="recording line 3: unknown record kind \"weird\"")
  let missing = header + "\n{\"k\":\"net\",\"t\":1}\n"
  let e2 = parse_error(missing)
  inspect(e2, content="recording line 2: missing field \"id\"")
  let no_header = "{\"k\":\"net\",\"t\":1}"
  let e3 = parse_error(no_header)
  inspect(e3, content="recording line 1: first line must be the header")
  let e4 = parse_error("\n \n")
  inspect(e4, content="recording line 0: empty recording")
  let e5 = parse_error("{not json")
  assert_true(e5.has_prefix("recording line 1: invalid JSON"))
}

///|
test "crlf line endings are accepted" {
  let text = sample_recording().to_text().replace_all(old="\n", new="\r\n")
  let back = @ledger.parse_recording(text)
  assert_eq(back.records.length(), 9)
}
