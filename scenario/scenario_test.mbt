///|
let synthetic_recording : String =
  #|{"k":"hdr","v":1,"t0":"134389774848293434","note":"synthetic","devices":[],"cores":[{"pid":14948,"name":"FlClashCore.exe"}],"tun":[],"listeners":[{"addr":"127.0.0.1","port":7890,"pid":14948}],"procs":[[17716,20008,"C:\\Windows\\System32\\curl.exe"],[17800,20008,"C:\\Windows\\System32\\curl.exe"]]}
  #|{"k":"net","t":1,"id":10,"pid":17716,"size":950,"sa":"127.0.0.1","sp":64607,"da":"127.0.0.1","dp":7890}
  #|{"k":"net","t":2,"id":11,"pid":17716,"size":5003000,"sa":"127.0.0.1","sp":64607,"da":"127.0.0.1","dp":7890}
  #|{"k":"mlog","t":5,"line":"[TCP] 127.0.0.1:64607(curl.exe) --> speed.cloudflare.com:443 match Match using Group 1[Node A]"}
  #|{"k":"net","t":9,"id":11,"pid":17800,"size":5003000,"sa":"10.0.0.6","sp":50001,"da":"104.16.1.1","dp":443}

///|
let synthetic_manifest : String =
  #|﻿{"mode":"syn","recording":"syn.ndjson","scenarios":[
  #| {"name":"curl-proxy-port","pid":17716,"exit_code":0,
  #|  "expect":{"process":"curl.exe","entry":"proxy-port","exit":"core","down_min":5000000,"only":true}},
  #| {"name":"curl-noproxy-v4","pid":17800,"exit_code":0,
  #|  "expect":[{"process":"curl.exe","entry":"proxy-port","exit":"core","down_min":5000000,"only":true}]},
  #| {"name":"curl-noproxy-v6","pid":1,"exit_code":6,"expect":[]}]}

///|
test "check reports pass, fail with the actual flows, and skip" {
  let m = @scenario.parse_manifest(synthetic_manifest)
  let rec = @ledger.parse_recording(synthetic_recording)
  inspect(
    @scenario.outcome_text(@scenario.check(m, rec)),
    content=(
      #|PASS curl-proxy-port: curl.exe proxy-port/core 4.8 MB
      #|FAIL curl-noproxy-v4:
      #|  curl.exe: proxy-port/core received 0 B, expected at least 5000000 B; flows: tcp 104.16.1.1:443 bypass/- down=5003000
      #|SKIP curl-noproxy-v6: command exited with 6
    ),
  )
}

///|
/// Finds testdata/scenarios whatever directory the test runs in.
async fn scenario_dir() -> String? {
  for
    d in [
      "testdata/scenarios", "../testdata/scenarios", "../../testdata/scenarios",
    ] {
    if @fs.exists(d) {
      return Some(d)
    }
  }
  None
}

///|
async test "recorded scenarios replay to their known outcomes" {
  guard scenario_dir() is Some(dir) else { return }
  for name in @fs.readdir(dir) {
    guard name.has_suffix(".manifest.json") else { continue }
    let m = @scenario.parse_manifest(@fs.read_file("\{dir}/\{name}").text())
    let rec = @ledger.parse_recording(
      @fs.read_file("\{dir}/\{m.recording}").text(),
    )
    let results = @scenario.check(m, rec)
    let failed = results.filter(r => r.1 is Fail(_))
    if failed.length() > 0 {
      fail("\{name}:\n" + @scenario.outcome_text(failed))
    }
  }
}
