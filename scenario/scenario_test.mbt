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

///|
async test "built-in rules classify well-known domains" {
  let path = for
    p in [
      "rules/builtin.txt", "../rules/builtin.txt", "../../rules/builtin.txt",
    ] {
    if @fs.exists(p) {
      break Some(p)
    }
  } nobreak {
    None
  }
  guard path is Some(path) else { return }
  let set = @rules.RuleSet::new()
  let n = @rules.load_builtin(set, @fs.read_file(path).text())
  assert_true(n > 5000, msg="only \{n} patterns")
  let app = fn(d : String) {
    match set.classify("x.exe", Some(d)) {
      Some(c) => c.app
      None => "Unknown"
    }
  }
  inspect(
    [
      "www.youtube.com", "i.ytimg.com", "www.google.com", "api.github.com", "github.githubassets.com",
      "login.microsoftonline.com", "www.bilibili.com", "chatgpt.com", "api.anthropic.com",
      "www.tiktok.com", "www.douyin.com", "speed.cloudflare.com", "example.org",
    ]
    .map(d => d + "=" + app(d))
    .join("\n"),
    content=(
      #|www.youtube.com=YouTube
      #|i.ytimg.com=YouTube
      #|www.google.com=Google
      #|api.github.com=GitHub
      #|github.githubassets.com=GitHub
      #|login.microsoftonline.com=Microsoft
      #|www.bilibili.com=Bilibili
      #|chatgpt.com=OpenAI
      #|api.anthropic.com=Anthropic
      #|www.tiktok.com=TikTok
      #|www.douyin.com=ByteDance
      #|speed.cloudflare.com=Cloudflare
      #|example.org=Unknown
    ),
  )
}

///|
async test "recorded bypasses get their causes" {
  guard scenario_dir() is Some(dir) else { return }
  let out = StringBuilder()
  // system-proxy-noenv: recorded in a terminal without proxy variables;
  // system-proxy and tun: with HTTPS_PROXY set in the terminal.
  for
    name in [
      "system-proxy-noenv.manifest.json", "system-proxy.manifest.json", "tun.manifest.json",
    ] {
    let m = @scenario.parse_manifest(@fs.read_file("\{dir}/\{name}").text())
    let rec = @ledger.parse_recording(
      @fs.read_file("\{dir}/\{m.recording}").text(),
    )
    let stem = name.strip_suffix(".manifest.json").unwrap().to_owned()
    for d in @scenario.diagnoses(m, rec) {
      for line in d.1 {
        out.write_string("\{stem} \{d.0}: \{line}\n")
      }
    }
  }
  inspect(
    out.to_string(),
    content=(
      #|system-proxy-noenv curl-noproxy-v4: curl.exe tcp 172.66.0.218:443 no-proxy-config (likely)
      #|system-proxy-noenv curl-noproxy-v6: curl.exe tcp [2606:4700:7::da]:443 no-proxy-config (likely)
      #|system-proxy-noenv git-ls-remote: git-remote-https.exe tcp 20.205.243.166:443 no-proxy-config (likely)
      #|system-proxy curl-noproxy-v4: curl.exe tcp 172.66.0.218:443 undetermined (undetermined)
      #|system-proxy curl-noproxy-v6: curl.exe tcp [2606:4700:7::da]:443 undetermined (undetermined)
      #|system-proxy nslookup-udp: nslookup.exe udp 1.1.1.1:53 udp-not-proxied (certain)
      #|tun curl-noproxy-v6: curl.exe tcp [2606:4700:7::da]:443 tun-no-ipv6 (certain)
      #|tun curl-bound-physical: curl.exe tcp 198.18.0.15:443 bound-off-tun (certain)
      #|
    ),
  )
}
