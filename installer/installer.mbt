// What `install` sets up, as pure functions (tested), executed by
// `netwhered install` in an elevated process.
//
// Layout under %ProgramData%\netwhere:
//   bin\netwhered.exe     collector binary run by the task (admin-only write)
//   ledger.db (+wal/shm)  written by the collector, readable by the user
//   requests\             mailbox: the user may create files here
//   config.json           user-editable settings
//   builtin-rules.txt     generated rule set (optional)
//   owner.sid             the installing user's SID
//   netwhered.log

///|
pub let task_name : String = "netwhere"

///|
fn xml_escape(s : String) -> String {
  let b = StringBuilder()
  for c in s {
    match c {
      '&' => b.write_string("&amp;")
      '<' => b.write_string("&lt;")
      '>' => b.write_string("&gt;")
      '"' => b.write_string("&quot;")
      _ => b.write_char(c)
    }
  }
  b.to_string()
}

///|
/// Task Scheduler definition: started on demand only (no trigger), with
/// highest privileges, no time limit, restarted on failure. The user's own
/// unelevated processes may run and end it without a UAC prompt, so start
/// at login is the tray's HKCU Run entry (`run_key_*`), which the user turns
/// on and off without elevation. A collector that exits after a stop
/// request returns 0 and is not restarted.
pub fn task_xml(sid : String, exe : String) -> String {
  let sid = xml_escape(sid)
  let exe = xml_escape(exe)
  (
    $|<?xml version="1.0" encoding="UTF-16"?>
    $|<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    $|  <RegistrationInfo>
    $|    <Description>netwhere collector: records where each program's traffic goes</Description>
    $|  </RegistrationInfo>
    $|  <Principals>
    $|    <Principal id="Author">
    $|      <UserId>\{sid}</UserId>
    $|      <LogonType>InteractiveToken</LogonType>
    $|      <RunLevel>HighestAvailable</RunLevel>
    $|    </Principal>
    $|  </Principals>
    $|  <Settings>
    $|    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    $|    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    $|    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    $|    <AllowHardTerminate>true</AllowHardTerminate>
    $|    <StartWhenAvailable>true</StartWhenAvailable>
    $|    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    $|    <IdleSettings>
    $|      <StopOnIdleEnd>false</StopOnIdleEnd>
    $|      <RestartOnIdle>false</RestartOnIdle>
    $|    </IdleSettings>
    $|    <AllowStartOnDemand>true</AllowStartOnDemand>
    $|    <Enabled>true</Enabled>
    $|    <Hidden>false</Hidden>
    $|    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    $|    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    $|    <Priority>7</Priority>
    $|    <RestartOnFailure>
    $|      <Interval>PT1M</Interval>
    $|      <Count>3</Count>
    $|    </RestartOnFailure>
    $|  </Settings>
    $|  <Actions Context="Author">
    $|    <Exec>
    $|      <Command>"\{exe}"</Command>
    $|      <Arguments>run --detach</Arguments>
    $|    </Exec>
    $|  </Actions>
    $|</Task>
    $|
  )
}

///|
/// UTF-16LE with a byte-order mark: what schtasks /XML expects.
pub fn utf16le_bom(s : String) -> Bytes {
  let n = s.length()
  Bytes::makei(2 + 2 * n, i => {
    if i == 0 {
      b'\xFF'
    } else if i == 1 {
      b'\xFE'
    } else {
      let cu = s.code_unit_at((i - 2) / 2).to_int()
      (if (i - 2) % 2 == 0 { cu & 0xff } else { cu >> 8 }).to_byte()
    }
  })
}

///|
/// One external command: program and arguments (quoted by the caller).
#derive(Eq, Debug)
pub(all) struct Command {
  program : String
  args : Array[String]
}

///|
/// Well-known SIDs: LocalSystem and BUILTIN\Administrators.
let system_sid : String = "S-1-5-18"

///|
let admins_sid : String = "S-1-5-32-544"

///|
/// Permissions: SYSTEM and Administrators full control everywhere; the
/// installing user read and execute everywhere, modify in requests\ and
/// on config.json only. Inheritance from ProgramData is cut so that no
/// other account can write anything the elevated collector reads or runs.
pub fn acl_commands(
  icacls : String,
  dir : String,
  sid : String,
) -> Array[Command] {
  [
    {
      program: icacls,
      args: [
        dir,
        "/inheritance:r",
        "/grant:r",
        "*\{system_sid}:(OI)(CI)F",
        "*\{admins_sid}:(OI)(CI)F",
        "*\{sid}:(OI)(CI)RX",
      ],
    },
    {
      program: icacls,
      args: [dir + "\\requests", "/grant", "*\{sid}:(OI)(CI)M"],
    },
    { program: icacls, args: [dir + "\\config.json", "/grant", "*\{sid}:M"], },
  ]
}

///|
pub fn register_commands(
  schtasks : String,
  xml_path : String,
) -> Array[Command] {
  [
    {
      program: schtasks,
      args: ["/Create", "/TN", task_name, "/XML", xml_path, "/F"],
    },
    { program: schtasks, args: ["/Run", "/TN", task_name], },
  ]
}

///|
pub fn unregister_commands(schtasks : String) -> Array[Command] {
  [
    { program: schtasks, args: ["/End", "/TN", task_name], },
    { program: schtasks, args: ["/Delete", "/TN", task_name, "/F"], },
  ]
}

///|
/// A plausible user SID: "S-1-5-21-" followed by digits and dashes.
pub fn valid_user_sid(s : String) -> Bool {
  if !s.has_prefix("S-1-5-21-") || s.length() > 100 {
    return false
  }
  for c in s {
    match c {
      'S' | '-' | '0'..<='9' => ()
      _ => return false
    }
  }
  true
}
