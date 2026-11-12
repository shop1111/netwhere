///|
let sid : String = "S-1-5-21-1111111111-2222222222-3333333333-1001"

///|
test "task definition" {
  let xml = @installer.task_xml(
    sid, "C:\\ProgramData\\net&where\\bin\\netwhered.exe",
  )
  assert_true(xml.has_prefix("<?xml version=\"1.0\" encoding=\"UTF-16\"?>"))
  assert_true(xml.contains("<RunLevel>HighestAvailable</RunLevel>"))
  assert_true(xml.contains("<UserId>\{sid}</UserId>"))
  assert_true(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"))
  assert_true(
    xml.contains(
      "<Command>\"C:\\ProgramData\\net&amp;where\\bin\\netwhered.exe\"</Command>",
    ),
  )
  assert_true(xml.contains("<Arguments>run --detach</Arguments>"))
}

///|
test "utf-16le with bom" {
  let b = @installer.utf16le_bom("A中")
  assert_eq(b.length(), 6)
  assert_eq(b[0], b'\xFF')
  assert_eq(b[1], b'\xFE')
  assert_eq(b[2], b'A')
  assert_eq(b[3], b'\x00')
  assert_eq(b[4], b'\x2D')
  assert_eq(b[5], b'\x4E')
}

///|
test "permissions" {
  let cmds = @installer.acl_commands(
    "icacls.exe", "C:\\ProgramData\\netwhere", sid,
  )
  inspect(
    cmds.map(c => c.args.join(" ")).join("\n"),
    content=(
      #|C:\ProgramData\netwhere /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-21-1111111111-2222222222-3333333333-1001:(OI)(CI)RX
      #|C:\ProgramData\netwhere\requests /grant *S-1-5-21-1111111111-2222222222-3333333333-1001:(OI)(CI)M
      #|C:\ProgramData\netwhere\config.json /grant *S-1-5-21-1111111111-2222222222-3333333333-1001:M
    ),
  )
}

///|
test "sid validation" {
  assert_true(@installer.valid_user_sid(sid))
  assert_false(@installer.valid_user_sid("S-1-5-18"))
  assert_false(@installer.valid_user_sid("S-1-5-21-1 & calc"))
  assert_false(@installer.valid_user_sid(""))
}
