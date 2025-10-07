rule capture_flag {
  strings:
    $flag = /flag\{[^\}\r\n]{1,1024}\}/i ##change flag par le format du flag
  condition:
    $flag
}
