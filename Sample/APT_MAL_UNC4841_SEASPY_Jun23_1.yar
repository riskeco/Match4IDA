
rule APT_MAL_UNC4841_SEASPY_Jun23_1 {
   meta:
      description = "Detects SEASPY malware used by UNC4841 in attacks against Barracuda ESG appliances exploiting CVE-2023-2868"
      author = "Florian Roth"
      reference = "https://blog.talosintelligence.com/alchimist-offensive-framework/"
      date = "2023-06-16"
      score = 85
      hash1 = "3f26a13f023ad0dcd7f2aa4e7771bba74910ee227b4b36ff72edc5f07336f115"
   strings:
      $sx1 = "usage: ./BarracudaMailService <Network-Interface>. e.g.: ./BarracudaMailService eth0" ascii fullword
      $s1 = "fcntl.tmp.amd64." ascii
      $s2 = "Child process id:%d" ascii fullword
      $s3 = "[*]Success!" ascii fullword
      $s4 = "NO port code" ascii 
      $s5 = "enter open tty shell" ascii
      $op1 = { 48 89 c6 f3 a6 0f 84 f7 01 00 00 bf 6c 84 5f 00 b9 05 00 00 00 48 89 c6 f3 a6 0f 84 6a 01 00 00 }
      $op2 = { f3 a6 0f 84 d2 00 00 00 48 89 de bf 51 5e 61 00 b9 05 00 00 00 f3 a6 74 21 48 89 de }
      $op3 = { 72 de 45 89 f4 e9 b8 f4 ff ff 48 8b 73 08 45 85 e4 ba 49 3d 62 00 b8 44 81 62 00 48 0f 45 d0 }
   condition:
      uint16(0) == 0x457f
      and filesize < 9000KB
      and 3 of them
      or 5 of them
}
