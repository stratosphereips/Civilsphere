rule MALTRAFFIC_GenericDataLeak_202107 {
   meta:
      description = "Detects Data Leaks"
      author = "Veronica Valeros"
      reference = ""
      date = "2021-07-22"
      hash1 = ""
   strings:
      $str_dcim = "/DCIM" fullword ascii
      $str_storage = "/storage" fullword ascii
      $str_sms = "//sms" fullword ascii
      $s4 = { 00 02 ff 34 30 }
      $str_b64_data = "IkRhdGEi" fullword ascii
      $str_imei = { 49 4D 45 49 }
   condition:
      any of them
}
