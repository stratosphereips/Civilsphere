rule MALTRAFFIC_Saefko_RAT_202107 {
   meta:
      description = "Detects Network Traffic CC of Saefko RAT"
      author = "Veronica Valeros"
      reference = "https://www.stratosphereips.org/blog/2021/6/2/dissecting-a-rat-analysis-of-the-saefko-rat"
      date = "2021-07-22"
      pcap1 = "https://mcfp.felk.cvut.cz/publicDatasets/Android-Mischief-Dataset/AndroidMischiefDataset_v2/RAT06_Saefko/RAT06_Saefko.pcap"
   strings:
      $s1 = "eyJUeXBlIjoiTG9hZFNNUyIsIkRhdGEiOiIxIn0" fullword ascii
      $s2 = "eyJUeXBlIjoiSWRlbnRpZml5IiwiRGF0YSI6Im" fullword ascii
      $s3 = "eyJUeXBlIjoi" fullword ascii
   condition:
      any of them
}
