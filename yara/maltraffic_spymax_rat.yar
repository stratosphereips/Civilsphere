rule MALTRAFFIC_SpyMAX_RAT_202107 {
   meta:
      description = "Detects Network Traffic CC of SpyMax RAT"
      author = "Veronica Valeros"
      reference = "https://www.stratosphereips.org/blog/2021/2/26/dissecting-a-rat-analysis-of-the-spymax"
      date = "2021-07-22"
      pcap1 = "https://mcfp.felk.cvut.cz/publicDatasets/Android-Mischief-Dataset/AndroidMischiefDataset_v2/RAT04_SpyMAX/RAT04_SpyMAX.pcap"
   strings:
      $str_cc_1 = { ?? ?? ?? ?? ?? ?? 1F 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 1F 8B }
      $str_cc_2 = { 32 38 00 1F 8B 08 00 }
   condition:
      all of them
}
