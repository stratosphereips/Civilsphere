rule MALTRAFFIC_DroidJack_RAT_202107 {
   meta:
      description = "Detects Network Traffic CC of DroidJack RAT"
      author = "Veronica Valeros"
      reference = "https://www.stratosphereips.org/blog/2021/1/22/analysis-of-droidjack-v44-rat-network-traffic"
      date = "2021-07-22"
      pcap1 = "https://mcfp.felk.cvut.cz/publicDatasets/Android-Mischief-Dataset/AndroidMischiefDataset_v2/RAT02_DroidJack/RAT02_DroidJack.pcap"
   strings:
      $s1 = { 20 6B 65 65 70 3A 61 6C 69 76 }
      $s2 = { ?? 23 66 61 6C 73 65 23 ?? }
   condition:
      any of them
}
