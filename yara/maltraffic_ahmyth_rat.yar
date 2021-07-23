rule MALTRAFFIC_AhMyth_RAT_202107 {
   meta:
      description = "Detects Network Traffic CC of AhMyth RAT"
      author = "Veronica Valeros"
      reference = "https://www.stratosphereips.org/blog/2021/5/6/dissecting-a-rat-analysis-of-the-ahmyth"
      date = "2021-07-22"
      pcap1 = "https://mcfp.felk.cvut.cz/publicDatasets/Android-Mischief-Dataset/AndroidMischiefDataset_v2/RAT07_AhMyth/RAT07_AhMyth.pcap"
   strings:
      $s1 = { ?? ?? 5B 22 6F 72 64 65 72 22 2C 7B 22 ?? }
      $s2 = { 22 78 30 30 30 }
   condition:
      any of them
}
