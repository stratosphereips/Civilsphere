rule MALTRAFFIC_AndroRAT_RAT_202107 {
   meta:
      description = "Detects Network Traffic CC of AndroRAT RAT"
      author = "Veronica Valeros"
      reference = "https://www.stratosphereips.org/blog/2021/3/29/dissecting-a-rat-analysis-of-the-androrat"
      date = "2021-07-22"
      pcap1 = "https://mcfp.felk.cvut.cz/publicDatasets/Android-Mischief-Dataset/AndroidMischiefDataset_v2/RAT05_AndroRAT/RAT05_AndroRAT.pcap"
   strings:
      $s1 = { 00 20 00 00 00 20 01 00 00 00 00 00 d5 40 3c 88 86 59 4a f4 f1 40 50 7d de 69 ad 42 c4 40 2e 16 c1 5f dc 33 }
   condition:
      any of them
}
