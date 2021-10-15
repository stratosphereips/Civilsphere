rule MALTRAFFIC_AndroidTester_RAT_202107 {
   meta:
      description = "Detects Network Traffic CC of AndroidTester RAT"
      author = "Veronica Valeros"
      reference = "https://www.stratosphereips.org/blog/2020/12/14/ngwqj0h060yv40w1afp51fg7wo9ijy-pzlhk"
      date = "2021-07-22"
      pcap1 = "https://mcfp.felk.cvut.cz/publicDatasets/Android-Mischief-Dataset/AndroidMischiefDataset_v2/RAT01_AndroidTester/RAT01_AndroidTester.pcap"
   strings:
      $s1 = "poing" fullword ascii
   condition:
      all of them
}
