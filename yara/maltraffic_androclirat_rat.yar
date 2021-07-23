rule MALTRAFFIC_AndroCLIRAT_RAT_202107 {
   meta:
      description = "Detects Network Traffic CC of AndroCLIRAT RAT"
      author = "Veronica Valeros"
      reference = "https://www.stratosphereips.org/blog/2021/5/6/dissecting-a-rat-analysis-of-the-command-line-androrat"
      date = "2021-07-22"
      pcap1 = "https://mcfp.felk.cvut.cz/publicDatasets/Android-Mischief-Dataset/AndroidMischiefDataset_v2/RAT08_cli_AndroRAT/RAT08_cli_AndroRAT.pcap"
   strings:
      $str_cli_end123 = { 45 4E 44 31 32 33 }
   condition:
      any of them
}
