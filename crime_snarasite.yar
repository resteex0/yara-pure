import "pe"

rule BKDR_Snarasite_Oct17 {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-10-07"
      hash1 = "36ba92cba23971ca9d16a0b4f45c853fd5b3108076464d5f2027b0f56054fd62"
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and (
          or
         
      )
}
