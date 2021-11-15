rule Win32_Ransomware_5ss5c : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "5SS5C"
        description         = "Yara rule that detects 5ss5c ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "5ss5c"
        tc_detection_factor = 5

    strings:

        $find_files_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B FA 89 BD ?? ?? ?? ?? 8B F1 
            8B 5D ?? 33 C0 89 9D ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 89 45 ?? 89 45 ?? 6A ?? 89 45 ?? 
            89 45 ?? 89 45 ?? E8 ?? ?? ?? ?? 89 45 ?? 8D 4D ?? 83 C4 ?? C7 00 ?? ?? ?? ?? C7 40 
            ?? ?? ?? ?? ?? 8B 45 ?? 89 08 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 
            57 8D 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 6A ?? C7 45 ?? 
            ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? 8D 4D 
            ?? C7 00 ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? 8B 45 ?? 89 08 C7 45 ?? ?? ?? ?? ?? C7 45 
            ?? ?? ?? ?? ?? C6 45 ?? ?? C6 45 ?? ?? 6A ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? 8D 4D ?? C7 00 ?? ?? ?? ?? C7 40 ?? 
            ?? ?? ?? ?? 8B 45 ?? 89 08 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? C6 
            45 ?? ?? 6A ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 83 C4 ?? C7 
            00 ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 08 C7 85 ?? ?? ?? ?? ?? ?? 
            ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 0F 57 C0 8B 43 ?? 66 0F D6
        }

        $find_files_p2 = {
            45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 89 45 ?? C6 45 
            ?? ?? 8B 3B 85 FF 74 ?? 6A ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? 
            ?? 8B 47 ?? 8D 8D ?? ?? ?? ?? 89 45 ?? 8D 45 ?? 89 47 ?? 89 7D ?? E8 ?? ?? ?? ?? 6A 
            ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 3B 
            C8 74 ?? 83 78 ?? ?? 8D 48 ?? 72 ?? 8B 09 FF 70 ?? 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 83 BD ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 0F 43 85 ?? ?? ?? ?? 51 
            50 FF 15 ?? ?? ?? ?? 8B C8 89 8D ?? ?? ?? ?? 83 F9 ?? 0F 84 ?? ?? ?? ?? 8B D8 66 66 
            0F 1F 84 00 ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 
            8B 8D ?? ?? ?? ?? 0F 43 45 ?? C7 45 ?? ?? ?? ?? ?? C6 00 ?? 8D 41 ?? 83 79 ?? ?? 72 
            ?? 8B 00 FF 71 ?? 8D 4D ?? 50 E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? 
            ?? 8D 8D ?? ?? ?? ?? 8B D0 8D 79 ?? 8A 01 41 84 C0 75 ?? 2B CF 8D 85 ?? ?? ?? ?? 51 
            50 8B CA E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B D8 F6 85 ?? 
            ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 33 FF FF B7 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 85 
            C0 0F 85 ?? ?? ?? ?? 83 C7 ?? 81 FF ?? ?? ?? ?? 72 ?? 68 ?? ?? ?? ?? 50 8D 85 ?? ?? 
            ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 45 ?? ?? 8D 85 ?? 
            ?? ?? ?? 8B 9D ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 6A ?? 83 CB ?? C7 85 ?? ?? ?? ?? ?? ?? 
            ?? ?? 50 89 9D ?? ?? ?? ?? 89 5D ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? C7
        }

        $find_files_p3 = {
            45 ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 6A ?? 8B 40 ?? C7 84 05 ?? ?? ?? ?? ?? ?? ?? ?? 
            8B 85 ?? ?? ?? ?? 8B 48 ?? 8D 41 ?? 89 84 0D ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 51 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 85 C0 75 
            ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 6A ?? 8B 40 ?? 03 C8 33 C0 39 41 ?? 0F 94 C0 
            8D 04 85 ?? ?? ?? ?? 0B 41 ?? 50 E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 55 ?? 83 7D ?? ?? 8D 
            8D ?? ?? ?? ?? FF 75 ?? 0F 43 55 ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 6A ?? 8B 
            40 ?? 03 C8 33 C0 39 41 ?? 0F 94 C0 8D 04 85 ?? ?? ?? ?? 0B 41 ?? 50 E8 ?? ?? ?? ?? 
            8B 5D ?? 8D 55 ?? 53 FF B5 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 8B 85 ?? 
            ?? ?? ?? 8B 40 ?? 85 FF 0F 85 ?? ?? ?? ?? C7 84 05 ?? ?? ?? ?? ?? ?? ?? ?? 8B 85 ?? 
            ?? ?? ?? 8B 48 ?? 8D 41 ?? 89 84 0D ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 
            85 ?? ?? ?? ?? 8B 40 ?? C7 84 05 ?? ?? ?? ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 48 ?? 
            8D 41 ?? 89 84 0D ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? C6 45 ?? ?? E9 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8D 51 
            ?? 0F 1F 80 ?? ?? ?? ?? 8A 01 41 84 C0 75 ?? 2B CA 8D 85 ?? ?? ?? ?? 51 50 8D 4D
        }

        $find_files_p4 = {
            E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8D 51 ?? 8A 01 41 84 C0 75 ?? 2B CA 8D 85 ?? ?? ?? 
            ?? 51 50 8D 4D ?? E8 ?? ?? ?? ?? 83 EC ?? 8D 45 ?? 83 7D ?? ?? 8B FC 0F 43 45 ?? C7 
            07 ?? ?? ?? ?? C7 47 ?? ?? ?? ?? ?? 89 47 ?? C6 45 ?? ?? 8B 5D ?? 85 DB 74 ?? 6A ?? 
            8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 8B 43 ?? 8D 8D ?? ?? ?? ?? 89 
            47 ?? 89 7B ?? 89 1F E8 ?? ?? ?? ?? 8B 45 ?? 8D 4D ?? 83 EC ?? 83 7D ?? ?? 8B FC 0F 
            43 4D ?? 03 C1 C7 07 ?? ?? ?? ?? C7 47 ?? ?? ?? ?? ?? 89 47 ?? C6 45 ?? ?? 8B 5D ?? 
            85 DB 74 ?? 6A ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 8B 43 ?? 8D 
            8D ?? ?? ?? ?? 89 47 ?? 89 7B ?? 89 1F E8 ?? ?? ?? ?? 83 EC ?? 8D 45 ?? 83 7D ?? ?? 
            8B FC 0F 43 45 ?? C7 07 ?? ?? ?? ?? C7 47 ?? ?? ?? ?? ?? 89 47 ?? C6 45 ?? ?? 8B 5D 
            ?? 85 DB 74 ?? 6A ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 8B 43 ?? 
            8D 8D ?? ?? ?? ?? 89 47 ?? 89 7B ?? 89 1F E8 ?? ?? ?? ?? BA ?? ?? ?? ?? C6 45
        }

        $find_files_p5 = {
            8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? 
            ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? 
            ?? 8D 55 ?? 83 7D ?? ?? 8B 4D ?? 0F 43 55 ?? C7 45 ?? ?? ?? ?? ?? 89 4D ?? 83 F9 ?? 
            72 ?? 49 83 C8 ?? 3B C8 89 4D ?? 0F 42 C1 03 C2 0F 1F 40 ?? 80 38 ?? 75 ?? 0F B6 08 
            80 F9 ?? 75 ?? 33 C9 EB ?? 1B C9 83 C9 ?? 85 C9 74 ?? 3B C2 74 ?? 48 EB ?? 2B C2 EB 
            ?? 83 C8 ?? 6A ?? 8D 78 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 
            83 C4 ?? C7 00 ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 08 C6 45 ?? ?? 
            8B 45 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? 
            ?? ?? 3B C7 0F 82 ?? ?? ?? ?? 2B C7 C7 45 ?? ?? ?? ?? ?? 83 C9 ?? 89 45 ?? 83 F8 ?? 
            0F 42 C8 83 7D ?? ?? 8D 45 ?? 0F 43 45 ?? 51 03 C7 8D 8D ?? ?? ?? ?? 50 E8 ?? ?? ?? 
            ?? 83 8D ?? ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? 
            ?? FF B5 ?? ?? ?? ?? 8D 4D ?? 50 E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D
        }

        $find_files_p6 = {
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 8D 45 ?? 83 7D ?? ?? 8B FC 0F 43 45 ?? C7 07 
            ?? ?? ?? ?? C7 47 ?? ?? ?? ?? ?? 89 47 ?? C6 45 ?? ?? 8B 5D ?? 85 DB 74 ?? 6A ?? 8D 
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 8B 43 ?? 8D 8D ?? ?? ?? ?? 89 47 
            ?? 89 7B ?? 89 1F E8 ?? ?? ?? ?? 8B 45 ?? 8D 4D ?? 83 EC ?? 83 7D ?? ?? 8B FC 0F 43 
            4D ?? 03 C1 C7 07 ?? ?? ?? ?? C7 47 ?? ?? ?? ?? ?? 89 47 ?? C6 45 ?? ?? 8B 5D ?? 85 
            DB 74 ?? 6A ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 8B 43 ?? 8D 8D 
            ?? ?? ?? ?? 89 47 ?? 89 7B ?? 89 1F E8 ?? ?? ?? ?? 83 EC ?? 8D 45 ?? 83 7D ?? ?? 8B 
            FC 0F 43 45 ?? C7 07 ?? ?? ?? ?? C7 47 ?? ?? ?? ?? ?? 89 47 ?? C6 45 ?? ?? 8B 5D ?? 
            85 DB 74 ?? 6A ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 8B 43 ?? 8D 
            8D ?? ?? ?? ?? 89 47 ?? 89 7B ?? 89 1F E8 ?? ?? ?? ?? BA ?? ?? ?? ?? C6 45 ?? ?? 8D 
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? 
            ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 
            33 FF 66 66 0F 1F 84 00 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? FF B7 ?? ?? ?? ?? 0F 43 45 
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 85 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 68 ?? ?? 
            ?? ?? 0F 43 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 85 ?? ?? ?? ?? 83 C7 ?? 83 FF 
            ?? 72 ?? 8B 5D ?? 85 DB 0F 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? 
            ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 8B 46 ?? 8D 4D ?? 51 39 46 ?? 74 ?? 8B C8 E8 ?? ?? ?? 
            ?? 8B 7E ?? 8D 8D ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 8B 0E 8D 41 ?? F7 D9 1B C9 23 C8
        }

        $find_files_p7 = {
            74 ?? 8B 01 85 C0 74 ?? 39 78 ?? 72 ?? 77 ?? C7 00 ?? ?? ?? ?? 8B 01 8B 40 ?? 89 01 
            EB ?? 8D 48 ?? 8B 01 85 C0 75 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 46 ?? ?? EB ?? 
            50 8B CE E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 
            85 C0 75 ?? 8B 46 ?? 8D 4D ?? 51 39 46 ?? 74 ?? 8B C8 E8 ?? ?? ?? ?? 8B 7E ?? 8D 8D 
            ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 8B 0E 8D 41 ?? F7 D9 1B C9 23 C8 74 ?? 8B 01 85 C0 
            74 ?? 66 0F 1F 44 00 ?? 39 78 ?? 72 ?? 77 ?? C7 00 ?? ?? ?? ?? 8B 01 8B 40 ?? 89 01 
            EB ?? 8D 48 ?? 8B 01 85 C0 75 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 46 ?? ?? EB ?? 
            50 8B CE E8 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? 
            ?? ?? 83 8D ?? ?? ?? ?? ?? 8B D8 8B 7D ?? 85 FF 74 ?? 8B 3F 8B CB E8 ?? ?? ?? ?? 3B
        }

        $find_files_p8 = {
            C7 74 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? E8 
            ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 75 ?? CC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 43 ?? 3B 45 ?? 74 ?? 8D 85 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? B3 ?? EB ?? 32 DB 8B 85 ?? 
            ?? ?? ?? A8 ?? 74 ?? 83 E0 ?? 89 85 ?? ?? ?? ?? 6A ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? 
            ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 84 DB 0F 
            84 ?? ?? ?? ?? 8B 46 ?? 8D 4D ?? 51 39 46 ?? 0F 84 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 
            8B 7E ?? 8D 8D ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 8B 0E 8D 41 ?? F7 D9 1B C9 23 C8 74 
            ?? 8B 01 85 C0 74 ?? 90 39 78 ?? 72 ?? 77 ?? C7 00 ?? ?? ?? ?? 8B 01 8B 40 ?? 89 01 
            EB ?? 8D 48 ?? 8B 01 85 C0 75 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 46 ?? ?? E9 ?? 
            ?? ?? ?? 83 FB ?? 0F 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 
            50 E8 ?? ?? ?? ?? 83 8D ?? ?? ?? ?? ?? 8B D8 8B 7D ?? 85 FF 74 ?? 8B 3F 8B CB E8 ?? 
            ?? ?? ?? 3B C7 74 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 75 ?? CC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 43 ?? 3B 45 ?? 75 ?? 8D
        }

        $find_files_p9 = {
            85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? B3 ?? EB ?? 32 
            DB 8B 85 ?? ?? ?? ?? A8 ?? 74 ?? 83 E0 ?? 89 85 ?? ?? ?? ?? 6A ?? 8D 8D ?? ?? ?? ?? 
            C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? C6 45 ?? ?? 84 DB 0F 84 ?? ?? ?? ?? 8B 46 ?? 8D 4D ?? 51 39 46 ?? 0F 84 ?? 
            ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 8B 7E ?? 8D 4D ?? 6A ?? E8 ?? ?? ?? ?? 8B 0E 8D 41 ?? 
            F7 D9 1B C9 23 C8 74 ?? 8B 01 85 C0 74 ?? 39 78 ?? 72 ?? 77 ?? C7 00 ?? ?? ?? ?? 8B 
            01 8B 40 ?? 89 01 EB ?? 8D 48 ?? 8B 01 85 C0 75 ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 46 ?? 
            ?? E9 ?? ?? ?? ?? 83 FB ?? 0F 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 
            ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8B 46 ?? 8D 4D ?? 51 39 46 ?? 74 ?? 8B C8 E8 ?? ?? 
            ?? ?? 8B 7E ?? 8D 4D ?? 6A ?? E8 ?? ?? ?? ?? 8B 0E 8D 41 ?? F7 D9 1B C9 23 C8 74 ?? 
            8B 01 85 C0 74 ?? 66 0F 1F 44 00 ?? 39 78 ?? 72 ?? 77 ?? C7 00 ?? ?? ?? ?? 8B 01 8B
        }

        $find_files_p10 = {
            40 ?? 89 01 EB ?? 8D 48 ?? 8B 01 85 C0 75 ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 46 ?? ?? EB 
            ?? 50 8B CE E8 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? 
            ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F8 83 FF ?? 
            75 ?? 33 FF 6A ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D 
            ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 
            ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D 
            ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B C7 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 
            5E 5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 C7 84 05 ?? ?? ?? ?? ?? ?? ?? ?? 8B 
            85 ?? ?? ?? ?? 8B 48 ?? 8D 41 ?? 89 84 0D ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8B 85 ?? ?? ?? ?? 8B 40 ?? C7 84 05 ?? ?? ?? ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 
            48 ?? 8D 41 ?? 89 84 0D ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? E8
        }

        $encrypt_files_p1 = {
            B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 44 24 ?? 55 8B 6C 24 ?? 56 8B 
            74 24 ?? 57 8B 7C 24 ?? 85 F6 0F 8E ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 
            83 C4 ?? 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 57 E8 
            ?? ?? ?? ?? 83 C4 ?? 89 44 24 ?? 85 C0 75 ?? A1 ?? ?? ?? ?? 85 C0 75 ?? E8 ?? ?? ?? 
            ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 
            ?? 83 C8 ?? 5F 5E 5D 8B 4C 24 ?? 33 CC E8 ?? ?? ?? ?? 83 C4 ?? C3 8B 4C 24 ?? 8B C1 
            83 E8 ?? 74 ?? 51 68 ?? ?? ?? ?? 8D 44 24 ?? 6A ?? 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            83 C4 ?? 85 C0 75 ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 
            ?? 6A ?? 50 E8 ?? ?? ?? ?? 8D 44 24 ?? 50 68 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 C4 
            ?? 83 C8 ?? 5F 5E 5D 8B 4C 24 ?? 33 CC E8 ?? ?? ?? ?? 83 C4 ?? C3 68 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 75 ?? A1 ?? ?? ?? ?? 85 C0 75
        }

        $encrypt_files_p2 = {
            E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 50 E8 ?? ?? 
            ?? ?? 83 C4 ?? 83 C8 ?? 5F 5E 5D 8B 4C 24 ?? 33 CC E8 ?? ?? ?? ?? 83 C4 ?? C3 33 C9 
            85 F6 7E ?? 8D 56 ?? 53 8B 5C 24 ?? 03 D7 66 0F 1F 44 00 ?? 8A 04 19 8D 52 ?? 41 88 
            42 ?? 3B CE 7C ?? 5B 8D 44 24 ?? 89 74 24 ?? 50 8B 44 24 ?? 57 6A ?? 6A ?? 6A ?? FF 
            70 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? A1 ?? ?? ?? ?? 85 C0 75 ?? E8 ?? ?? 
            ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 
            C4 ?? FF 15 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8D 44 24 ?? 6A ?? 50 E8 ?? ?? ?? ?? 8D 44 
            24 ?? 50 68 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? FF 74 24 ?? 57 E8 ?? ?? ?? ?? 68 ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 83 C4 ?? 83 C8 ?? 5F 5E 5D 8B 4C 24 ?? 33 CC 
            E8 ?? ?? ?? ?? 83 C4 ?? C3 8B 74 24 ?? 56 57 55 E8 ?? ?? ?? ?? 56 57 E8 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4C 24 ?? 8B C6 5F 5E 5D 
            33 CC E8 ?? ?? ?? ?? 83 C4 ?? C3
        }

        $remote_connection_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 6A ?? E8 ?? 
            ?? ?? ?? FF 35 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 6A ?? 
            E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 8B D8 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 83 
            C4 ?? 49 90 8A 41 ?? 8D 49 ?? 84 C0 75 ?? A1 ?? ?? ?? ?? BA ?? ?? ?? ?? 83 3D ?? ?? 
            ?? ?? ?? 89 01 A1 ?? ?? ?? ?? 0F 43 15 ?? ?? ?? ?? 89 41 ?? 8B F2 A1 ?? ?? ?? ?? 89 
            41 ?? A1 ?? ?? ?? ?? 89 41 ?? A1 ?? ?? ?? ?? 89 41 ?? 8A 02 42 84 C0 75 ?? 8D BD ?? 
            ?? ?? ?? 2B D6 4F 8A 47 ?? 47 84 C0 75 ?? 8B CA C1 E9 ?? F3 A5 8B CA 83 E1 ?? F3 A4 
            8D 8D ?? ?? ?? ?? 49 8A 41 ?? 8D 49 ?? 84 C0 75 ?? A1 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 
            8B F2 89 01 66 A1 ?? ?? ?? ?? 66 89 41 ?? A0 ?? ?? ?? ?? 88 41 ?? 66 90 8A 02 42 84 
            C0 75 ?? 8D BD ?? ?? ?? ?? 2B D6 4F 8A 47 ?? 47 84 C0 75 ?? 8B CA C1 E9 ?? F3 A5 8B 
            CA 83 E1 ?? F3 A4 8D 8D ?? ?? ?? ?? 49 0F 1F 00 8A 41 ?? 8D 49 ?? 84 C0 75 ?? A1 ?? 
            ?? ?? ?? 8B F3 89 01 66 A1 ?? ?? ?? ?? 66 89 41 ?? A0 ?? ?? ?? ?? 88 41 ?? 8A 03 43 
            84 C0 75 ?? 8D BD ?? ?? ?? ?? 2B DE 4F 8A 47 ?? 47 84 C0 75 ?? 8B CB C1 E9 ?? F3 A5 
            8B CB 83 E1 ?? F3 A4 8D 8D ?? ?? ?? ?? 49 8A 41 ?? 8D 49 ?? 84 C0 75 ?? A1 ?? ?? ?? 
            ?? 8B 95 ?? ?? ?? ?? 8B F2 89 01 A1 ?? ?? ?? ?? 89 41 ?? A0 ?? ?? ?? ?? 88 41 ?? 0F
        }

        $remote_connection_p2 = {
            1F 44 00 ?? 8A 02 42 84 C0 75 ?? 8D BD ?? ?? ?? ?? 2B D6 4F 8A 47 ?? 47 84 C0 75 ?? 
            8B CA C1 E9 ?? F3 A5 8B CA 83 E1 ?? F3 A4 8D 8D ?? ?? ?? ?? 49 0F 1F 00 8A 41 ?? 8D 
            49 ?? 84 C0 75 ?? A1 ?? ?? ?? ?? 89 01 A1 ?? ?? ?? ?? 89 41 ?? A1 ?? ?? ?? ?? 89 41 
            ?? A0 ?? ?? ?? ?? 6A ?? 88 41 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8D 8D ?? ?? 
            ?? ?? 83 C4 ?? C7 00 ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 08 C7 45 
            ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8D 51 ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 0F 1F 00 8A 01 41 84 C0 75 ?? 2B CA 8D 85 ?? 
            ?? ?? ?? 51 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 
            6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 8B D8 85 
            DB 74 ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 83 EC ?? 8D 85 ?? ?? ?? ?? 8B CC 50 E8 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 50 68 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 8B F0 85 F6 
            74 ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 56 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 6A ?? 56 
            FF 15 ?? ?? ?? ?? 56 FF D7 53 FF D7 FF B5 ?? ?? ?? ?? FF D7 8D 8D ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 
            8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($find_files_p*)
        ) and
        (
            all of ($encrypt_files_p*)
        ) and
        (
            all of ($remote_connection_p*)
        )
}