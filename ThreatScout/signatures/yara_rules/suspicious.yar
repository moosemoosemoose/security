rule Suspicious_Executable_Behavior
{
    meta:
        description = "Detects suspicious behavioral indicators in Windows executables"
        author = "YourName"
        confidence = "medium"
        scope = "behavioral"
        last_updated = "2025-01-01"

    strings:
        /* Command execution */
        $cmd1 = "cmd.exe /c" ascii nocase
        $cmd2 = "powershell -enc" ascii nocase
        $cmd3 = "powershell.exe" ascii nocase
        $cmd4 = "whoami" ascii nocase

        /* Process injection / memory abuse */
        $mem1 = "VirtualAllocEx" ascii
        $mem2 = "WriteProcessMemory" ascii
        $mem3 = "CreateRemoteThread" ascii
        $mem4 = "NtCreateThreadEx" ascii

        /* Dynamic loading / evasion */
        $dyn1 = "LoadLibraryA" ascii
        $dyn2 = "GetProcAddress" ascii

        /* Persistence */
        $reg1 = "RegSetValueExA" ascii
        $reg2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase

        /* Networking / payload retrieval */
        $net1 = "URLDownloadToFileA" ascii
        $net2 = "InternetOpenA" ascii
        $net3 = "InternetConnectA" ascii
        $net4 = "WinHttpOpen" ascii

        /* Simple obfuscation / loader stubs */
        $xor_stub1 = { 31 C0 31 DB 31 C9 31 D2 }   // XOR zeroing registers
        $xor_stub2 = { 33 C0 33 DB 33 C9 }         // alternate zeroing

    condition:
        /* PE executable only */
        uint16(0) == 0x5A4D and

        (
            /* Multiple behavioral indicators */
            3 of ($cmd*, $mem*, $net*, $reg*) or

            /* Loader + memory abuse */
            (2 of ($mem*) and 1 of ($dyn*)) or

            /* Obfuscation + suspicious behavior */
            (1 of ($xor_stub*) and 2 of ($cmd*, $mem*, $net*))
        )
}
