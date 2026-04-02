/*
 * Guardian Security Scanner — YARA Rules
 *
 * Coverage:
 *   1.  XCSSET macOS malware
 *   2.  Silver Sparrow macOS malware
 *   3.  ThiefQuest / EvilQuest ransomware/spyware
 *   4.  OSX.Shlayer adware dropper
 *   5.  Atomic Stealer (AMOS) infostealer
 *   6.  MacStealer infostealer
 *   7.  RustBucket (Lazarus) backdoor
 *   8.  Geacon (Go-based macOS Beacon)
 *   9.  XMRig / cryptominer detection
 *  10.  Reverse shell patterns (bash -i, nc -e)
 *  11.  Keylogger indicators (CGEventTap, IOHIDManager)
 *  12.  Screen capture indicators (CGWindowListCreateImage, AVCaptureSession)
 *  13.  Pegasus / NSO Group indicators
 *  14.  Generic UPX-packed Mach-O binary
 *  15.  Generic stripped Mach-O with suspicious strings
 *  16.  Cobalt Strike Beacon beacon config strings
 *  17.  Generic macOS LaunchAgent persistence strings
 *  18.  Frida / dynamic instrumentation gadget
 *  19.  Empire PowerShell macOS stager
 *  20.  Generic Mach-O with privilege escalation strings
 *
 * Sources: public threat intelligence reports from Kaspersky, SentinelOne,
 * Malwarebytes, Objective-See, Trend Micro, and open YARA rule repositories.
 */

// ---------------------------------------------------------------------------
// 1. XCSSET
// ---------------------------------------------------------------------------
rule OSX_XCSSET
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects XCSSET macOS malware infecting Xcode projects"
        severity    = "critical"
        reference   = "https://www.trendmicro.com/en_us/research/20/h/xcsset-mac-malware--infects-xcode-projects--uses-0-days.html"
        hash        = "3f3e95f8cf1bb18f0c929b7e0b0fad6fc7888de16d70ee37e84d70aae9e96fc3"

    strings:
        $s1 = "XCSSET" ascii wide
        $s2 = "xcassets" ascii
        $s3 = "infected_xcode" ascii
        $s4 = "/tmp/xcode_inject" ascii
        $s5 = "safari_remote" ascii
        $s6 = ".xcodeproj" ascii
        $s7 = "xcsset.applescript" ascii
        $s8 = "com.apple.dt.Xcode" ascii
        $b1 = { 58 43 53 53 45 54 }   // "XCSSET" bytes
        $launch = "com.user.update.agent.plist" ascii

    condition:
        (
            (3 of ($s*)) or
            ($b1 and 1 of ($s*)) or
            ($launch and 1 of ($s*))
        )
}

// ---------------------------------------------------------------------------
// 2. Silver Sparrow
// ---------------------------------------------------------------------------
rule OSX_SilverSparrow
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects Silver Sparrow macOS malware (M1-native variant)"
        severity    = "critical"
        reference   = "https://redcanary.com/blog/clipping-silver-sparrows-wings/"

    strings:
        $s1 = "verx" ascii fullword
        $s2 = "tapioka" ascii
        $s3 = "com.updater.mco.plist" ascii
        $s4 = "com.tapioka.plist" ascii
        $s5 = "PlistBuddy" ascii
        $s6 = "self_delete" ascii
        $s7 = "/tmp/verx" ascii
        $s8 = "s3.amazonaws.com/specialattributes" ascii
        $s9 = "updater.pkg" ascii

    condition:
        2 of ($s*)
}

// ---------------------------------------------------------------------------
// 3. ThiefQuest / EvilQuest
// ---------------------------------------------------------------------------
rule OSX_ThiefQuest_EvilQuest
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects ThiefQuest/EvilQuest ransomware and spyware for macOS"
        severity    = "critical"
        reference   = "https://objective-see.org/blog/blog_0x59.html"

    strings:
        $s1  = "mixednkey" ascii
        $s2  = "toolroomd" ascii
        $s3  = "com.apple.questd" ascii
        $s4  = "questd.plist" ascii
        $s5  = "EvilQuest" ascii wide
        $s6  = "ThiefQuest" ascii wide
        $s7  = "find_and_change_encryption_status" ascii
        $s8  = "encrypt_file" ascii
        $s9  = "is_already_encrypted" ascii
        $s10 = "read_file_to_buf" ascii
        $s11 = "run_shell_cmd" ascii
        $s12 = "connect_to_c2" ascii
        $s13 = ".syslog" ascii
        $ransom = "Your files have been encrypted" ascii wide

    condition:
        3 of ($s*) or $ransom
}

// ---------------------------------------------------------------------------
// 4. OSX.Shlayer
// ---------------------------------------------------------------------------
rule OSX_Shlayer
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects OSX.Shlayer adware dropper"
        severity    = "high"
        reference   = "https://securelist.com/shlayer-for-macos/95724/"

    strings:
        $s1 = "com.adobe.GC.Invoker" ascii
        $s2 = "com.adobe.GC.Inv.plist" ascii
        $s3 = "ADOBE_GC" ascii
        $s4 = "/var/tmp/.lauch" ascii
        $s5 = "flashplayer_" ascii nocase
        $s6 = "AdobeFlash" ascii nocase
        $s7 = "installFlash" ascii nocase
        $s8 = "curl -s http" ascii
        $s9 = "base64 -D" ascii
        $sh = { 62 61 73 65 36 34 20 2D 44 }   // "base64 -D"
        $pkg = "package.pkg" ascii nocase

    condition:
        (2 of ($s*)) or ($sh and ($s5 or $s6 or $s7)) or $pkg
}

// ---------------------------------------------------------------------------
// 5. Atomic Stealer (AMOS)
// ---------------------------------------------------------------------------
rule OSX_AtomicStealer
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects Atomic Stealer (AMOS) macOS infostealer"
        severity    = "critical"
        reference   = "https://www.malwarebytes.com/blog/threat-intelligence/2023/04/atomic-macos-stealer-is-sold-for-1-000-per-month-on-telegram"

    strings:
        $s1  = "AtomicStealer" ascii wide nocase
        $s2  = "osascript -e 'display dialog" ascii
        $s3  = "grab_keychain" ascii
        $s4  = "steal_browser" ascii
        $s5  = "get_crypto_wallets" ascii
        $s6  = "MetaMask" ascii
        $s7  = "Exodus" ascii
        $s8  = "Electrum" ascii
        $s9  = "Telegram bot API" ascii nocase
        $s10 = "api.telegram.org/bot" ascii
        $s11 = "security find-generic-password" ascii
        $s12 = "security find-internet-password" ascii
        $dialog = "Please enter your Mac password" ascii wide nocase

    condition:
        3 of ($s*) or $dialog
}

// ---------------------------------------------------------------------------
// 6. MacStealer
// ---------------------------------------------------------------------------
rule OSX_MacStealer
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects MacStealer infostealer (2023)"
        severity    = "critical"
        reference   = "https://www.uptycs.com/blog/macstealer-command-control-telegram"

    strings:
        $s1 = "MacStealer" ascii wide nocase
        $s2 = "weed" ascii fullword
        $s3 = "api.telegram.org" ascii
        $s4 = "KeychainDump" ascii nocase
        $s5 = "sendDocument" ascii
        $s6 = "chrome_cookies" ascii nocase
        $s7 = "firefox_cookies" ascii nocase
        $s8 = "brave_cookies" ascii nocase
        $s9 = "com.MacStealer.plist" ascii
        $s10 = "security dump-keychain" ascii
        $s11 = "~/Library/Keychains" ascii
        $s12 = "passwords.txt" ascii nocase

    condition:
        ($s1 and 2 of ($s2, $s3, $s4, $s5, $s6, $s7, $s8)) or
        (4 of ($s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12))
}

// ---------------------------------------------------------------------------
// 7. RustBucket (Lazarus Group)
// ---------------------------------------------------------------------------
rule OSX_RustBucket_Lazarus
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects RustBucket macOS backdoor attributed to Lazarus Group (DPRK)"
        severity    = "critical"
        reference   = "https://www.jamf.com/blog/jamf-threat-labs-swift-macos-backdoor/"

    strings:
        $s1 = "rustbucket" ascii nocase
        $s2 = "RustBucket" ascii
        $s3 = "pdf_viewer" ascii nocase
        $s4 = "com.adobedc.notif.plist" ascii
        $s5 = "zsh_history_bak" ascii
        $s6 = "is_first_run" ascii
        $s7 = "check_c2" ascii
        $s8 = "get_commands" ascii
        $s9 = "execute_payload" ascii
        $rust = { 72 75 73 74 63 }   // "rustc" (Rust compiler marker)

    condition:
        ($s1 or $s2 or $rust) and 2 of ($s3, $s4, $s5, $s6, $s7, $s8, $s9)
}

// ---------------------------------------------------------------------------
// 8. Geacon (Go-based Cobalt Strike Beacon for macOS)
// ---------------------------------------------------------------------------
rule OSX_Geacon
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects Geacon, a Go implementation of Cobalt Strike Beacon targeting macOS"
        severity    = "critical"
        reference   = "https://www.sentinelone.com/blog/geacon-brings-cobalt-strike-capabilities-to-macos-threat-actors/"

    strings:
        $s1 = "geacon" ascii nocase
        $s2 = "Geacon" ascii
        $s3 = "geacon_pro" ascii nocase
        $s4 = "BeaconSleep" ascii
        $s5 = "BeaconInjectProcess" ascii
        $s6 = "BeaconGetSpawnTo" ascii
        $s7 = "ReflectiveDLLInject" ascii
        $s8 = "main.BeaconBof" ascii
        $go1 = "go build" ascii
        $go2 = "gobuild" ascii
        $go3 = { 47 6F 20 62 75 69 6C 64 }   // "Go build"

    condition:
        ($s1 or $s2 or $s3) or
        (3 of ($s4, $s5, $s6, $s7, $s8)) or
        ($go1 and 2 of ($s4, $s5, $s6, $s7, $s8)) or
        ($go2 or $go3)
}

// ---------------------------------------------------------------------------
// 9. XMRig Cryptominer
// ---------------------------------------------------------------------------
rule OSX_XMRig_Cryptominer
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects XMRig cryptominer and Stratum protocol usage"
        severity    = "high"
        reference   = "https://xmrig.com/"

    strings:
        $s1  = "xmrig" ascii nocase fullword
        $s2  = "XMRig" ascii
        $s3  = "stratum+tcp://" ascii
        $s4  = "stratum+ssl://" ascii
        $s5  = "pool.minexmr.com" ascii
        $s6  = "xmrpool.eu" ascii
        $s7  = "mining.subscribe" ascii
        $s8  = "mining.authorize" ascii
        $s9  = "RandomX" ascii
        $s10 = "CryptoNight" ascii
        $s11 = "donate-level" ascii
        $s12 = "cpu-max-threads-hint" ascii
        $s13 = "cryptonight" ascii nocase
        $hash_alg = { 43 72 79 70 74 6F 4E 69 67 68 74 }   // "CryptoNight"

    condition:
        ($s1 or $s2) or
        ($s3 or $s4) and (1 of ($s7, $s8, $s9, $s10)) or
        (3 of ($s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13)) or
        $hash_alg
}

// ---------------------------------------------------------------------------
// 10. Reverse Shell Patterns
// ---------------------------------------------------------------------------
rule Generic_ReverseShell
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects common reverse shell patterns in binaries and scripts"
        severity    = "critical"

    strings:
        $bash_i  = "bash -i >& /dev/tcp/" ascii
        $bash_i2 = "bash -i >& /dev/udp/" ascii
        $nc_e    = "nc -e /bin/bash" ascii
        $nc_e2   = "nc -e /bin/sh" ascii
        $nc_e3   = "ncat -e /bin/bash" ascii
        $nc_lv   = "nc -lvp" ascii
        $python_s = "python -c 'import socket,subprocess,os" ascii
        $python_s2 = "python3 -c 'import socket,subprocess,os" ascii
        $perl_s  = "perl -e 'use Socket" ascii
        $ruby_s  = "ruby -rsocket -e" ascii
        $mkfifo  = "mkfifo /tmp/pipe" ascii
        $socat   = "socat exec:" ascii
        $dev_tcp = "/dev/tcp/" ascii
        $pty     = "pty.spawn" ascii

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// 11. Keylogger Indicators
// ---------------------------------------------------------------------------
rule OSX_Keylogger_Indicators
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects keylogger API usage: CGEventTap, IOHIDManager in Mach-O binaries"
        severity    = "high"

    strings:
        $cg1 = "CGEventTapCreate" ascii
        $cg2 = "CGEventTapEnable" ascii
        $cg3 = "kCGEventKeyDown" ascii
        $cg4 = "kCGEventFlagsChanged" ascii
        $cg5 = "CGEventGetIntegerValueField" ascii
        $hid1 = "IOHIDManagerCreate" ascii
        $hid2 = "IOHIDManagerSetDeviceMatchingMultiple" ascii
        $hid3 = "IOHIDManagerRegisterInputValueCallback" ascii
        $hid4 = "IOHIDValueGetElement" ascii
        $hid5 = "kIOHIDElementTypeInput_Button" ascii
        $ax1  = "AXObserverCreate" ascii
        $ax2  = "AXUIElementCreateApplication" ascii

    condition:
        (2 of ($cg*)) or
        (2 of ($hid*)) or
        (1 of ($cg*) and 1 of ($hid*)) or
        (1 of ($ax*) and 2 of ($cg*, $hid*))
}

// ---------------------------------------------------------------------------
// 12. Screen Capture Indicators
// ---------------------------------------------------------------------------
rule OSX_ScreenCapture_Indicators
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects screen capture and session recording API strings in Mach-O binaries"
        severity    = "high"

    strings:
        $cg1  = "CGWindowListCreateImage" ascii
        $cg2  = "CGWindowListCopyWindowInfo" ascii
        $cg3  = "CGDisplayCreateImage" ascii
        $av1  = "AVCaptureSession" ascii
        $av2  = "AVCaptureScreenInput" ascii
        $av3  = "AVAssetWriterInput" ascii
        $rp1  = "RPScreenRecorder" ascii
        $rp2  = "startCaptureWithHandler" ascii
        $sc1  = "SCStreamConfiguration" ascii
        $sc2  = "SCContentFilter" ascii
        $sc3  = "SCShareableContent" ascii

    condition:
        (2 of ($cg*)) or
        (2 of ($av*)) or
        ($rp1 and $rp2) or
        (2 of ($sc*)) or
        (1 of ($cg*) and 1 of ($av*, $rp*, $sc*))
}

// ---------------------------------------------------------------------------
// 13. Pegasus / NSO Group Indicators
// ---------------------------------------------------------------------------
rule iOS_Pegasus_NSO_Indicators
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects file paths and strings associated with Pegasus spyware from public research"
        severity    = "critical"
        reference   = "https://citizenlab.ca/2021/09/forcedentry-nso-group-imessage-zero-click-exploit-captured-in-the-wild/"

    strings:
        // Known Pegasus process names and paths from Citizen Lab / Amnesty Tech reports
        $p1 = "bh" ascii fullword
        $p2 = "msgaccount" ascii
        $p3 = "libtouchregd" ascii
        $p4 = "Backboardd" ascii
        $p5 = "CommCenter" ascii nocase
        $p6 = "IMTransferAgent" ascii
        $p7 = "rolldiced" ascii
        $p8 = "RDRInit" ascii
        $p9 = "/private/var/db/Accessibility/com.apple.accessibility.Assets.plist" ascii
        $p10 = "net.dirapi" ascii
        $p11 = "jbsqli" ascii
        $p12 = "FORCEDENTRY" ascii
        $p13 = "NSO Group" ascii
        $p14 = "Pegasus" ascii
        $p15 = "/tmp/bh" ascii
        // Amnesty Tech MVT IOC paths
        $mvt1 = "com.apple.icloud.fmfd" ascii
        $mvt2 = "idiskstorage" ascii
        $mvt3 = "fseventsd-uuid" ascii
        $mvt4 = ".xpc/com.apple.cfnetwork" ascii

    condition:
        2 of ($p*) or 2 of ($mvt*) or ($p12 or $p13 or $p14)
}

// ---------------------------------------------------------------------------
// 14. Generic UPX-Packed Mach-O
// ---------------------------------------------------------------------------
rule Generic_UPX_Packed_MachO
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects UPX-packed Mach-O binaries, commonly used to evade static analysis"
        severity    = "medium"

    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "$Info: This file is packed with the UPX" ascii
        $upx3 = "UPX 3." ascii
        $upx4 = { 55 50 58 21 }   // UPX! magic
        $macho32 = { CE FA ED FE }   // Mach-O 32-bit LE
        $macho64 = { CF FA ED FE }   // Mach-O 64-bit LE
        $fat     = { CA FE BA BE }   // Fat binary

    condition:
        ($macho32 at 0 or $macho64 at 0 or $fat at 0) and
        (1 of ($upx*))
}

// ---------------------------------------------------------------------------
// 15. Generic Stripped Mach-O with Suspicious Strings
// ---------------------------------------------------------------------------
rule Generic_Suspicious_MachO_Stripped
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects stripped Mach-O binaries with suspicious capability strings"
        severity    = "medium"

    strings:
        $macho64 = { CF FA ED FE }
        $macho32 = { CE FA ED FE }
        // Suspicious capabilities often abused by malware
        $s1 = "/bin/sh" ascii
        $s2 = "curl " ascii
        $s3 = "wget " ascii
        $s4 = "chmod 777" ascii
        $s5 = "chmod +x" ascii
        $s6 = "sudo " ascii
        $s7 = "osascript" ascii
        $s8 = "launchctl load" ascii
        $s9 = "defaults write" ascii
        $s10 = "killall" ascii
        $s11 = "srm -rf" ascii
        $s12 = "/tmp/" ascii
        $s13 = "base64" ascii
        $s14 = "eval" ascii fullword
        $s15 = "exec" ascii fullword

    condition:
        ($macho64 at 0 or $macho32 at 0) and
        (5 of ($s*))
}

// ---------------------------------------------------------------------------
// 16. Cobalt Strike Beacon Config Strings
// ---------------------------------------------------------------------------
rule CobaltStrike_Beacon_Strings
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects Cobalt Strike Beacon configuration and staging strings"
        severity    = "critical"
        reference   = "https://github.com/Te-k/cobaltstrike"

    strings:
        $s1  = "%s (admin)" ascii
        $s2  = "beacon.dll" ascii nocase
        $s3  = "ReflectiveDllInjection" ascii
        $s4  = "BeaconPrintf" ascii
        $s5  = "BeaconOutput" ascii
        $s6  = "BeaconDataParse" ascii
        $s7  = "BeaconInjectProcess" ascii
        $s8  = "METERPRETER" ascii
        $s9  = "loadlibrary" ascii nocase
        $s10 = "post-ex" ascii
        $s11 = "spawnto" ascii
        $s12 = "sleeptime" ascii
        $s13 = "pipename" ascii
        $s14 = "http-get" ascii
        $s15 = "http-post" ascii
        $config = { 69 00 6E 00 66 00 6F 00 73 00 74 00 65 00 61 00 6C 00 65 00 72 }

    condition:
        3 of ($s*) or $config
}

// ---------------------------------------------------------------------------
// 17. Generic macOS LaunchAgent Persistence
// ---------------------------------------------------------------------------
rule OSX_LaunchAgent_Persistence
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects scripts or binaries that install LaunchAgent persistence"
        severity    = "medium"

    strings:
        $la1 = "~/Library/LaunchAgents/" ascii
        $la2 = "/Library/LaunchAgents/" ascii
        $la3 = "/Library/LaunchDaemons/" ascii
        $la4 = "launchctl load" ascii
        $la5 = "launchctl bootstrap" ascii
        $la6 = "PlistBuddy" ascii
        $la7 = "RunAtLoad" ascii
        $la8 = "KeepAlive" ascii
        $la9 = "StartInterval" ascii
        $la10 = "ProgramArguments" ascii

    condition:
        (($la1 or $la2 or $la3) and ($la4 or $la5)) or
        ($la6 and 2 of ($la7, $la8, $la9, $la10)) or
        (3 of ($la7, $la8, $la9, $la10) and ($la1 or $la2 or $la3))
}

// ---------------------------------------------------------------------------
// 18. Frida / Dynamic Instrumentation Gadget
// ---------------------------------------------------------------------------
rule Generic_Frida_Gadget
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects Frida dynamic instrumentation framework gadget injection"
        severity    = "high"
        reference   = "https://frida.re"

    strings:
        $s1 = "FridaGadget" ascii
        $s2 = "frida-gadget" ascii nocase
        $s3 = "frida_agent_main" ascii
        $s4 = "GumInterceptor" ascii
        $s5 = "gum_init_embedded" ascii
        $s6 = "frida" ascii nocase fullword
        $s7 = "_frida_" ascii
        $s8 = "fridaDylib" ascii

    condition:
        2 of them
}

// ---------------------------------------------------------------------------
// 19. Empire PowerShell macOS Stager
// ---------------------------------------------------------------------------
rule Generic_Empire_macOS_Stager
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects Empire framework macOS agent stager strings"
        severity    = "critical"
        reference   = "https://github.com/EmpireProject/Empire"

    strings:
        $s1 = "import Empire" ascii nocase
        $s2 = "EMPIRE_LISTENER" ascii
        $s3 = "staging_key" ascii nocase
        $s4 = "killswitch" ascii nocase
        $s5 = "sysinfo" ascii
        $s6 = "getuid" ascii
        $s7 = "Empire Agent" ascii nocase
        $s8 = "/admin/get_tasking" ascii
        $s9 = "/admin/stage0" ascii
        $s10 = "powershell -NoP -NonI -W Hidden" ascii nocase
        $s11 = "IEX (New-Object Net.WebClient)" ascii nocase
        $s12 = "System.Net.WebClient" ascii

    condition:
        2 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9) or
        ($s10 and $s11) or
        ($s10 and $s12)
}

// ---------------------------------------------------------------------------
// 20. Privilege Escalation Strings in Mach-O
// ---------------------------------------------------------------------------
rule OSX_PrivilegeEscalation_Strings
{
    meta:
        author      = "Guardian Security Scanner"
        description = "Detects Mach-O binaries containing common macOS privilege escalation strings"
        severity    = "high"

    strings:
        $macho64 = { CF FA ED FE }
        $macho32 = { CE FA ED FE }
        $s1  = "AuthorizationExecuteWithPrivileges" ascii
        $s2  = "AuthorizationCreate" ascii
        $s3  = "SMJobBless" ascii
        $s4  = "seteuid(0)" ascii
        $s5  = "setuid(0)" ascii
        $s6  = "sudo -S" ascii
        $s7  = "DYLD_INSERT_LIBRARIES" ascii
        $s8  = "task_for_pid(0)" ascii
        $s9  = "kauth_cred_setuid" ascii
        $s10 = "com.apple.private.security.no-sandbox" ascii
        $s11 = "CVE-2021-30883" ascii
        $s12 = "CVE-2021-30807" ascii
        $s13 = "CVE-2022-32917" ascii

    condition:
        ($macho64 at 0 or $macho32 at 0) and
        (2 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10) or
         1 of ($s11, $s12, $s13))
}
