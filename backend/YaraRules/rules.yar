/*
===============================================================================
  SecureUploader - YARA Detection Ruleset
-------------------------------------------------------------------------------
  Project : SecureUploader (Senior Thesis)
  Authors : Ahmed Khallouf, Talal Al Helou
  Purpose : Content-based detection of malicious patterns hidden inside
            uploaded files.
  Used by : Layer 5  (SignatureScanning)  - scans raw file bytes
            Layer 5b (PdfFlateDecode)      - scans DECOMPRESSED PDF streams
            Both layers load THIS SAME file, so every rule applies to raw
            content and to decompressed PDF stream content automatically.

  DESIGN PRINCIPLE (low false positives):
    Every rule requires a FILE-TYPE MARKER *together with* a real malicious
    construct - never a single keyword. A legitimate file containing the word
    "eval" will NOT trigger a rule on its own.

  KNOWN LIMITATION (disclose this honestly):
    Modern Office formats (.docx/.xlsx/.pptx) are ZIP archives; VBA macros and
    relationship files live COMPRESSED inside them. Raw scanning therefore sees
    macro content only in legacy OLE formats (.doc/.xls) or AFTER archive
    decompression. This is the same class of limitation the FlateDecode layer
    solves for PDF, and motivates a future archive-decompression layer.
    Static analysis also cannot catch every novel/obfuscated variant by design.
===============================================================================
*/


/* ==========================================================================
   0. PIPELINE TEST FILE
   ========================================================================== */

rule EICAR_Test_File
{
    meta:
        description = "Standard EICAR antivirus test string (harmless). Used to verify the scanning pipeline end-to-end."
        author      = "SecureUploader Team"
        category    = "test"
        severity    = "test"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}


/* ==========================================================================
   1. PHP WEBSHELLS
   ========================================================================== */

rule PHP_Webshell_Input_To_Sink
{
    meta:
        description = "PHP: request input passed directly into a code or command execution sink"
        author      = "SecureUploader Team"
        category    = "webshell"
        severity    = "critical"
        reference   = "OWASP Unrestricted File Upload; CWE-434; MITRE ATT&CK T1505.003"
    strings:
        $php1 = "<?php" nocase
        $php2 = "<?="
        // request input flows into a code-execution sink
        $s1 = /(eval|assert)\s*\(\s*(\$_(POST|GET|REQUEST|COOKIE|SERVER)|base64_decode|gzinflate|gzuncompress|str_rot13)/ nocase
        // request input flows into an OS-command sink
        $s2 = /(system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        // dynamic function call built from the request:  $_GET['f']( ... )
        $s3 = /\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]{0,64}\]\s*\(/
        // preg_replace with the (deprecated) /e code-execution modifier
        $s4 = /preg_replace\s*\(\s*['"][^'"]*\/e['"]/ nocase
    condition:
        ($php1 or $php2) and any of ($s1, $s2, $s3, $s4)
}

rule PHP_Webshell_Obfuscated_Execution
{
    meta:
        description = "PHP: obfuscation/decoder chain feeding a code-execution sink"
        author      = "SecureUploader Team"
        category    = "webshell"
        severity    = "critical"
        reference   = "OWASP Unrestricted File Upload; CWE-434"
    strings:
        $php = "<?php" nocase
        $o1 = /eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode|hex2bin)\s*\(/ nocase
        $o2 = /assert\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(/ nocase
        $o3 = /(create_function|call_user_func|call_user_func_array)\s*\(\s*(base64_decode|\$)/ nocase
        $o4 = "${\"GLOBALS\"}"
        // long hex-escaped string blob = obfuscation
        $o5 = /(\\x[0-9a-f]{2}){8,}/ nocase
    condition:
        $php and any of ($o1, $o2, $o3, $o4, $o5)
}

rule PHP_Webshell_Known_Signatures
{
    meta:
        description = "PHP: markers of well-known webshell families / backdoors"
        author      = "SecureUploader Team"
        category    = "webshell"
        severity    = "critical"
        reference   = "OWASP Unrestricted File Upload; CWE-434"
    strings:
        $php = "<?php" nocase
        // strong, distinctive family markers - fire on their own
        $strong1 = "c99shell" nocase
        $strong2 = "r57shell" nocase
        $strong3 = "b374k" nocase
        $strong4 = "FilesMan" nocase
        $strong5 = "phpspy" nocase
        $strong6 = /@eval\s*\(\s*\$_(POST|GET|REQUEST)/ nocase   // China Chopper style
        $strong7 = "WSO 2." nocase
        // weak markers - only count when several appear together with PHP
        $weak1 = "shell_exec"
        $weak2 = "safe_mode" nocase
        $weak3 = "web shell" nocase
        $weak4 = "backdoor" nocase
        $weak5 = "uname -a"
    condition:
        any of ($strong*) or ($php and 3 of ($weak*))
}

rule PHP_Code_In_Image_File
{
    meta:
        description = "PHP code embedded in a file that begins with an image magic header (disguised/polyglot webshell)"
        author      = "SecureUploader Team"
        category    = "webshell"
        severity    = "critical"
        reference   = "OWASP Unrestricted File Upload; CWE-434"
    strings:
        $php1 = "<?php" nocase
        $php2 = "<?="
        $sink = /\b(eval|system|shell_exec|passthru|assert|base64_decode)\s*\(/ nocase
    condition:
        // starts with a common image magic ...
        ( uint16(0) == 0xD8FF          // JPEG  (FF D8)
          or uint32(0) == 0x38464947   // GIF8  ("GIF8")
          or uint32(0) == 0x474E5089   // PNG   (89 50 4E 47)
          or uint16(0) == 0x4D42 )     // BMP   ("BM")
        // ... yet contains PHP code
        and ($php1 or $php2) and $sink
}


/* ==========================================================================
   2. ASP / ASPX / JSP WEBSHELLS
   ========================================================================== */

rule ASP_Webshell_Execution
{
    meta:
        description = "Classic ASP webshell: request input passed to eval/execute or a shell object"
        author      = "SecureUploader Team"
        category    = "webshell"
        severity    = "critical"
        reference   = "OWASP Unrestricted File Upload; CWE-434"
    strings:
        $tag = "<%"
        $a1 = /eval\s*\(?\s*request/ nocase
        $a2 = /execute(global)?\s*\(?\s*request/ nocase
        $a3 = /Server\.CreateObject\s*\(\s*"WScript\.Shell"/ nocase
        $a4 = /Server\.CreateObject\s*\(\s*"Shell\.Application"/ nocase
        $a5 = /CreateObject\s*\(\s*"WScript\.Shell"/ nocase
    condition:
        $tag and any of ($a1, $a2, $a3, $a4, $a5)
}

rule ASPX_Webshell_Execution
{
    meta:
        description = "ASP.NET webshell: server page combined with process/assembly execution driven by request input"
        author      = "SecureUploader Team"
        category    = "webshell"
        severity    = "critical"
        reference   = "OWASP Unrestricted File Upload; CWE-434"
    strings:
        $p1 = "<%@ Page" nocase
        $p2 = "runat=\"server\"" nocase
        $x1 = /Process\.Start\s*\(/ nocase
        $x2 = "System.Diagnostics.Process" nocase
        $x3 = /Request\[[^\]]+\]/
        $x4 = "cmd.exe" nocase
        $x5 = "System.Reflection.Assembly.Load" nocase
        $x6 = /eval\s*\(\s*Request/ nocase
    condition:
        (any of ($p1, $p2)) and ( 2 of ($x1, $x2, $x3, $x4, $x5) or $x6 )
}

rule JSP_Webshell_Execution
{
    meta:
        description = "JSP webshell: runtime/process execution combined with request input"
        author      = "SecureUploader Team"
        category    = "webshell"
        severity    = "critical"
        reference   = "OWASP Unrestricted File Upload; CWE-434"
    strings:
        $tag = "<%"
        $j1 = "Runtime.getRuntime().exec(" nocase
        $j2 = "ProcessBuilder" nocase
        $j3 = /request\.getParameter\s*\(/ nocase
        $j4 = "/bin/sh"
        $j5 = "cmd.exe" nocase
    condition:
        $tag and ( ($j1 or $j2) and ($j3 or $j4 or $j5) )
}


/* ==========================================================================
   3. MALICIOUS PDF
   ========================================================================== */

rule PDF_Auto_Executing_JavaScript
{
    meta:
        description = "PDF containing JavaScript wired to an automatic trigger (OpenAction / additional-actions)"
        author      = "SecureUploader Team"
        category    = "malicious-document"
        severity    = "high"
        reference   = "CWE-434; MITRE ATT&CK T1204"
    strings:
        $pdf  = "%PDF"
        $js1  = "/JavaScript" nocase
        $js2  = "/JS" nocase
        $act1 = "/OpenAction" nocase
        $act2 = "/AA" nocase
    condition:
        ($pdf in (0..1024) or not $pdf) and ($js1 or $js2) and ($act1 or $act2)
}

rule PDF_Launch_Action
{
    meta:
        description = "PDF Launch action - can start external programs; strong malicious signal for an upload"
        author      = "SecureUploader Team"
        category    = "malicious-document"
        severity    = "high"
        reference   = "CWE-434"
    strings:
        $pdf    = "%PDF"
        $launch = "/Launch" nocase
    condition:
        ($pdf in (0..1024) or not $pdf) and $launch
}

rule PDF_Embedded_File
{
    meta:
        description = "PDF carrying an embedded file - may smuggle a payload. Medium confidence: legitimate attachments exist; flag for review."
        author      = "SecureUploader Team"
        category    = "malicious-document"
        severity    = "medium"
        reference   = "CWE-434"
    strings:
        $pdf = "%PDF"
        $emb = "/EmbeddedFile" nocase
        $ef  = "/EF"
    condition:
        ($pdf in (0..1024) or not $pdf) and ($emb or $ef)
}

rule PDF_Obfuscated_Name_Evasion
{
    meta:
        description = "PDF hiding an executable-trigger keyword behind #XX hex escapes in a name object - a filter-evasion technique"
        author      = "SecureUploader Team"
        category    = "evasion"
        severity    = "high"
        reference   = "CWE-434; CIC-Evasive-PDFMal2022 structural feature: obfuscated names"

    strings:
        $pdf = "%PDF"

        // Each pattern targets ONE keyword that matters, with the escape at any
        // position inside it. A generic "name containing #XX" matched clean
        // documents: '#' occurs legitimately in text and in compressed data, so
        // the shape of an escape is not evidence on its own. What IS evidence is
        // an escape used to spell a keyword that triggers execution.
        $js1  = /\/(J#61|Ja#76|Jav#61|Java#53|JavaS#63|JavaSc#72|JavaScr#69|JavaScri#70|JavaScrip#74)/ nocase
        $js2  = /\/J#61vaScript/ nocase
        $js3  = /\/(J#53|JS#00)/ nocase
        $oa   = /\/(O#70en|Op#65n|Ope#6E|Open#41|OpenA#63|OpenAc#74|OpenAct#69)/ nocase
        $la   = /\/(L#61unch|La#75nch|Lau#6Ech|Laun#63h|Launc#68)/ nocase
        $aa   = /\/#41A/ nocase
        $ef   = /\/(E#6DbeddedFile|Em#62eddedFile|Emb#65ddedFile)/ nocase

    condition:
        ($pdf in (0..1024) or not $pdf) and any of ($js1, $js2, $js3, $oa, $la, $aa, $ef)
}


/* ==========================================================================
   4. MALICIOUS OFFICE DOCUMENTS
   NOTE: fully effective on legacy OLE (.doc/.xls). For OOXML (.docx/.xlsx)
   the macro body is compressed inside the ZIP - needs an archive layer first.
   ========================================================================== */

rule Office_Macro_AutoExec
{
    meta:
        description = "VBA auto-execution trigger in a macro-bearing document"
        author      = "SecureUploader Team"
        category    = "malicious-document"
        severity    = "high"
        reference   = "CWE-434; MITRE ATT&CK T1059.005"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }   // OLE compound-file magic (legacy Office)
        $vba = "vbaProject.bin"              // present (uncompressed) in OOXML ZIP directory
        $m1  = "AutoOpen"
        $m2  = "Auto_Open"
        $m3  = "Document_Open"
        $m4  = "Workbook_Open"
        $m5  = "AutoExec"
        $m6  = "AutoClose"
    condition:
        ($ole at 0 or $vba) and any of ($m1, $m2, $m3, $m4, $m5, $m6)
}

rule Office_Macro_Suspicious_Calls
{
    meta:
        description = "VBA source combined with multiple suspicious runtime calls (shell/download/persistence)"
        author      = "SecureUploader Team"
        category    = "malicious-document"
        severity    = "high"
        reference   = "CWE-434; MITRE ATT&CK T1059.005"
    strings:
        $vba = "Attribute VB_Name"
        $c1  = "Shell(" nocase
        $c2  = "CreateObject(" nocase
        $c3  = "WScript.Shell" nocase
        $c4  = "powershell" nocase
        $c5  = "MSXML2.XMLHTTP" nocase
        $c6  = "URLDownloadToFile" nocase
        $c7  = "ADODB.Stream" nocase
        $c8  = "Environ(" nocase
        $c9  = "GetObject(" nocase
    condition:
        $vba and 2 of ($c1, $c2, $c3, $c4, $c5, $c6, $c7, $c8, $c9)
}

rule Office_DDE_AutoExec
{
    meta:
        description = "DDE / DDEAUTO field - executes external commands when the document opens"
        author      = "SecureUploader Team"
        category    = "malicious-document"
        severity    = "high"
        reference   = "CWE-434; MITRE ATT&CK T1559.002"
    strings:
        $d1 = "DDEAUTO" nocase
        $d2 = /!\s*DDE/ nocase
    condition:
        any of them
}


/* ==========================================================================
   5. SCRIPT INJECTION / SVG / XXE
   ========================================================================== */

rule Script_Or_Handler_Embedded
{
    meta:
        description = "Embedded script tag / JS event handler / javascript: URI. Defense-in-depth for script in unexpected file types."
        author      = "SecureUploader Team"
        category    = "script-injection"
        severity    = "medium"
        reference   = "CWE-79; CWE-434"
    strings:
        $s1 = "<script" nocase
        $s2 = /on(load|error|click|mouseover)\s*=/ nocase
        $s3 = "javascript:" nocase
        $s4 = "<iframe" nocase
        $s5 = /document\.write\s*\(/ nocase
        $s6 = /eval\s*\(/ nocase
    condition:
        ($s1 and any of ($s2, $s3, $s5, $s6)) or 3 of them
}

rule SVG_With_Active_Content
{
    meta:
        description = "SVG carrying active content (script / event handler / foreignObject / external entity)"
        author      = "SecureUploader Team"
        category    = "script-injection"
        severity    = "high"
        reference   = "CWE-79; CWE-434"
    strings:
        $svg = "<svg" nocase
        $s1  = "<script" nocase
        $s2  = /on(load|click|mouseover|error)\s*=/ nocase
        $s3  = "foreignObject" nocase
        $s4  = "javascript:" nocase
        $s5  = "<!ENTITY" nocase
    condition:
        $svg and any of ($s1, $s2, $s3, $s4, $s5)
}

rule XML_External_Entity_XXE
{
    meta:
        description = "XML external-entity (XXE) declaration - can read local files or reach internal services"
        author      = "SecureUploader Team"
        category    = "xxe"
        severity    = "high"
        reference   = "CWE-611; OWASP XXE"
    strings:
        $doc  = "<!DOCTYPE" nocase
        $ent  = "<!ENTITY" nocase
        $sys  = "SYSTEM"
        $pub  = "PUBLIC"
        $file = "file://" nocase
        $php  = "php://" nocase
    condition:
        $doc and $ent and ($sys or $pub or $file or $php)
}


/* ==========================================================================
   6. HIDDEN EXECUTABLES (defense-in-depth)
   ========================================================================== */

rule Embedded_Windows_Executable
{
    meta:
        description = "Windows PE executable content inside a file that does NOT start with MZ (disguised/appended executable)"
        author      = "SecureUploader Team"
        category    = "embedded-executable"
        severity    = "critical"
        reference   = "CWE-434"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $pe and #mz > 0 and not (uint16(0) == 0x5A4D)
}

rule Embedded_ELF_Executable
{
    meta:
        description = "Linux ELF executable magic located away from offset 0 (embedded in another file)"
        author      = "SecureUploader Team"
        category    = "embedded-executable"
        severity    = "critical"
        reference   = "CWE-434"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf and not ($elf at 0)
}

rule PDF_Encrypted_Unscannable
{
    meta:
        description = "Encrypted PDF: streams are unreadable, so the signature, decompression and link layers are all blind"
        author      = "SecureUploader Team"
        category    = "evasion"
        severity    = "medium"
        reference   = "CIC-Evasive-PDFMal2022 general feature: encryption"

    strings:
        // Header, allowing the leading bytes real-world readers tolerate.
        $pdf = "%PDF"

        // The trailer entry that declares an encryption dictionary.
        $enc = "/Encrypt"

    condition:
        ($pdf in (0..1024) or not $pdf) and $enc
}

rule Archive_Embedded_In_Image
{
    meta:
        description = "Archive signature inside an image container: the covert half of a documented image polyglot"
        author      = "SecureUploader Team"
        category    = "polyglot"
        severity    = "critical"
        reference   = "Koch et al., On the Abuse and Detection of Polyglot Files, ACM WWW 2025"

    strings:
        // Overt container, pinned at the start of the file.
        $jpeg = { FF D8 FF }
        $png  = { 89 50 4E 47 0D 0A 1A 0A }
        $riff = { 52 49 46 46 }            // WebP and other RIFF containers

        // Covert archive containers. Four bytes minimum â€” see the note above.
        $zip    = { 50 4B 03 04 }          // local file header
        $zip_ed = { 50 4B 05 06 }          // end of central directory
        $rar4   = { 52 61 72 21 1A 07 00 }
        $rar5   = { 52 61 72 21 1A 07 01 00 }
        $sevenz = { 37 7A BC AF 27 1C }
        $cab    = { 4D 53 43 46 00 00 00 00 }

    condition:
        ($jpeg at 0 or $png at 0 or $riff at 0)
        and any of ($zip, $zip_ed, $rar4, $rar5, $sevenz, $cab)
}

rule PDF_Name_Tree_JavaScript
{
    meta:
        description = "PDF registering JavaScript through the document name tree - executes on open without /OpenAction or /AA"
        author      = "SecureUploader Team"
        category    = "malicious-document"
        severity    = "high"
        reference   = "PDF 32000-1:2008 s7.7.4 (name dictionary); CWE-434"

    strings:
        $pdf = "%PDF"

        // The catalogue points at a name dictionary, which in turn holds a
        // /JavaScript entry. A reader runs every script registered there when the
        // document opens, so this is a third auto-execution path alongside
        // /OpenAction and /AA - and the one our existing rule required to be
        // absent, which is why files using it passed.
        $names = "/Names" nocase
        $js    = "/JavaScript" nocase

    condition:
        ($pdf in (0..1024) or not $pdf) and $names and $js
}

rule PDF_Page_Covering_Link
{
    meta:
        description = "PDF link annotation whose clickable area spans most of the page - any click opens it"
        author      = "SecureUploader Team"
        category    = "phishing"
        severity    = "high"
        reference   = "PDF 32000-1:2008 s12.5.2 (annotation Rect); CWE-1021 (improper restriction of rendered UI layers)"

    strings:
        $pdf  = "%PDF"
        $link = "/Subtype/Link" nocase
        $uri  = "/URI" nocase

        // A four-digit width in a Rect. A page is 595pt wide (A4) or 612pt
        // (Letter), so any dimension of 1000pt or more spans more than a full
        // page. Measured: benign reference links in an academic paper ran
        // 248-339pt wide by 11-17pt tall (3,000-5,700 pt2), while a phishing
        // overlay was 1224 x 792 (969,650 pt2) - a 170-fold gap with nothing
        // in between.
        $wide = /\/Rect\s*\[\s*-?[\d.]{1,8}\s+-?[\d.]{1,8}\s+[1-9]\d{3,}(\.\d+)?\s/

    condition:
        ($pdf in (0..1024) or not $pdf) and $link and $uri and $wide
}