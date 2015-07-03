rule write_msr
{
    meta:
    description = "Writing MSR"

    
    strings:
    /* 
        mov ecx, [ebp+??]
        mov eax, [ebp+??]
        mov edx, [ebp+??]
        wrmsr 
    */
    $wr1 = {8B 4D ?? 8B 55 ?? 8B 45 ?? 0F 30}
    $wr2 = {8B 4D ?? 8B 45 ?? 8B 55 ?? 0F 30}
    $wr3 = {8B 55 ?? 8B 4D ?? 8B 45 ?? 0F 30}
    $wr4 = {8B 55 ?? 8B 45 ?? 8B 4D ?? 0F 30}
    $wr5 = {8B 45 ?? 8B 55 ?? 8B 4D ?? 0F 30}
    $wr6 = {8B 45 ?? 8B 4D ?? 8B 55 ?? 0F 30}
    /* 
        mov ecx, imm32
        mov eax, imm32
        mov edx, imm32
        wrmsr
    */
    $wr7 = {B8 ?? ?? ?? BA ?? ?? ?? B9 ?? ?? ?? 0F 30}
    $wr8 = {B8 ?? ?? ?? B9 ?? ?? ?? BA ?? ?? ?? 0F 30}
    $wr9 = {B9 ?? ?? ?? B8 ?? ?? ?? BA ?? ?? ?? 0F 30}
    $wra = {B9 ?? ?? ?? BA ?? ?? ?? B8 ?? ?? ?? 0F 30}
    $wrb = {BA ?? ?? ?? B8 ?? ?? ?? B9 ?? ?? ?? 0F 30}
    $wrc = {BA ?? ?? ?? B9 ?? ?? ?? B8 ?? ?? ?? 0F 30}
    
    condition:
    any of them
}

rule embedded_exe 
{
    meta:
    description = "Detects embedded executables"
    
    strings:
    $a = "This program cannot be run in DOS mode"
    
    condition:
    $a in (1024..filesize)
}

rule encoding 
{ 
    meta: 
    description = "Indicates encryption/compression"
    
    strings:
    $zlib0 = "deflate" fullword
    $zlib1 = "Jean-loup Gailly"
    $zlib2 = "inflate" fullword
    $zlib3 = "Mark Adler"
    
    $ssl0 = "OpenSSL" fullword
    $ssl1 = "SSLeay" fullword
    
    condition:
    (all of ($zlib*)) or (all of ($ssl*))
}

rule irc
{
    meta:
    description = "Indicates use of IRC"
    
    strings:
    $irc0 = "join" nocase fullword
    $irc1 = "msg" nocase fullword
    $irc2 = "nick" nocase fullword
    $irc3 = "notice" nocase fullword
    $irc4 = "part" nocase fullword
    $irc5 = "ping" nocase fullword
    $irc6 = "quit" nocase fullword
    $irc7 = "chat" nocase fullword
    $irc8 = "privmsg" nocase fullword
    
    condition:
    any of them
}   

rule sniffer 
{ 
    meta:
    description = "Indicates network sniffer"
    
    strings:
    $sniff0 = "sniffer" nocase fullword
    $sniff1 = "rpcap:////" nocase
    $sniff2 = "wpcap.dll" nocase fullword
    $sniff3 = "pcap_findalldevs" nocase
    $sniff4 = "pcap_open" nocase
    $sniff5 = "pcap_loop" nocase
    $sniff6 = "pcap_compile" nocase
    $sniff7 = "pcap_close" nocase
 
    condition:
    any of them
}

rule spam 
{
    meta:
    description = "Indicates spam-related activity"
    
    strings:
    $spam0000 = "invitation card" nocase
    $spam0002 = "shipping documents" nocase
    $spam0003 = "e-cards@hallmark.com" nocase
    $spam0004 = "invitations@twitter.com" nocase
    $spam0005 = "invitations@hi5.com" nocase
    $spam0006 = "order-update@amazon.com" nocase
    $spam0007 = "hallmark e-card" nocase
    $spam0008 = "invited you to twitter" nocase
    $spam0009 = "friend on hi5" nocase
    $spam000a = "shipping update for your amazon.com" nocase
    $spam000b = "rcpt to:" nocase
    $spam000c = "mail from:" nocase
    $spam000d = "smtp server" nocase 
    $spam000e = "mx record" nocase
    $spam000f = "cialis" nocase fullword
    $spam0010 = "pharma" nocase fullword
    $spam0011 = "casino" nocase fullword
    $spam0012 = "ehlo " nocase fullword
    $spam0013 = "from: " nocase fullword
    $spam0014 = "subject: " nocase fullword
    $spam0015 = "Content-Disposition: attachment;" nocase
    $spam0016 = "postcard" nocase fullword
    
    condition:
    any of them
}
