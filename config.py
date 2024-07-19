vt_api_key = "replace"
xforce_api_key = "replace"
xforce_api_password= "replace"
abuse_key="replace"

urls = [
    #TOR
    ('http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv',
     'is not a TOR Exit Node',
     'is a TOR Exit Node',
     False),

    #EmergingThreats
    ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
     'is not listed on EmergingThreats',
     'is listed on EmergingThreats',
     True),

    #AlienVault
    ('http://reputation.alienvault.com/reputation.data',
     'is not listed on AlienVault',
     'is listed on AlienVault',
     True),

    #BlocklistDE
    ('http://www.blocklist.de/lists/bruteforcelogin.txt',
     'is not listed on BlocklistDE',
     'is listed on BlocklistDE',
     True),

    #Dragon Research Group - SSH
    ('http://dragonresearchgroup.org/insight/sshpwauth.txt',
     'is not listed on Dragon Research Group - SSH',
     'is listed on Dragon Research Group - SSH',
     True),

    #Dragon Research Group - VNC
    ('http://dragonresearchgroup.org/insight/vncprobe.txt',
     'is not listed on Dragon Research Group - VNC',
     'is listed on Dragon Research Group - VNC',
     True),

    #NoThinkMalware
    ('http://www.nothink.org/blacklist/blacklist_malware_http.txt',
     'is not listed on NoThink Malware',
     'is listed on NoThink Malware',
     True),

    #NoThinkSSH
    ('http://www.nothink.org/blacklist/blacklist_ssh_all.txt',
     'is not listed on NoThink SSH',
     'is listed on NoThink SSH',
     True),

    #Feodo
    ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
     'is not listed on Feodo',
     'is listed on Feodo',
     True),

    #antispam.imp.ch
    ('http://antispam.imp.ch/spamlist',
     'is not listed on antispam.imp.ch',
     'is listed on antispam.imp.ch',
     True),

    #dshield
    ('http://www.dshield.org/ipsascii.html?limit=10000',
     'is not listed on dshield',
     'is listed on dshield',
     True),

    #malc0de
    ('http://malc0de.com/bl/IP_Blacklist.txt',
     'is not listed on malc0de',
     'is listed on malc0de',
     True),

    #MalWareBytes
    ('http://hosts-file.net/rss.asp',
     'is not listed on MalWareBytes',
     'is listed on MalWareBytes',
     True)
]
bls = ["b.barracudacentral.org", "bl.spamcop.net",
       "blacklist.woody.ch", "cbl.abuseat.org", 
       "combined.abuse.ch", "combined.rbl.msrbl.net", 
       "db.wpbl.info", "dnsbl.cyberlogic.net",
       "dnsbl.sorbs.net", "drone.abuse.ch", "drone.abuse.ch",
       "duinv.aupads.org", "dul.dnsbl.sorbs.net", "dul.ru",
       "dynip.rothen.com",
       "http.dnsbl.sorbs.net", "images.rbl.msrbl.net",
       "ips.backscatterer.org", "ix.dnsbl.manitu.net",
       "korea.services.net", "misc.dnsbl.sorbs.net",
       "noptr.spamrats.com"]
#, "ohps.dnsbl.net.au", "omrs.dnsbl.net.au",
       #"osps.dnsbl.net.au", "osrs.dnsbl.net.au",
       #"owfs.dnsbl.net.au", "pbl.spamhaus.org", "phishing.rbl.msrbl.net",
       #"probes.dnsbl.net.au", "proxy.bl.gweep.ca", "rbl.interserver.net",
       #"rdts.dnsbl.net.au", "relays.bl.gweep.ca", "relays.nether.net",
       #"residential.block.transip.nl", "ricn.dnsbl.net.au",
       #"rmst.dnsbl.net.au", "smtp.dnsbl.sorbs.net",
       #"socks.dnsbl.sorbs.net", "spam.abuse.ch", "spam.dnsbl.sorbs.net",
       #"spam.rbl.msrbl.net", "spam.spamrats.com", "spamrbl.imp.ch",
       #"t3direct.dnsbl.net.au", "tor.dnsbl.sectoor.de",
       #"torserver.tor.dnsbl.sectoor.de", "ubl.lashback.com",
       #"ubl.unsubscore.com", "virus.rbl.jp", "virus.rbl.msrbl.net",
       #"web.dnsbl.sorbs.net", "wormrbl.imp.ch", "xbl.spamhaus.org",
       #"zen.spamhaus.org", "zombie.dnsbl.sorbs.net"
