# knowledge
Links to various sources for infosec knowledge

## Privilege Escalation
* [Windows Privilege Escalation via DLL Hijacking](https://hacknpentest.com/windows-privilege-escalation-dll-hijacking/)
* [DLL hollowing](https://github.com/hasherezade/module_overloading) @Hasherezade
* [CVE-2019-1322](https://twitter.com/decoder_it/status/1193496591140818944?s=08)
* [Basic Priv info](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
* [Azure AD privilege escalation - Taking over default application permissions as Application Admin](https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/)
* [NTLM relay from one Exchange server to another](https://twitter.com/tifkin_/status/1167570558030155776?s=08)
* [Privilege Escalation Cheatsheet](https://github.com/Ignitetechnologies/Privilege-Escalation)
* [Hot Potato - Windows Priv tool](https://foxglovesecurity.com/2016/01/16/hot-potato/)
* [Privilege Escalation Windows](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
* [Top Five Ways I Got Domain Admin on Your Internal Network before Lunch](https://medium.com/@adam.toscher/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)
* [Internal Monologue Attack - Retrieving NTLM Hashes without Touching LSASS](https://shenaniganslabs.io/2019/01/14/Internal-Monologue.html)
* [Brute Forcing Accounts that have logged onto an AD joined computer](https://medium.com/@markmotig/brute-forcing-local-accounts-on-an-ad-joined-computer-30c4a45af027)

## LOLBAS/LOLBINS
* [Locading DLL using odbcconf.exe](https://twitter.com/Hexacorn/status/1187143326673330176?s=08)
* [3rd party signed LOLBIN](https://twitter.com/gN3mes1s/status/1196366977369022464?s=08)


## Lateral Movement
* [Lateral Movement – WinRM](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/)
* [Offensive Lateral Movement](https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f)

## Hack Tool
* [WinRM shell-trojan](https://github.com/Hackplayers/evil-winrm)
* [Detects potential privileged account threats in the scanned network](https://github.com/cyberark/zBang)
* [PowerShell ADIDNS/LLMNR/NBNS/mDNS/DNS spoofer and man-in-the-middle tool](https://github.com/Kevin-Robertson/Inveigh)
* [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)

## Researches
* [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
* [Evasion - Microsoft Phishing Attack Uses Google Redirects to Evade Detection](https://www.bleepingcomputer.com/news/security/microsoft-phishing-attack-uses-google-redirects-to-evade-detection/)
* [Mapping the connections inside Russia’s APT Ecosystem](https://research.checkpoint.com/russianaptecosystem/#results)
* [Why You Should Never Save Passwords on Chrome or Firefox](https://hackernoon.com/why-you-should-never-save-passwords-on-chrome-or-firefox-96b770cfd0d0)
* [DealPly Revisited: Leveraging Reputation Services To Remain Under The Radar](https://blog.ensilo.com/leveraging-reputation-services?hs_amp=true&__twitter_impression=true)

## Recommendations, Best practices
* [Hardening Your Azure Domain Front](https://medium.com/@rvrsh3ll/hardening-your-azure-domain-front-7423b5ab4f64)
* [Security baseline for Office 365 ProPlus (v1907, July 2019) - DRAFT](https://techcommunity.microsoft.com/t5/Microsoft-Security-Baselines/Security-baseline-for-Office-365-ProPlus-v1907-July-2019-DRAFT/ba-p/771308)
* [Preventing Mimikatz Attacks](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5)

## Evasion
* [Embedding EXE files into PowerShell script](https://truesecdev.wordpress.com/2016/03/15/embedding-exe-files-into-powershell-scripts/)
* [creating hta file with Evading AV](https://github.com/felamos/weirdhta)
* [Data exfiltration techniques](https://www.pentestpartners.com/security-blog/data-exfiltration-techniques/)
* [Data exfiltration techniques @Azeria](https://azeria-labs.com/data-exfiltration/)
* [executables from the memory of Word or Excel](https://github.com/itm4n/VBA-RunPE)
* [Creates a local or "reverse" Socks proxy using powershell](https://github.com/p3nt4/Invoke-SocksProxy/blob/master/README.md)
* [Bypassing AV (Windows Defender) … the tedious way](https://www.cyberguider.com/bypassing-windows-defender-the-tedious-way/)
* [Bypassing PowerShell Protections](https://blog.stealthbits.com/how-attackers-are-bypassing-powershell-protections/)
* [Exploring PowerShell AMSI and Logging Evasion](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/)
* [DotNet Core: A Vector For AWL Bypass & Defense Evasion](https://bohops.com/2019/08/19/dotnet-core-a-vector-for-awl-bypass-defense-evasion/)
* [How to Bypass AMSI with an Unconventional Powershell Cradle](https://medium.com/@gamer.skullie/bypassing-amsi-with-an-unconventional-powershell-cradle-6bd15a17d8b9)
* [Suck it, Windows Defender.](https://hausec.com/2019/02/09/suck-it-windows-defender/)
* [Download Cradles](https://gist.github.com/HarmJ0y/bb48307ffa663256e239)
* [Download Cradles 2](https://gist.github.com/HarmJ0y/fd98c4f16575ba28c091)
* [NTLM relaying examples using letit software and commands](https://twitter.com/mubix/status/1123784467187945484)
* [Understanding UNC paths, SMB, and WebDAV](https://www.n00py.io/2019/06/understanding-unc-paths-smb-and-webdav/)
* [Executing Metasploit & Empire Payloads from MS Office Document Properties (part 1 of 2)](https://stealingthe.network/executing-metasploit-empire-payloads-from-ms-office-document-properties-part-1-of-2/)
* [Sandbox Evasion Techniques – Part 1](https://www.vmray.com/cyber-security-blog/sandbox-evasion-techniques-part-1/)
* [PowerShell obfuscation](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1492186586.pdf)
* [APIunhooker](https://github.com/RedLectroid/APIunhooker)
* [Amsi-Bypass-Powershell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)

## OSINT
* [Digital Shadows: Seeking Sector035](https://nixintel.info/osint/digital-shadows-seeking-sector035-quiztime-26th-september-2019/)
* [GreyNoise Intelligence Anounce](https://www.linkedin.com/posts/andrew---morris_im-extremely-excited-to-announce-greynoise-activity-6580154869917765632-H-bm/)
* [Censys - Search certificates and hosts](https://Censys.io)
* [Shodan - Internet search]()
* [Certificate transparency project search - CRT.SH](https://crt.sh)
* [Certificate transparency project search - Google](https://transparencyreport.google.com/https/certificates?hl=en)
* [Certificates search](https://certdb.com/)
* [Whois - Domaintools](https://whois.domaintools.com/)
* [Whois.net](https://whois.net/)
* [Search ASN info](https://www.ultratools.com/tools/asnInfo)
* [Reverse whois](https://viewdns.info/reversewhois/)
* [IP whois](https://www.ultratools.com/tools/ipWhoisLookup)
* [Shared hosting on same IP search](https://hackertarget.com/reverse-ip-lookup/)
* [Shared domains on same NS server search)[https://hackertarget.com/find-shared-dns-servers/]
* [Metadata tool](https://github.com/opsdisk/metagoofil/blob/master/README.md)
* [General OSINT - RiskIQ](https://community.riskiq.com)
* [Reverse IP](http://reverse.domainlex.com/reverse-ip/)

## Feeds
* [Google Safe Browsing](https://developers.google.com/safe-browsing)

## Attacks
* [Bypassing Network Restrictions Through RDP/SSH Tunneling](https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html)  @Fireeye
* [Advanced persistence threats: to be a cybercriminal, think like a sysadmin](https://redcanary.com/blog/detecting-persistence-techniques/) @RedCanary
* [a .lnk file that contains an entire obfuscated .vbs script and a cmd oneliner to call it](https://twitter.com/JayTHL/status/1176897375882924032?s=08)
* [This malware is harvesting saved credentials in Chrome, Firefox browsers](https://www.zdnet.com/article/this-malware-is-harvesting-saved-credentials-in-chrome-firefox-browsers/)
* [Campaign Collections](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections))
* [#TrickBot Banking #Malware](https://twitter.com/VK_Intel/status/1152436348802019328?s=08)
* [Dismantling a fileless campaign: Microsoft Defender ATP’s Antivirus exposes Astaroth attack](https://www.microsoft.com/security/blog/2019/07/08/dismantling-a-fileless-campaign-microsoft-defender-atp-next-gen-protection-exposes-astaroth-attack/)
* [Pass-The-Hash](https://blog.stealthbits.com/passing-the-hash-with-mimikatz)
* [Kerberoasting](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)

## Monitoring/IR/Forensics
* [Sysmon configuration file template with default high-quality event tracing](https://github.com/SwiftOnSecurity/sysmon-config)
* [Sigma pastes](https://github.com/Neo23x0/sigma/blob/master/rules/proxy/proxy_raw_paste_service_access.yml)
* [Hunting and detecting APTs using Sysmon and PowerShell logging](https://www.botconf.eu/wp-content/uploads/2018/12/2018-Tom-Ueltschi-Sysmon.pdf)
* [Hunting for malicious powershell with splunk](https://conf.splunk.com/files/2016/slides/powershell-power-hell-hunting-for-malicious-use-of-powershell-with-splunk.pdf)
* [Splunk cheetshit](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5a3187b4419202f0fb8b2dd1/1513195444728/Windows+Splunk+Logging+Cheat+Sheet+v2.2.pdf)
* [Windows advanced audit](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1511904841.pdf)
* [AD auditing](https://activedirectorypro.com/audit-policy-best-practices/#active-directory-audit-policy)
* [Hunting credential dumping](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf)
* [Enabling Advanced Security Audit Policy via DS Access](https://blogs.technet.microsoft.com/canitpro/2017/03/29/step-by-step-enabling-advanced-security-audit-policy-via-ds-access/)
* [Investigating PowerShell Attacks](https://www.blackhat.com/docs/us-14/materials/us-14-Kazanciyan-Investigating-Powershell-Attacks-WP.pdf)
* [Sigma rules](https://medium.com/oscd/oscd-threat-detection-sprint-1-c42317e06771)

## Study/Guide
* [BUILDING AND ATTACKING AN ACTIVE DIRECTORY LAB WITH POWERSHELL - Thread](https://twitter.com/FlatL1ne/status/1178668327947948033?s=08)
* [Python for Beginners @Microsoft](https://www.youtube.com/playlist?list=PLlrxD0HtieHhS8VzuMCfQD4uJ9yne1mE6)
* [How to host a site on the dark web](https://medium.com/@jasonrigden/how-to-host-a-site-on-the-dark-web-38edf00996bf)
* [Reversing course](https://0verfl0w.podia.com/)
* [Guide to Mimikatz](https://adsecurity.org/?page_id=1821)
* [Powershell for exploitation and post exploitation - Part 2](https://www.peerlyst.com/posts/powershell-for-exploitation-and-post-exploitation-part-2-david-dunmore?utm_source=twitter&utm_medium=social&utm_content=peerlyst_post&utm_campaign=peerlyst_shared_post)
* [Cryptographic Attacks: A Guide for the Perplexed](https://research.checkpoint.com/cryptographic-attacks-a-guide-for-the-perplexed/) @Checkpoint
* [Attacking Private Networks from the Internet with DNS Rebinding](https://medium.com/@brannondorsey/attacking-private-networks-from-the-internet-with-dns-rebinding-ea7098a2d325)
* [Fileless threats](https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/fileless-threats)
* [Finding metadata](https://resources.infosecinstitute.com/metadata-the-hidden-treasure/)
* [Red Team Techniques for Evading, Bypassing, and Disabling MS](https://www.blackhat.com/docs/eu-17/materials/eu-17-Thompson-Red-Team-Techniques-For-Evading-Bypassing-And-Disabling-MS-Advanced-Threat-Protection-And-Advanced-Threat-Analytics.pdf).
* [Blueteam tips](https://www.sneakymonkey.net/2018/06/25/blue-team-tips/)
* [DCSync](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [Powershell attack and defence](https://adsecurity.org/?p=2921)
* [Atomic coverage](https://atomicthreatcoverage.atlassian.net/wiki/spaces/ATC/overview)

## Information
* [Your fucking IP](https://wtfismyip.com/)
* [Dimitry finds out - Original](https://www.youtube.com/watch?v=2-XxbdR3Nik)
* [GPO information](https://getadmx.com/)
* [Detect mimikatz idea](https://twitter.com/mysmartlogon/status/1158816784524500998?s=20)
* [defensive techniques that are relatively simple to configure/deploy that has a high success rate ](https://twitter.com/PyroTek3/status/1167466030127620096?s=08)
* [Basic windows RED commands](https://ired.team/offensive-security-experiments/offensive-security-cheetsheets)
* [EVTX attack samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/tree/master/Privilege%20Escalation)
* [Malicious Powershell Scripts](https://onedrive.live.com/?cid=7874cfd565b38d4b&id=7874CFD565B38D4B%211091892&authkey=!AC9cbXs-twuSZ-E)
* [Panache_sysmon config](https://twitter.com/SBousseaden/status/1155476334379962370?s=08)
* [Pros and Cons of DNS Over HTTPS](https://dzone.com/articles/pros-and-cons-of-dns-over-https)
* [Recommended scan exclusion list for Trend Micro Endpoint products](https://success.trendmicro.com/solution/1059770-recommended-scan-exclusion-list-for-trend-micro-endpoint-products)
* [Living Off The Land Binaries and Scripts (and also Libraries)](https://lolbas-project.github.io/)
* [reminder that Powershell resides in many places](https://twitter.com/Hexacorn/status/1149088638959071237)
* [Tracking Threat Actor Emails in Phishing Kits](https://github.com/neonprimetime/PhishingKitTracker?files=1)
* [A checkpoint forum thread about how to deal with DNS encryption problem](https://community.checkpoint.com/t5/Access-Control-Products/How-to-deal-with-DNS-over-HTTPS-DNS-over-TLS-QUIC-and-PSOM/td-p/11528)
* [Shodan filters](https://github.com/JavierOlmedo/shodan-filters)
* [PowerShell cheatsheet](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf)

## Other tools
* [An open-source whistleblower submission system](https://twitter.com/SecureDrop)
* [Shellphish: A Phishing Tool](https://www.hackingarticles.in/shellphish-a-phishing-tool/)
* [Create a minidump of the LSASS process from memory](https://github.com/b4rtik/SharpMiniDump)
* [C3 - C&C tool](https://rastamouse.me/2019/09/mwr-labs-c3-first-look/)
* [Semi-Automated Cyber Threat Intelligence - ACT Platform](https://github.com/mnemonic-no/act-platform)
* [NebulousAD: A Free Credential Auditor for Active Directory](https://blog.nuid.io/nebulousad/)
* [HTTP requests interceptor](https://beeceptor.com/)
* [HTTP rqquests interceptor 2](http://webhook.site/)
* [Browser leaks](https://browserleaks.com)
* [GZIP file that infinitely contains itself](https://twitter.com/WhoStoleHonno/status/1153315367235784704?s=08)
* [How to win a free trip to the gulag.](https://twitter.com/CrazyinRussia/status/1153293395932135424?s=08)
* [PowerShell repository that help raise "safe" security alerts](https://twitter.com/MiladMSFT/status/1152222809747329024?s=08)
* [A small hobby ads block dns project with doh, dot, dnscrypt support.](https://blahdns.com/)
* [Creating mindmaps](https://www.mindmup.com/)
* [Azure CyberRange script](https://github.com/xFreed0m/Disruption)

