// Main JavaScript File for Gravix-Hack AI

class GravixHackAI {
    constructor() {
        this.init();
        this.setupEventListeners();
        this.startMatrixEffect();
        this.startTypingEffect();
    }

    init() {
        console.log(`
 ██████╗ ██████╗  █████╗ ██╗   ██╗██╗██╗  ██╗      ██╗  ██╗ █████╗  ██████╗██╗  ██╗
██╔════╝ ██╔══██╗██╔══██╗██║   ██║██║╚██╗██╔╝      ██║  ██║██╔══██╗██╔════╝██║ ██╔╝
██║  ███╗██████╔╝███████║██║   ██║██║ ╚███╔╝ █████╗███████║███████║██║     █████╔╝ 
██║   ██║██╔══██╗██╔══██║╚██╗ ██╔╝██║ ██╔██╗ ╚════╝██╔══██║██╔══██║██║     ██╔═██╗ 
╚██████╔╝██║  ██║██║  ██║ ╚████╔╝ ██║██╔╝ ██╗      ██║  ██║██║  ██║╚██████╗██║  ██╗
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚═╝  ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
        
        Welcome to Gravix-Hack AI Terminal
        Advanced Cybersecurity Assistant v2.1.0
        `);
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const target = document.querySelector(link.getAttribute('href'));
                target.scrollIntoView({ behavior: 'smooth' });
            });
        });

        // Mobile menu toggle
        const hamburger = document.querySelector('.hamburger');
        if (hamburger) {
            hamburger.addEventListener('click', this.toggleMobileMenu);
        }

        // Scroll effects
        window.addEventListener('scroll', this.handleScroll);

        // Terminal input
        const terminalInput = document.getElementById('terminal-input');
        if (terminalInput) {
            terminalInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.handleTerminalInput(e.target.value);
                    e.target.value = '';
                }
            });
        }

        // Tool category filters
        document.querySelectorAll('.tool-category').forEach(category => {
            category.addEventListener('click', (e) => {
                this.filterTools(e.target.dataset.category);
            });
        });
    }

    startMatrixEffect() {
        const matrixBg = document.getElementById('matrix-bg');
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+-=[]{}|;:,.<>?';
        
        setInterval(() => {
            if (document.querySelectorAll('.matrix-char').length < 50) {
                const char = document.createElement('div');
                char.className = 'matrix-char';
                char.textContent = characters[Math.floor(Math.random() * characters.length)];
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
        }, 200);
    }

    startTypingEffect() {
        const commands = [
            'nmap -sS -A target.com',
            'sqlmap -u "http://target.com/page?id=1" --dbs',
            'hydra -l admin -P rockyou.txt target ssh',
            'nikto -h http://target.com',
            'metasploit framework loading...',
            'burpsuite --target=http://target.com'
        ];
        
        const typingElement = document.getElementById('typing-command');
        const outputElement = document.getElementById('terminal-output');
        
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
                    setTimeout(typeChar, 100);
                } else {
                    setTimeout(() => {
                        if (outputElement) {
                            outputElement.innerHTML += `
                                <div class="output-line">
                                    <span style="color: #00ff41;">[✓]</span> 
                                    <span style="color: #cccccc;">Command executed successfully</span>
                                </div>
                            `;
                        }
                        
                        commandIndex = (commandIndex + 1) % commands.length;
                        setTimeout(typeCommand, 2000);
                    }, 1000);
                }
            };
            
            typeChar();
        };
        
        typeCommand();
    }

    handleTerminalInput(input) {
        const terminalContent = document.getElementById('terminal-content');
        if (!terminalContent) return;

        // Add user input to terminal
        const inputLine = document.createElement('div');
        inputLine.innerHTML = `
            <div class="terminal-line">
                <span class="terminal-prompt">root@gravix-hack:~#</span>
                <span style="color: #ffffff;">${input}</span>
            </div>
        `;
        terminalContent.appendChild(inputLine);

        // Process command
        const response = this.processCommand(input.toLowerCase().trim());
        
        // Add response to terminal
        const responseLine = document.createElement('div');
        responseLine.innerHTML = `
            <div class="terminal-response" style="color: #00ff41; margin: 1rem 0;">
                ${response}
            </div>
        `;
        terminalContent.appendChild(responseLine);

        // Scroll to bottom
        terminalContent.scrollTop = terminalContent.scrollHeight;
    }

    processCommand(command) {
        // Basic AI command processing
        const responses = {
            'help': `
                <div style="color: #00ff41;">
                    <h4>🔐 Gravix-Hack AI Commands:</h4>
                    <div style="margin-left: 20px; color: #cccccc;">
                        <p><span style="color: #ffd700;">help</span> - Show this help menu</p>
                        <p><span style="color: #ffd700;">tools</span> - List available security tools</p>
                        <p><span style="color: #ffd700;">scan [target]</span> - Network scanning guidance</p>
                        <p><span style="color: #ffd700;">exploit [service]</span> - Exploitation techniques</p>
                        <p><span style="color: #ffd700;">crack [hash]</span> - Password cracking methods</p>
                        <p><span style="color: #ffd700;">web [url]</span> - Web application testing</p>
                        <p><span style="color: #ffd700;">clear</span> - Clear terminal</p>
                    </div>
                </div>
            `,
            'tools': `
                <div style="color: #00ff41;">
                    <h4>🛠️ Available Security Tools:</h4>
                    <div style="margin-left: 20px; color: #cccccc;">
                        <p><span style="color: #ff6b6b;">Network:</span> nmap, masscan, zmap</p>
                        <p><span style="color: #ff6b6b;">Web:</span> burpsuite, sqlmap, nikto, dirb</p>
                        <p><span style="color: #ff6b6b;">Exploitation:</span> metasploit, exploit-db</p>
                        <p><span style="color: #ff6b6b;">Password:</span> john, hashcat, hydra</p>
                        <p><span style="color: #ff6b6b;">Wireless:</span> aircrack-ng, reaver</p>
                    </div>
                </div>
            `,
            'clear': '',
        };

        // Handle clear command
        if (command === 'clear') {
            document.getElementById('terminal-content').innerHTML = '';
            return '';
        }

        // Handle scan command
        if (command.startsWith('scan ')) {
            const target = command.split(' ')[1] || 'TARGET';
            return `
                <div style="color: #00ff41;">
                    <h4>🔍 Network Scanning Guide for: ${target}</h4>
                    <div style="margin-left: 20px; color: #cccccc;">
                        <p>1. <span style="color: #ffd700;">nmap -sS ${target}</span> - SYN scan</p>
                        <p>2. <span style="color: #ffd700;">nmap -A -T4 ${target}</span> - Aggressive scan</p>
                        <p>3. <span style="color: #ffd700;">nmap -p- --min-rate 10000 ${target}</span> - All ports</p>
                        <p>4. <span style="color: #ffd700;">nikto -h ${target}</span> - Web vulnerabilities</p>
                        <p style="color: #ff6b6b;">⚠️ Only scan authorized targets</p>
                    </div>
                </div>
            `;
        }

        // Handle web command
        if (command.startsWith('web ')) {
            const url = command.split(' ')[1] || 'TARGET_URL';
            return `
                <div style="color: #00ff41;">
                    <h4>🌐 Web Application Testing: ${url}</h4>
                    <div style="margin-left: 20px; color: #cccccc;">
                        <p>1. <span style="color: #ffd700;">nikto -h ${url}</span> - Vulnerability scan</p>
                        <p>2. <span style="color: #ffd700;">dirb ${url}</span> - Directory enumeration</p>
                        <p>3. <span style="color: #ffd700;">sqlmap -u "${url}/page?id=1"</span> - SQL injection</p>
                        <p>4. Manual testing with Burp Suite</p>
                        <p style="color: #ff6b6b;">⚠️ Educational purposes only</p>
                    </div>
                </div>
            `;
        }

        // Default response for other commands
        if (responses[command]) {
            return responses[command];
        }

        // AI-like responses for general queries
        return `
            <div style="color: #00ff41;">
                <h4>🤖 Gravix-Hack AI Response:</h4>
                <div style="margin-left: 20px; color: #cccccc;">
                    <p>I understand you're asking about: "<span style="color: #ffd700;">${command}</span>"</p>
                    <p>For specific cybersecurity guidance, try:</p>
                    <p>• <span style="color: #ffd700;">scan [target]</span> - for network testing</p>
                    <p>• <span style="color: #ffd700;">web [url]</span> - for web app testing</p>
                    <p>• <span style="color: #ffd700;">tools</span> - to see available tools</p>
                    <p>Type <span style="color: #ffd700;">help</span> for more commands</p>
                </div>
            </div>
        `;
    }

    filterTools(category) {
        // Update active category
        document.querySelectorAll('.tool-category').forEach(cat => {
            cat.classList.remove('active');
        });
        document.querySelector(`[data-category="${category}"]`).classList.add('active');

        // Filter tools (this would connect to your tools database)
        this.loadTools(category);
    }

    loadTools(category = 'all') {
        const toolsGrid = document.getElementById('tools-grid');
        if (!toolsGrid) return;

        const tools = this.getToolsData(category);
        
        toolsGrid.innerHTML = '';
        
        tools.forEach(tool => {
            const toolCard = document.createElement('div');
            toolCard.className = 'tool-card fade-in-up';
            toolCard.innerHTML = `
                <div class="tool-header">
                    <div class="tool-icon">
                        <i class="${tool.icon}"></i>
                    </div>
                    <div class="tool-name">${tool.name}</div>
                </div>
                <div class="tool-description">${tool.description}</div>
                <div class="tool-tags">
                    ${tool.tags.map(tag => `<span class="tool-tag">${tag}</span>`).join('')}
                </div>
            `;
            toolsGrid.appendChild(toolCard);
        });
    }

    getToolsData(category) {
        const allTools = {
            recon: [
                {
                    name: 'Nmap',
                    description: 'Network discovery and security auditing tool',
                    icon: 'fas fa-search',
                    tags: ['scanning', 'enumeration', 'discovery']
                },
                {
                    name: 'TheHarvester',
                    description: 'Email, subdomain and people name harvester',
                    icon: 'fas fa-seedling',
                    tags: ['osint', 'gathering', 'reconnaissance']
                },
                {
                    name: 'Maltego',
                    description: 'Interactive data mining tool',
                    icon: 'fas fa-project-diagram',
                    tags: ['osint', 'visualization', 'analysis']
                }
            ],
            scanning: [
                {
                    name: 'Nikto',
                    description: 'Web server vulnerability scanner',
                    icon: 'fas fa-spider',
                    tags: ['web', 'vulnerability', 'scanning']
                },
                {
                    name: 'OpenVAS',
                    description: 'Vulnerability assessment system',
                    icon: 'fas fa-shield-alt',
                    tags: ['vulnerability', 'assessment', 'enterprise']
                }
            ],
            exploitation: [
                {
                    name: 'Metasploit',
                    description: 'Penetration testing framework',
                    icon: 'fas fa-rocket',
                    tags: ['exploitation', 'framework', 'payloads']
                },
                {
                    name: 'SQLMap',
                    description: 'SQL injection testing tool',
                    icon: 'fas fa-database',
                    tags: ['sql', 'injection', 'automation']
                }
            ],
            password: [
                {
                    name: 'John the Ripper',
                    description: 'Password cracking tool',
                    icon: 'fas fa-key',
                    tags: ['password', 'cracking', 'hashes']
                },
                {
                    name: 'Hashcat',
                    description: 'Advanced password recovery',
                    icon: 'fas fa-unlock',
                    tags: ['gpu', 'cracking', 'advanced']
                }
            ],
            wireless: [
                {
                    name: 'Aircrack-ng',
                    description: 'WiFi security auditing suite',
                    icon: 'fas fa-wifi',
                    tags: ['wifi', 'wireless', 'cracking']
                }
            ]
        };

        if (category === 'all') {
            return Object.values(allTools).flat();
        }
        
        return allTools[category] || [];
    }

    handleScroll() {
        const navbar = document.querySelector('.navbar');
        if (window.scrollY > 100) {
            navbar.style.background = 'rgba(10, 10, 10, 0.98)';
        } else {
            navbar.style.background = 'rgba(10, 10, 10, 0.95)';
        }
    }

    toggleMobileMenu() {
        const navMenu = document.querySelector('.nav-menu');
        navMenu.classList.toggle('active');
    }
}

// Global functions
function startHacking() {
    document.getElementById('terminal').scrollIntoView({ behavior: 'smooth' });
    setTimeout(() => {
        document.getElementById('terminal-input').focus();
    }, 1000);
}

function scrollToFeatures() {
    document.getElementById('features').scrollIntoView({ behavior: 'smooth' });
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new GravixHackAI();
    
    // Load tools on page load
    const toolsSection = document.getElementById('tools-grid');
    if (toolsSection) {
        setTimeout(() => {
            window.gravixAI = new GravixHackAI();
            window.gravixAI.loadTools('all');
        }, 1000);
    }
});

// Export for global access
window.GravixHackAI = GravixHackAI;
