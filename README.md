# OSINT-CD
OSINT writeup for the team





# OSINT Objective 
OSINT (Open-Source Intelligence) is the First Step of the Penetration Testing process for a given target. OSINT is a thorough examination of publicly available information, which can increase the chances of finding a vulnerable system, gaining valid credentials through password spraying, gaining a foothold via social engineering and many more. 

There are many tools and techniques that can be used for OSINT, these tools help with information gathering which can include but are not limited to:
- Image OSINT
- Email Address 
- Breached Data
- People OSINT
- Phone Numbers
- Usernames
- Website OSINT
- Social Media OSINT
- Wireless Network OSINT
- OSINT Automation

For the full OSINT framework, you can refer to this https://osintframework.com/





# OSINT Methodology
1. Domain Name
    - First step in OSINT is often identifying the target's domain name. Assuming the client’s domain name is available for OSINT, we can start with domain name enumeration by finding more subdomains associated with the main domain.
    - Once the domain names has been found, investigation of its registration details (via WHOIS lookups), discovering its expiration dates, registrar information, and even the contact details of domain administrators. This can provide useful intelligence, including potential targets for social engineering or insights into potential weak spots for cyberattacks.
    
    **Tools**: *WHOIS, DNSdumpster, Passive DNS, Virustotal*
    
2. Subdomain enumeration
    - Subdomain enumeration involves identifying subdomains associated with the target's domain. Attackers often exploit subdomains that are overlooked, misconfigured, or less secure.
    - Insecure subdomains can expose staging environments (like `dev.target.com`), internal services (like `intranet.target.com`), or even misconfigured services (like `files.target.com`). Subdomains often serve as attack vectors or gateways into the organization’s network.
    
    **Tools**: *Sublist3r, Amass, Knockpy, Subfinder, DNSdumpster*
    
3. Username/Email Intelligence
    - Username and email intelligence involves gathering data about usernames or email addresses that are linked to the target organization.
    - Gathering email addresses and usernames can be critical for phishing campaigns or brute-forcing login attempts.
    
    **Tools**: *[Hunter.io](http://hunter.io/), Have I Been Pwned, Social Media Scraping, LinkedIn, Shodan*
    
4. IP/MAC Address 
    - IP address and MAC address intelligence involves identifying the IP addresses that belong to a target domain.
    - Performing IP/MAC Address reverse lookups on the given addresses might provide the hosting servers of the target.
    
    **Tools**: *Shodan, Censys, RIPE NCC, ipinfo.io, ARIN*
    
5. Social Media
    - Gather intelligence about employees, key personnel, business partners, and organizational activities.
    - Leaks such as passwords, business plans, or internal tools shared unintentionally by employees could be found. Employees' social media activity can also provide direct clues for spear-phishing attempts or social engineering.
    
    **Tools**: *Social Search Engines (Social-Searcher), LinkedIn, Facebook, Twitter, Instagram, Recon-ng*
    
6. Automated OSINT Tools
    1. large surface scans, including the darkweb
    2. Tools can scan through large datasets, compile results from various sources, and present them in a useful manner.
    
    **Tools:** *SpiderFoot, IntelligenceX, theHarvester, GHunt, sherlock*
    
7. Malicious file analysis
    - If the target has been compromised, analysts can extract useful intelligence such as attack vectors, IP addresses, infrastructure used by attackers, and even potential links to adversaries or threat actors.
    
    **Tools**: *Virustotal, Ghidra, Ether*
    
8. Threat Intelligence
    - Threat intelligence is gathering data on past/current threats related to the target. This could include identifying malware signatures, attack vectors, or actors involved in previous attacks on the target.
    
    **Tools:** *Malpedia, HoneyDB, MISP, ThreatConnect*
    
9. Exploits and Adversaries 
    - If the target organization is using outdated software, common vulnerabilities, or has exposed weak points, we may exploit these.
    - Knowing common exploits and tactics used by specific adversaries (e.g., cybercriminal groups, APTs) can guide the identification of vulnerabilities within the target's defenses.
    
    **Tools:** E*xploit-DB, Metasploit, CVE Search, Zero Day Initiative, Censys*







# What to Look out for?

1. Examples of Vulnerabilities from data collected
    1. **DNS**
        1. Expired Domains
           - Domains that have passed their expiry date and are still publicly available to enumeration
           - Tools like `DNSDumpster` will show the domain expiry dates.
        2. Zone Transfer Vulnerabilities
           - An attacker may query a DNS server and obtain a full list of records for a domain.
           - Tools like `dig` or `dnsrecon` can query for open zone transfers. If the server is not properly restricted, a zone transfer can reveal valuable information.
        3. Exposed internal DNS servers
        4. Whois obfuscation
            -  DNS servers might obfuscate the whois information in order to hide.
        5. Third party DNS provider
            - The target’s DNS might be hosted on a third-party provider.
    2. **Subdomains**
        1. Internal or Hidden subdomains
           - possible leaked subdomains that are used internally
           - Domains could be using weak credentials, legacy systems or HTTP 
           - Use tools like `Amass`, `Sublist3r`, and `crt.sh` to find hidden subdomains.
        2. Subdomain Takeover
           - Domains that are no longer in use, but still shows on public DNS records. Attackers can gain control of the subdomain through a takeover.
           - Tools like `subjack`, `takeover`, and `subdomain-takeover` can help identify potential subdomain takeover risks.
        3. Sensitive files 
           - subdomains might contain sensitive files such as `.bak`, `.sql`, `.zip`, `.tar`, `.log`, or `.env` files.
           - Use directory brute-forcing tools like `dirbuster` or `gobuster` to scan subdomains for sensitive files or directories that might be exposed.
        4. Wildcard DNS records
           - `*.domain.com` can cause unexpected subdomains to resolve to the same server or IP address, potentially exposing sensitive information or causing unintended behavior.
        5. Open Redirects 
           - Look for URL redirection mechanisms on subdomains, especially those that allow redirection to external sites. This can be tested by manipulating URLs and observing the behavior.
    3. **IP Address**
           - As the IP addresses are exposed, we can further enumerate the publicly available IP addresses from OSINT. 
           - Exposed Open Ports (Service Enumeration)
    4. **Breached Data**
           - Utilising tools to search for breached/leaked data of the target.
           - Can contain leaked emails and password combos.
           


Updated: 4/3/2025
TO DO: 
      - Dark Web OSINT
