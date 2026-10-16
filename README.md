# 🛠️ MOD Worker Panel

A modified Cloudflare Worker Panel for **my** needs. You are welcome to use it.

# ⭐ Key Features

- 🔒 String + property-name obfuscation with a per-build ChaCha20 cipher, verified against the un-obfuscated build before every zip is written
- 🚫 Automatic banned word detection that decrypts the payload and scans the cleartext (not just `grep` over the bundle)
- 🌐 Smart CleanIP management with random selection (up to 10 IPs) from clean IP pool

# 🚀 Configuration

## 🔑 Required Environment Variables

- `ID`: Your UUID for VLESS (old `UUID`)
- `PASS`: Password for Trojan protocol (old `TROJAN_PASS`)
- `HASH`: Hash for Trojan protocol (calc it here for `PASS` https://emn178.github.io/online-tools/sha224.html)
- `DATABASE`: KV namespace for settings storage (old hardcoded `bpb`). Must be same as KV name.
- `PROXYIP`: Comma-separated list of proxy IPs. Pick few closest to your location https://www.nslookup.io/domains/bpb.yousef.isegaro.com/dns-records/. Or just use `bpb.yousef.isegaro.com` if you are lazy.

![image](https://github.com/user-attachments/assets/12aaad8a-d05c-4356-aa2f-291a139301f6)

## ⚙️ Panel Settings

### 🌍 Clean IPs

https://github.com/goingfine/WinCFScan

Example:

```
108.162.198.28,108.162.198.164,23.227.39.128,23.227.39.83,45.12.31.29,45.12.30.95,195.245.221.118,195.245.221.53,104.25.236.198,104.25.140.172,188.244.122.154,188.244.122.8,141.101.120.101,141.101.121.60,185.176.26.247,185.176.26.153,195.85.23.46,195.85.23.61,199.181.197.120,199.181.197.2,104.22.55.15,104.22.43.239,45.131.5.20,45.131.5.102,172.66.217.214,172.66.129.151,185.135.9.14,185.135.9.167,162.159.60.98,162.159.253.109,154.85.99.215,154.85.99.137,103.169.142.219,103.169.142.117,45.80.111.218,45.80.111.111,185.148.107.69,185.148.107.54,89.116.250.251,89.116.250.124,45.8.211.235,45.8.211.222,185.193.28.231,185.193.28.24,170.114.45.222,170.114.46.33,168.100.6.39,168.100.6.208,104.24.192.66,104.24.86.106,31.43.179.166,31.43.179.153,188.42.88.124,188.42.88.206,104.20.42.62,104.20.127.20,104.19.5.69,104.19.145.125,188.114.97.155,188.114.99.212,156.238.19.229,156.238.19.195,185.162.230.167,185.162.230.98,194.152.44.102,194.152.44.236,172.64.69.108,45.85.118.28,45.85.119.170,147.78.140.125,147.78.140.56,190.93.247.239,190.93.244.35,205.233.181.138,205.233.181.84,159.246.55.144,159.246.55.125,66.235.200.53,66.235.200.105,185.146.173.37,185.146.173.44,185.221.160.29,185.221.160.225,192.65.217.189,192.65.217.113,172.67.11.230,172.67.27.97,104.27.127.11,104.27.11.55,104.21.61.199,104.21.231.8,160.153.0.59,160.153.0.182,185.174.138.94,185.174.138.241,45.142.120.55,45.142.120.9,45.159.216.46,45.159.217.230,103.160.204.250,103.160.204.48,154.83.2.152,154.83.2.124,194.53.53.76,194.53.53.37,162.251.82.95,162.251.82.132,141.193.213.87,141.193.213.239,185.238.228.54,185.238.228.122,185.59.218.169,185.59.218.219,108.165.216.31,108.165.216.72,159.112.235.13,159.112.235.191,193.9.49.201,193.9.49.187,66.81.247.158,66.81.247.95,193.227.99.7,193.227.99.123,91.193.59.7,91.193.58.184,194.36.55.59,194.36.55.183,198.41.201.130,198.41.216.12,185.18.250.223,185.18.250.98,147.185.161.48,147.185.161.195,104.16.74.225,104.16.96.97,185.170.166.169,185.170.166.127,104.254.140.79,104.254.140.243,103.21.244.96,103.21.244.5,104.26.5.39,173.245.59.126,173.245.49.227,104.31.16.99,104.31.16.236,104.18.73.253,104.18.240.219
```

### Filter Clean IP

Often you can leverage latency to find good IPs. For example, you are in center of Iran and closest CF inside country has 35 ms ping. Next stop is EU with 60 ms. Use next PS1 script that read clean ip list from clipboard and select best ones

```
# Define constants for better readability and maintainability
$MIN_LATENCY = 35+5  # Minimum acceptable latency in milliseconds
$MAX_LATENCY = 60+10  # Maximum acceptable latency in milliseconds
$PING_ATTEMPTS = 5 # Number of times to ping each IP address

# Retrieve the content from the clipboard
$clipboardContent = Get-Clipboard

# Split the clipboard content by commas to get individual IP addresses
$ipList = $clipboardContent -split ','

# Check if the clipboard content is empty or not a valid list of IP addresses
if ($null -eq $ipList -or $ipList.Count -eq 0) {
    Write-Error "Clipboard does not contain a valid comma-separated list of IP addresses."
    return
}

# Initialize an array to store filtered IP addresses
$filteredIPs = @()

# Loop through each IP address in the list
foreach ($ip in $ipList) {
    # Trim any leading or trailing whitespace from the IP address
    $trimmedIP = $ip.Trim()

    # Initialize an array to store response times for the current IP
    $responseTimes = @()

    # Ping the IP address multiple times to get response times
    for ($i = 0; $i -lt $PING_ATTEMPTS; $i++) {
        $pingResult = Test-Connection -ComputerName $trimmedIP -Count 1 -ErrorAction SilentlyContinue
        if ($pingResult) {
            # If the ping is successful, add the response time to the array
            $responseTimes += $pingResult.ResponseTime
        }
    }

    # Check if we have any response times recorded
    if ($responseTimes.Count -gt 0) {
        # Calculate the average latency from the response times
        $avgLatency = ($responseTimes | Measure-Object -Average).Average

        # Check if the average latency is within the desired range
        if ($avgLatency -gt $MIN_LATENCY -and $avgLatency -lt $MAX_LATENCY) {
            # If the latency is within the range, add the IP to the filtered list
            $filteredIPs += $trimmedIP
        }
    }
}

# Create comma-separated string and copy to clipboard
if ($filteredIPs.Count -gt 0) {
    $output = $filteredIPs -join ','
    $output | Set-Clipboard
    $output  # Display results in console
} else {
    Write-Warning "No IP addresses matched the latency criteria"
    "" | Set-Clipboard  # Clear clipboard if no results
}
```

# 🔐 Build & Obfuscation

`build.ps1` produces each worker like this:

1. `wrangler deploy --dry-run` bundles `src/worker.js`;
2. `uglify-js --compress drop_console=true --mangle` minifies it (AST-level work only - no regex is ever run over the source);
3. a copy is kept as `output/_worker.reference.js`;
4. `obfuscate.mjs` runs js-confuser and encrypts every string literal **and every property name** with **ChaCha20 (RFC 8439)**: one random 32-byte key per build, one random 8-byte nonce per string, payload carried as base64;
5. `verify.mjs` proves that nothing was lost, that no banned word survives in the clear and that the artifact still parses and exports a handler;
6. `smoke.mjs` drives both the obfuscated worker and the reference through 21 requests and requires byte-identical behaviour;
7. only then is the zip written.

## What this is, and what it is not

- It defeats keyword scanning and string/property signature matching: the bundle contains no `vless`, `trojan` or `bpb`, no readable HTML/CSS/client script, and no readable property names.
- It is **not confidentiality**. The ChaCha20 key ships inside `_worker.js`, so anyone who obtains the file can decode the payload. Treat the worker as public: keep `ID`, `PASS`, `HASH`, `PROXYIP` in environment variables/secrets and never put secrets in code.

## Hardening knobs (environment variables)

| Variable | Default | Notes |
| --- | --- | --- |
| `HARDEN_STRINGS` | `true` | `false` = legacy mode: only strings containing `bpb`/`vless`/`trojan` are concealed (~40% smaller, but the panel's identity is readable) |
| `HARDEN_OPAQUE` | `0.2` | opaque predicate probability |
| `HARDEN_INTEGRITY` | `false` | per-function checksum lock. **Off by default**: js-confuser 2.0 generates its wrapper locals without checking the names `renameVariables` already handed out, so a build can shadow the hash function itself (`function dJ(){var aV=…aV(ba,9897108)}`) and make that function throw `TypeError` at runtime. It is a per-build lottery, so `verify.mjs` rejects the shape and the lock is opt-in |
| `HARDEN_ANTIDEBUG` | `false` | `debugger;` injection - costs CPU, not recommended on the free plan |
| `HARDEN_SELFDEFENDING` | `false` | breaks any code formatter |
| `HARDEN_CFF` | `0` | **must stay 0**: js-confuser's control-flow flattening emits a `with` statement, which is a syntax error in an ES module. `obfuscate.mjs` refuses to build with it enabled |

`HARDEN_INTEGRITY=true` hashes each top-level function through `Function.prototype.toString()` on first call. Two reasons it is off by default: the wrapper-local collision described above, and the fact that the check fires on any runtime that normalises the source text. `verify.mjs` rejects the collision shape statically, so if you enable the lock you will at least not ship that bug.

`HARDEN_OPAQUE` is the cheap anti-analysis knob (it survives the ES-module constraint that rules out control-flow flattening). Raise it if you want more noise in the control flow; it costs a few bytes and no measurable CPU.

## Gates

```powershell
node tools/cipher.test.mjs   # RFC 8439 test vector, round-trip, non-determinism
node verify.mjs              # syntax, data-loss coverage, banned-word leak, runtime presence
node verify.mjs <_worker.js> # audit a lone artifact (a downloaded zip): the key is recovered from the file itself
node smoke.mjs               # behaviour parity against output/_worker.reference.js
node smoke.mjs --bench       # ...plus cold/warm cost of the concealed-string path
```

A zip is only written when all gates pass, and every one of the 20 builds is verified individually with its own key.

Measured overhead of the concealed-string path (Node wall clock, 400 warm `GET /login` requests): `+0.04 ms/request` warm and `+7 ms` on the very first request in an isolate, because js-confuser caches each decoded payload entry per index. That is far inside the free-plan 10 ms CPU budget.

## Password storage

`pwd` in KV holds `pbkdf2$<iterations>$<salt>$<hash>` (PBKDF2-SHA256, 25 000 iterations by default). The measured cost of one derivation with WebCrypto here is ~4.5 ms (10k ~3 ms, 100k ~18 ms), so the default fits the Workers free-plan 10 ms CPU budget; set the `PBKDF2_ITERATIONS` variable (e.g. `100000`) on a paid plan. Legacy plain-text values are verified and upgraded in place on the next successful login. Passwords must contain a capital letter, a number and be at least 8 characters - enforced on the server now, not only in the browser. Login is throttled to 5 failures per IP per 15 minutes (KV-backed, best effort).

# 📝 Credits

Based on [BPB Worker Panel](https://github.com/bia-pain-bache/BPB-Worker-Panel) <3
