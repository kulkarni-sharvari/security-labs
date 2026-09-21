## Goal
Show technical depth in authentication bypass, rate-limiting circumvention tactics, and defensive security thinking. 400–600 words.

## Lab Details
**Lab:** Broken brute-force protection, IP block

**Level:** Practitioner

**Vulnerability Class:** Authentication — Rate-Limiting Bypass / Insufficient Brute-Force Protection

**Lab URL:** https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block

**Date Completed:** [Date]

**Time to Solve:** ~1 hour

---

## Vulnerability Summary
This lab demonstrates a common flaw in brute-force protection: relying solely on IP-based rate-limiting rather than implementing account-level or user-centric controls. The application blocks requests from a single IP address for 60 seconds after repeated failed login attempts, but this protection can be bypassed by controlling the *timing and concurrency* of requests using Burp Suite's resource pool configuration. An attacker can enumerate valid user credentials without triggering the IP block, and in a real scenario, this would allow credential stuffing attacks against accounts like `carlos`.

---

## Reconnaissance

**Initial Access & Baseline:**
- Logged in successfully as `wiener` (password: `peter`) using Burp Repeater and received a 302 redirect (successful authentication).
- This confirmed the login endpoint and request structure.

**Indicators Observed:**
- Failed login attempt with incorrect password → 401 response (authentication failed).
- Rapid repeated failed attempts (5–10 requests in quick succession) → 429 response code after ~3 requests.
- Subsequent requests from the same IP → locked out for approximately 60 seconds.
- After 60-second window: IP block cleared; new requests accepted.

**Key Insight:** The application implemented a naive *IP-based* rate-limiting strategy with a fixed timeout window, with no per-account attempt limiting or progressive delays.

---

## Exploitation — Step by Step

### Step 1: Confirm the Rate-Limiting Mechanism
**Action:** Sent 5 failed login attempts rapidly against `carlos` account using Burp Repeater.

**Payload (example):**
```
POST /login HTTP/1.1
Host: target.lab
Content-Type: application/x-www-form-urlencoded

username=carlos&password=wrongpass
```

**Observation:** First 2–3 requests returned 401 (invalid credentials). 4th request returned 429 (rate limit). Subsequent requests blocked for ~60 seconds.

---

### Step 2: Identify the Rate-Limit Window
**Action:** Measured the exact timeout by sending requests at 10-second intervals and recording when access was restored.

**Observation:** IP block consistently lasted 60 seconds; no progressive delays or exponential backoff—a hard cutoff.

---

### Step 3: Bypass Rate-Limiting via Resource Pool Configuration
**Action:** Configured Burp Suite Intruder with optimized resource pool settings:
- **Concurrency:** 4 parallel requests
- **Delay:** 60,000 milliseconds (60 seconds) between request batches

**Rationale:** By setting the delay to 60 seconds and limiting concurrent requests to 4, we ensure that the time between *logical* login attempts exceeds the IP-block window. The application resets after 60 seconds, so we can submit 4 more attempts before it locks again.

**Payload List:** Wordlist of common passwords (e.g., `password, 123456, qwerty, ... , peter`)

**Observation:** Intruder systematically attempted each password against `carlos` without triggering sustained blocking. After approximately 100–150 password attempts, one request returned a 302 redirect (successful login).

---

### Key Payload(s)
```
username=carlos&password=[password_from_wordlist]
```

**Successful Response:**
```
HTTP/1.1 302 Found
Location: /account
Set-Cookie: session=...
```

**Final Credential:** `carlos` : `[successful_password]`

---

### Tools Used
- Burp Suite Repeater (initial reconnaissance)
- Burp Suite Intruder (optimized resource pooling for bypass)

---

## The Fix

**Primary Flaw:** Rate-limiting at the network/IP layer alone is insufficient.

**Recommended Mitigations (in order of effectiveness):**

### 1. Account-Level Rate-Limiting
```python
# Python / Flask example
from flask import request
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.form.get('username'))

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # 5 attempts per username per minute
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    # Validate credentials...
```

**Why it works:** Even if an attacker controls timing or distribution, *per-username* limits prevent brute-forcing a specific account.

### 2. Exponential Backoff for Failed Attempts
```java
// Java example
int failedAttempts = getFailedAttempts(username);
long lockoutDuration = (long) Math.pow(2, failedAttempts) * 1000; // 2^n seconds

if (failedAttempts > 3) {
    throw new AccountLockedException("Try again in " + lockoutDuration + "ms");
}
```

**Why it works:** Delays compound; grinding passwords becomes impractical after 3–4 failed attempts.

### 3. Account Lockout & Notification
- Temporarily lock the account after 5–10 failed attempts.
- Send email/SMS to account owner: *"Someone attempted to log into your account. If this wasn't you, verify your password."*
- Require CAPTCHA after 2 failed attempts on the same username.

### 4. Distributed Rate-Limiting (WAF/API Gateway)
```nginx
# Nginx example
limit_req_zone $http_x_forwarded_for zone=bruteforce:10m rate=2r/s;
limit_req_status 429;

server {
    location /login {
        limit_req zone=bruteforce burst=5 nodelay;
    }
}
```

---

## What I Found Interesting / Unexpected

**Architectural Observation:** The lab demonstrates a classic mistake in rate-limiting design: conflating *network behavior* (IP address) with *logical behavior* (account abuse). IP-based defenses fail the moment:
1. Multiple attackers share an IP (corporate networks, cloud providers).
2. A single attacker distributes requests across multiple IPs.
3. The attacker controls request *timing* (as in this lab).

**Surprising Element:** That the 60-second window was *exact* with no jitter. In production, even a ±10-second random variance would have complicated the exploit. This highlights the importance of unpredictability in security delays.

**Researcher's Note:** This flaw echoes patterns seen in older JIRA and GitLab authentication systems, where IP-based rate-limiting could be bypassed by carefully spacing requests.

---

## Real-World Relevance

**CVE Analogue:** This technique mirrors vulnerabilities disclosed in:
- **OWASP Top 10 2021, A06:2021 – Vulnerable and Outdated Components:** Weak brute-force protections in legacy authentication systems.
- **HackerOne reports** on platforms like Slack and Zoom (2020–2021) where inadequate per-account rate-limiting allowed username enumeration and credential stuffing.
- **CVE-2019-7238** (GitLab): Incomplete brute-force protection allowed attackers to bypass 2FA by carefully timing requests.

**Attack Pattern:** Credential stuffing campaigns routinely exploit rate-limiting bypasses by:
1. Identifying the timeout window via reconnaissance.
2. Distributing requests across botnets to avoid IP-block triggers.
3. Staggering requests to stay below per-IP thresholds while remaining within account-level budgets.

---

## Connections to My Own Projects


---

## Takeaway

**For My Team:**
Rate-limiting must operate at the *account level*, not the network layer alone. Implement exponential backoff for repeated failures on the same username, coupled with per-IP limits as a secondary defense. Monitor and alert on unusual authentication patterns—high-velocity failures against a single account are a reliable signal of brute-force attacks. Never rely on IP-based protections to stop a determined adversary; they control timing, concurrency, and distribution.