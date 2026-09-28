# Lab: 2FA broken logic

## Lab Details
**Lab:** PortSwigger Web Security Academy — 2FA Brute-Force Bypass  
**Level:** Practitioner  
**Vulnerability Class:** Broken Authentication — 2FA Bypass via Parameter Tampering + Brute-Force  
**Lab URL:** [Lab link](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic)  
**Date Completed:** 25-Sep-2026  
**Time to Solve:** ~15–20 minutes

---

## Vulnerability Summary

The login endpoint fails to validate that the requesting user matches the account in the `verify` parameter during 2FA verification. By modifying the `verify` parameter to target another user (e.g., `carlos`), an attacker can trigger 2FA code generation for that user and brute-force a 4-digit numeric code (1000–9999) without rate limiting or account lockout. This enables complete account takeover without requiring the target user's password, rendering 2FA ineffective.

---

## Reconnaissance

With Burp Suite running, I investigated the authentication flow by logging in with a known account and observing the 2FA verification process.

**Key Indicators Observed:**

- **Session cookie is NOT validated against the `verify` parameter**: After removing the session cookie from the GET request, the page still displayed `/login2` and accepted input, proving session state does not govern authorization at this endpoint.

- **The `verify` parameter is user-controlled and determines whose 2FA is being verified**, not the authenticated session identity. This is a critical authorization flaw.

- **`verify` parameter accepts ONLY valid usernames**: Attempted injection of non-existent users (e.g., `nonexistent`, `admin'--`, `1' OR '1'='1`) returned 400 Bad Request, confirming the parameter is validated against the user database but not against session ownership.

- **No rate limiting observed**: Sent 100+ consecutive failed MFA-code attempts without triggering delays, lockout warnings, or exponential backoff. Requests processed uniformly fast (~200–500ms per request).

- **2FA code is numeric, 4 digits (range 1000–9999)**: This represents 9,000 possible values—highly brute-forceable with parallelization.

---

## Exploitation — Step by Step

### Step 1: Observe the 2FA Flow in Logged-In Session
**What I did:** Logged into my account with valid credentials, then analyzed the `POST /login2` request in Burp Suite.

**Observation:** The `verify` parameter in both GET and POST requests determines which user's 2FA code is being validated, regardless of who is logged in.

```
GET /login2?verify=[YOUR_USERNAME]
```

**Response:** 200 OK, displays 2FA code entry form with server-generated code sent.

---

### Step 2: Trigger 2FA Code Generation for Target User
**What I did:** Logged out, then sent a `GET /login2` request with `verify=carlos` to force the server to generate a 2FA code for Carlos.

```
GET /login2?verify=carlos
```

**Response:** 200 OK — Server generated a 2FA code for carlos, even though I am not authenticated as carlos. The endpoint blindly trusts the `verify` parameter.

**Why this works:** No authorization check validates that the requesting user should be accessing carlos's 2FA verification.

---

### Step 3: Brute-Force the 2FA Code
**What I did:** Submitted an invalid 2FA code first (to confirm the failure response), then configured Burp Intruder to brute-force the `mfa-code` parameter while keeping `verify=carlos`.

```
POST /login2 HTTP/1.1
verify=carlos&mfa-code=[PAYLOAD]
```

**Attack Configuration:**
- **Attack Type:** Sniper (single payload position on `mfa-code`)
- **Payload Set:** Numbers 1000–9999
- **Threads:** Maximum (to parallelize requests and mitigate per-request latency)
- **Success Indicator:** 302 redirect (accepted code) vs. 200 (rejected code)

**Result:** Intruder identified the correct code (e.g., `5412`) within ~3 minutes using parallelized requests. Sequential iteration would have taken ~20+ minutes due to per-request network latency.

---

### Step 4: Access Target Account
**What I did:** Loaded the 302 response in the browser to navigate to `/account` as carlos.

**Result:** Successfully logged into Carlos's account without knowing his password.

---

## Key Payloads

### Final Working Exploit Flow
```
# Step 1: Trigger code generation for target user
GET /login2?verify=carlos

# Step 2: Brute-force the 4-digit code via Intruder
POST /login2
verify=carlos&mfa-code=1000
verify=carlos&mfa-code=1001
...
verify=carlos&mfa-code=5412  ← Correct code, returns 302

# Step 3: Follow redirect
GET /account (in 302 Location header)
```

### Reconstructed Full Query Flow
```
Unauthenticated Request:
→ GET /login2?verify=carlos
← 200 OK (code generated for carlos, no auth check)

Brute-force Request:
→ POST /login2
  verify=carlos&mfa-code=5412
← 302 Location: /account

Follow Redirect:
→ GET /account
← 200 OK (logged in as carlos)
```

---

## Tools Used

- **Burp Suite Repeater** — Manually tested requests and verified `verify` parameter behavior
- **Burp Suite Intruder** — Parallelized brute-force of 4-digit codes (Sniper attack, 9,000 payloads)
- **Manual HTTP analysis** — Confirmed authorization logic flaws before automating

---

## The Fix

### Primary Issue: Parameter Tampering & Missing Authorization Check

**Vulnerable Code (Python/Flask example):**
```python
@app.route('/login2', methods=['POST'])
def verify_mfa():
    # ✗ VULNERABLE: trusts user input for authorization
    username = request.form.get('verify')  
    code = request.form.get('mfa-code')
    
    if check_mfa_code(username, code):
        login_user(username)
        return redirect('/account')
    
    return render_template('2fa.html', error='Invalid code')
```

**Secure Code:**
```python
@app.route('/login2', methods=['POST'])
def verify_mfa():
    # ✓ SECURE: derive identity from session, not user input
    username = session.get('pending_user')
    
    # Validate session state
    if not username or session.get('mfa_required') is not True:
        return redirect('/login'), 401
    
    code = request.form.get('mfa-code')
    
    # Use constant-time comparison to prevent timing attacks
    if hmac.compare_digest(code, get_mfa_code(username)):
        session['authenticated'] = True
        session['mfa_required'] = False
        login_user(username)
        return redirect('/account'), 302
    
    # Increment failed attempt counter
    session['failed_mfa_attempts'] = session.get('failed_mfa_attempts', 0) + 1
    if session['failed_mfa_attempts'] >= 10:
        session.clear()  # Force re-login
        return redirect('/login'), 401
    
    return render_template('2fa.html', error='Invalid code'), 401
```

### Secondary Issue: No Rate Limiting

**Add rate limiting to prevent brute-force:**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login2', methods=['POST'])
@limiter.limit("5 per minute")  # Max 5 attempts per minute per IP
def verify_mfa():
    # ... code from above ...
```

### Additional Security Mitigations

- **2FA Code Expiration**: Generate 4-digit codes with 5–10 minute TTL. Invalidate codes after the session times out.
- **Single-Use Enforcement**: Once a code is accepted, immediately invalidate it. Store hash in database, never plaintext.
- **Account Lockout Policy**: Lock account after 10 failed attempts; require manual admin unlock or 30-minute cooldown.
- **Constant-Time Comparison**: Use `hmac.compare_digest()` instead of `==` to prevent timing-based attacks on code guessing.
- **Audit Logging**: Log all 2FA verification attempts (success and failure) with timestamps, IP address, and username. Flag repeated failures for investigation.
- **WAF/Reverse Proxy Protection**: Configure Web Application Firewall to block IPs making >10 requests/minute to `/login2`.
- **Error Handling**: Never expose whether a username is valid or whether a code was close to correct. Use generic "Invalid code" message.

---

## What I Found Interesting / Unexpected

**The session cookie became completely irrelevant** once the user reached `/login2`. Most developers assume "if the user has a session, the request belongs to them," but here the `verify` parameter essentially overrides that assumption. This is a textbook example of **inconsistent authorization checks** across the authentication pipeline.

A developer might think: "We implemented 2FA—we're secure," without realizing the implementation itself undermines the security property 2FA is supposed to provide. The code length (4 digits) is weaker than industry standards (6 digits = 1 million possibilities), but the **real vulnerability is the absent rate limiting**. Even a 6-digit code becomes trivial when an attacker can send thousands of requests per second without penalty.

The brute-force slowness (20+ minutes sequentially) initially seemed like a barrier, but parallelization reduced this to ~3 minutes—a realistic real-world attack time. This reinforces that **rate limiting must be enforced at the application and infrastructure level, not just hoped for**.

---

## Real-World Relevance

- **Real-World Impact**: If Carlos is an administrator or has access to sensitive data (customer records, financial systems, source code), this becomes a **critical business risk**. An attacker could:
  - Steal admin credentials without physical/social engineering
  - Compromise data in minutes vs. days
  - Escalate privileges to infrastructure accounts
  - Establish persistent backdoors before detection

- **Attack Feasibility**: A 4-digit code (9,000 possibilities) on an unrate-limited endpoint is brute-forceable in **minutes** with basic automation. In production with even modest network speed, this is a viable attack vector for motivated adversaries.

---

## Connections to My Own Projects

When reviewing my own application authentication flows, I confirmed:
- Session validation is enforced on every protected endpoint (verify `session.user_id` matches request scope)
- 2FA endpoints explicitly reject requests where the authenticated user does not match the user being verified
- Rate limiting is applied at both application and reverse-proxy levels
- Failed 2FA attempts are logged and trigger account lockout after threshold

This lab reinforced the importance of treating 2FA endpoints with the same rigor as login endpoints—they are, functionally, a second login mechanism.

---

## Takeaway

**2FA is only as secure as its implementation.** A weak code length is fixable; missing rate limiting and parameter-based authorization checks are critical flaws that make 2FA worthless. When implementing or auditing multi-factor authentication, ensure:

1. **Identity derivation from session only** — Never let user input determine whose account is being accessed.
2. **Rate limiting at application and infrastructure layers** — Account lockout after N failures is mandatory.
3. **Short code expiration and single-use enforcement** — Codes should not persist indefinitely or be reusable.

**2FA endpoints ARE authentication endpoints. Treat them accordingly.**

---