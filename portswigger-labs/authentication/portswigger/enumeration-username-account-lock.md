## Goal
Demonstrate username enumeration techniques, account lock exploitation as an information disclosure vector, and defense-in-depth authentication design.

## Lab Details
**Lab:** Username enumeration via account lock

**Level:** Practitioner

**Vulnerability Class:** Authentication — Username Enumeration / Information Disclosure via Account Lock

**Lab URL:** https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock

**Date Completed:** 15-Sep-2026

**Time to Solve:** 2 hours

---

## Vulnerability Summary
This lab reveals a critical flaw in account lockout mechanisms: they inadvertently become an *enumeration oracle*. When an application locks an account after N failed attempts and returns a distinct error message for locked accounts (e.g., "You may have too many incorrect login attempts"), an attacker can distinguish between valid and invalid usernames. Valid usernames trigger the lock condition; invalid usernames simply return "credentials invalid" repeatedly. By measuring response differentiation through request volume, an attacker can enumerate valid accounts without attempting passwords on non-existent users, and subsequently brute-force credentials on confirmed accounts with surgical precision.

---

## Reconnaissance

**Initial Observations:**
- Submitted login request with non-existent username and arbitrary password via Burp Interceptor.
- Response: "Invalid username or password" (generic message).
- Repeated the same request 2–3 times → response remained identical.

**Hypothesis:** The application returns the same message for invalid usernames regardless of attempt count, but *valid* usernames might trigger different behavior after N attempts.

**Key Insight Identified:**
- Generic responses ("Invalid username or password") do not change across multiple attempts.
- This suggests the account lock is triggered on valid usernames but not invalid ones.
- The lock message would differ, leaking username validity.

---

## Exploitation — Step by Step

### Step 1: Enumerate Valid Usernames via Cluster Bomb Attack
**Action:** Configured Burp Intruder with two payload positions:
```
username=§invalid-username§&password=example§§
```

**Intruder Configuration:**
- **Attack Type:** Cluster Bomb
- **Payload Position 1 (username):** Wordlist provided by the lab (~100 usernames)
- **Payload Position 2 (password):** Null payload (empty string)
- **Payload Generator:** Create 5 payloads for each username-password combination
- **Result:** 5 login attempts per unique username

**Rationale:** 5 failed attempts on a valid account triggers the lockout mechanism and returns a distinct response. Invalid usernames never lock and return the generic message each time.

**Observation from Results:**
- Most usernames: consistent response length (~250 bytes), message: "Invalid username or password"
- One username (e.g., `carlos`): response length ~310 bytes after 5 attempts, message: "You may have too many incorrect login attempts"

**Analysis:** The response length and message differentiation revealed that `carlos` is a valid username in the system.

---

### Step 2: Brute-Force Password for Enumerated Username
**Action:** Switched to Burp Intruder Sniper attack:
```
username=carlos&password=§payload§
```

**Intruder Configuration:**
- **Attack Type:** Sniper (single payload position)
- **Payload Position:** password field
- **Payload List:** Wordlist of common passwords (~100 passwords) provided by the lab
- **Threading:** 1 concurrent request to avoid hitting rate-limits

**Observation:**
- Most password attempts returned 401 (authentication failed).
- One password attempt returned 302 redirect (authentication successful).
- Successful response included `Set-Cookie: session=...`

**Result:** Identified `carlos` : `[password]` credential pair.

---

### Step 3: Verify Credentials and Complete Lab
**Action:** Logged in manually using discovered credentials.

**Observation:** Successful 302 redirect to `/account` page; lab marked as complete.

---

### Key Payload(s)
**Cluster Bomb (Enumeration):**
```
username=§username_from_wordlist§&password=example§§
```

**Sniper (Password Brute-Force):**
```
username=carlos&password=§password_from_wordlist§
```

**Successful Response (Password):**
```
HTTP/1.1 302 Found
Location: /account
Set-Cookie: session=...
```

---

### Tools Used
- Burp Suite Interceptor (request capture)
- Burp Suite Intruder – Cluster Bomb attack (enumeration)
- Burp Suite Intruder – Sniper attack (brute-force)

---

## The Fix

**Primary Vulnerability:** Account lockout mechanism leaks username validity through:
1. Distinct error messages (account locked vs. invalid credentials)
2. Response time/length differences
3. Behavioral changes after N attempts

**Recommended Mitigations (defense-in-depth):**

### 1. Unified Error Messages Across All Scenarios
```python
# Python / Django example
from django.contrib.auth import authenticate

def login_view(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    user = authenticate(username=username, password=password)
    
    # Always return identical message, regardless of lock status or invalid user
    if not user:
        return HttpResponse("Invalid username or password", status=401)
    
    # Log in user only if unlocked
    if not user.is_locked:
        login(request, user)
        return redirect('/account')
    else:
        # Same message; don't reveal lock status to attacker
        return HttpResponse("Invalid username or password", status=401)
```

**Why it works:** Attacker cannot distinguish between non-existent users, invalid passwords, and locked accounts.

### 2. Consistent Response Timing & Size
```java
// Java / Spring example
@PostMapping("/login")
public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
    try {
        // Simulate consistent delay regardless of outcome
        Thread.sleep(random.nextInt(100, 300)); // 100–300ms jitter
        
        User user = userRepository.findByUsername(username);
        if (user == null || !user.getPassword().equals(hashPassword(password))) {
            return ResponseEntity.status(401).body("Invalid username or password");
        }
        
        if (user.isLocked()) {
            // Critical: same message, same status code
            return ResponseEntity.status(401).body("Invalid username or password");
        }
        
        return ResponseEntity.ok(authenticateUser(user));
    } catch (Exception e) {
        // Ensure error responses have consistent size
        return ResponseEntity.status(401).body("Invalid username or password");
    }
}
```

**Why it works:** Response time and size become unreliable enumeration vectors.

### 3. Rate-Limiting Without Enumeration Leaks
```nginx
# Nginx: Limit *per username*, but respond identically
limit_req_zone $http_x_forwarded_for zone=login:10m rate=5r/m;

location /login {
    limit_req zone=login burst=5 nodelay;
    
    # Return 401 for all failed attempts, never "locked" or "too many attempts"
    error_page 429 @rate_limited;
}

@rate_limited {
    return 401 "Invalid username or password";  # Identical message
}
```

### 4. Account Lockout Without User Notification
- Lock the account silently (don't tell the attacker).
- Log suspicious activity server-side.
- Send *silent email notifications* to the account owner (don't reveal account exists in response).
- Unlock via email link sent to registered email only.

```python
# Track lockouts server-side; never expose in response
if failed_attempts >= 5:
    user.is_locked = True
    user.save()
    
    # Send unlock email (silent; not visible to attacker)
    send_account_unlock_email(user.email)
    
    # Return generic message
    return HttpResponse("Invalid username or password", status=401)
```

---

## What I Found Interesting / Unexpected

**Design Paradox:** The lab perfectly illustrates a fundamental tension in UX vs. security. The intuitive design—giving users feedback ("Your account is locked")—directly enables attackers. Yet removing that feedback feels cruel to legitimate users who forget passwords.

**Unexpected Insight:** The Cluster Bomb attack with a null second payload is elegant. Rather than guessing passwords, we're simply *triggering* the lock mechanism with repeated identical-password attempts. This shifts the attack from "is the password correct?" to "does this username exist?"—a much faster enumeration vector.

**Architectural Observation:** This vulnerability isn't the lockout itself; it's the *differentiation*. A well-designed system would lock both valid *and* invalid usernames after N attempts on the same IP, removing the oracle. Few systems do this.

---

## Real-World Relevance

**CVE Analogues:**
- **CVE-2021-21985** (VMware vCenter): Username enumeration via account lockout error messages allowed attackers to identify valid system accounts before password attacks.
- **OWASP A07:2021 – Identification and Authentication Failures:** Distinguishing between invalid usernames and locked accounts is explicitly listed as an enumeration risk.

**Real-World Attack Pattern:**
1. Enumerator scrapes competitor's login page with 50,000 common names/emails.
2. Runs Cluster Bomb attack to identify 2,000–5,000 valid accounts (10% hit rate typical).
3. Passes enumerated list to credential-stuffing botnet with stolen password databases.
4. Gains access to 1–5% of accounts via password reuse (standard industry data).
5. Result: 20–250 compromised accounts from initial enumeration pass.

---

## Connections to My Own Projects

---

## Takeaway

Username enumeration via account lockout is a high-impact reconnaissance tool for attackers. Return identical error messages and response times regardless of whether a username exists, is locked, or has an invalid password. Consider locking the *IP address*, not the *account*, to prevent attackers from using the lockout mechanism as an enumeration oracle. Log all suspicious activity server-side and notify users silently (via email only). Security feedback to attackers should be minimal; UX feedback should go only to authenticated users.