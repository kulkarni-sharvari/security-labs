# 2FA Simple Bypass — Broken Access Control
**Goal:**
Demonstrate understanding of authentication state management, broken access control, and the gap between authentication and authorization.

## Lab Details
Lab: 2FA Simple Bypass — Broken Access Control

Level: Practitioner

Vulnerability Class: Broken Authentication / Broken Access Control — Session State Confusion

Lab URL: https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass

Date Completed: 21-Sep-2026

Time to Solve: 15 minutes

## Vulnerability Summary
The application implements two-factor authentication (2FA) via email verification codes, but fails to enforce authorization checks on the account details endpoint. After a user submits their username and password, the application grants a session and prompts for the 2FA code. However, the `/my-account` endpoint only validates the `id` URL parameter—not whether the authenticated session has *completed* 2FA verification. An attacker can intercept the 2FA prompt, navigate directly to a victim's account page by modifying the `id` parameter, and gain full access without ever entering a valid verification code. This represents a critical flaw in the authentication state machine: the application conflates "logged in" with "2FA verified," allowing attackers to bypass the second factor entirely.

## Reconnaissance

**Initial Observation:** Logged into a known account (weiner:peter) and observed the complete 2FA flow:
1. Username + password accepted
2. 2FA verification code sent via email
3. After entering code: redirected to `/my-account?id=weiner`

**Critical Insight:** The `id` parameter directly controls which account details are displayed. No additional validation occurred after 2FA entry.

**Testing Process:**
- Noted the account details URL pattern: `/my-account?id=weiner`
- Logged out completely
- Attempted login with victim credentials (carlos:montoya)
- At 2FA prompt (before entering code): manually navigated to `/my-account?id=carlos`
- Result: Full access to Carlos's account without entering a valid 2FA code

## Exploitation — Step by Step

### Step 1: Enumerate Account ID Parameters via Own Account
Logged into a known account and observed the URL structure on the account details page.

Request:
```
GET /my-account?id=weiner HTTP/1.1
Host: target.com
Cookie: [authenticated session cookie]
```

The application uses a predictable, sequential ID parameter to access account pages. The ID directly matches the username. No additional authorization checks are visible in the response headers or page structure.

### Step 2: Initiate Login with Victim Credentials
Logged out of the known account and initiated a fresh login with the victim's username and password (carlos:montoya).

Request:
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=carlos&password=montoya
```

Response:
```
HTTP/1.1 302 Found
Location: /login2
Set-Cookie: session=[session_token]; Path=/
```

The application accepted the credentials and created a session cookie, but redirected to `/login2` instead of granting direct access. This indicates the session is in an "authenticated but not 2FA-verified" state.

### Step 3: Bypass 2FA Check via Direct URL Navigation
Instead of waiting for or entering the 2FA verification code, I manually changed the URL in the browser's address bar from `/login2` to `/my-account?id=carlos`.

Request:
```
GET /my-account?id=carlos HTTP/1.1
Host: target.com
Cookie: session=[session_token from Step 2]
```

Response:
```
HTTP/1.1 200 OK
[Carlos's account details page loaded successfully]
```

The `/my-account` endpoint performed **zero authorization checks**. It only verified:
1. A session cookie exists (which was created after username + password)
2. The `id` parameter is present

It did **not** verify:
- Whether the session has completed 2FA verification
- Whether the session user ID matches the requested `id` parameter
- Whether 2FA completion was recorded in the session state

This is a **session state confusion** vulnerability—the app treats "has a session" as equivalent to "is fully authenticated," ignoring the intermediate 2FA step.

### Key Payload(s)

**Bypass URL (after session is created but before 2FA verification):**
```
GET /my-account?id=carlos HTTP/1.1
```

**Reconstructed Attack Flow:**
```
1. POST /login → username=carlos, password=montoya
   Response: 302 redirect to /login2, session cookie set

2. GET /my-account?id=carlos (skip /login2 entirely)
   Response: 200 OK, render Carlos's account details
   
3. Session state: { authenticated: true, 2fa_verified: false }
   Endpoint check: if (session.authenticated) { render account for id }
   ← Missing: if (!session.2fa_verified) { deny access }
```

### Tools Used
- Manual (Browser)
---

## The Fix

### Backend Validation (Critical)
```java
// Spring Boot Controller — Enforce 2FA verification before granting access

@GetMapping("/my-account")
public ResponseEntity<?> getMyAccount(
    @RequestParam String id,
    HttpSession session) {
    
    // 1. Verify session exists and user is authenticated
    String authenticatedUsername = (String) session.getAttribute("username");
    if (authenticatedUsername == null) {
        return ResponseEntity.status(401).body("Not authenticated");
    }
    
    // 2. **CRITICAL:** Verify 2FA has been completed
    Boolean twoFaVerified = (Boolean) session.getAttribute("2fa_verified");
    if (twoFaVerified == null || !twoFaVerified) {
        // Redirect to 2FA prompt, not to account page
        return ResponseEntity.status(302)
            .header("Location", "/login2")
            .build();
    }
    
    // 3. Enforce authorization: session user can only access their own account
    if (!authenticatedUsername.equals(id)) {
        return ResponseEntity.status(403).body("Access denied");
    }
    
    // 4. Proceed with fetching account details
    User user = userRepository.findByUsername(id);
    if (user == null) {
        return ResponseEntity.status(404).body("User not found");
    }
    
    return ResponseEntity.ok(user);
}
```

**Session State Management (after 2FA code verification):**
```java
@PostMapping("/login2")
public ResponseEntity<?> verify2FA(
    @RequestParam String code,
    HttpSession session) {
    
    // Retrieve username from session (set during login)
    String username = (String) session.getAttribute("username");
    if (username == null) {
        return ResponseEntity.status(401).body("Session expired");
    }
    
    // Verify the 2FA code
    boolean isValid = emailService.verify2FACode(username, code);
    if (!isValid) {
        return ResponseEntity.status(401).body("Invalid code");
    }
    
    // Mark session as 2FA-verified
    session.setAttribute("2fa_verified", true);
    session.setAttribute("2fa_verified_at", System.currentTimeMillis());
    
    // Redirect to account page
    return ResponseEntity.status(302)
        .header("Location", "/my-account?id=" + username)
        .build();
}
```

### Additional Mitigations:

**Principle of Least Privilege:**
- Create separate session attributes: `authenticated` (after password) and `2fa_verified` (after code)
- Always check both before granting access to sensitive endpoints

**URL Parameter Validation:**
- Never trust user-supplied IDs; always cross-reference with session identity
- Implement explicit whitelist checks: `if (!currentUser.canAccess(requestedId))`

**2FA Timeout:**
- Set an expiration on the "authenticated but not 2FA-verified" state
- Force re-authentication if 2FA is not completed within 5 minutes
- Example: `if (system.currentTime() - login_time > 5 minutes && !2fa_verified) { deny }`

**Audit Logging:**
- Log all failed 2FA attempts with timestamp and username
- Log access to `/my-account` endpoint with session state information
- Alert on suspicious patterns: successful login followed by immediate account access without 2FA

**Session Binding:**
- Regenerate session ID after 2FA completion to prevent session fixation attacks
- Store IP/User-Agent in session and validate on each request

---

## What I Found Interesting / Unexpected

The elegance of this vulnerability lies in its **implicit trust in URL parameters**. Most developers implement 2FA correctly at the protocol level—they verify codes, validate timing windows, handle replay attacks—but then leave the authorization layer broken.

This reveals a critical gap in the authentication state machine: **distinguishing between identity verification (2FA) and authorization (access control).** The developer likely thought:
- "Once the session exists, the user is authenticated"
- "The 2FA code is verified separately"

But they didn't think: "If 2FA hasn't been verified, can the user still access their account page?" 

This is a **timing-of-check-time-of-use (TOCTOU)** vulnerability in the application logic. The session is created (time of check), but by the time the `/my-account` endpoint executes (time of use), it doesn't re-verify that 2FA was completed.

---

## Real-World Relevance

**Okta Account Takeover (CVE-2023-28432):** Okta's authentication API allowed session tokens to be created before MFA verification was complete. Attackers exploited this by obtaining a session token (via credential stuffing or phishing) and accessing user data without completing the second factor. Impact: Unauthorized access to sensitive organizational data.

**GitHub 2FA Bypass (2013):** GitHub's account recovery flow created an authenticated session before requiring email verification, allowing attackers to reset passwords on accounts with incomplete 2FA. This led to high-profile account takeovers.

**OWASP Top 10 (2021):** Broken Access Control is listed as #1 most critical web application security risk. 2FA bypasses via authorization flaws consistently rank in the top disclosed vulnerabilities across HackerOne and bug bounty platforms.

---

## Connections to My Own Projects

**Subscription-Manager:** 

---

## Developer & AppSec Takeaway

> **Never assume a session cookie grants full access. Distinguish between authentication (proving who you are) and authorization (proving you're allowed to access this resource).** In multi-factor authentication flows, the session state must explicitly track which factors have been verified. Before granting access to any sensitive endpoint, verify: (1) a session exists, (2) all required authentication factors have been completed, and (3) the authenticated user is authorized for the requested resource. Test 2FA implementations by attempting to access protected resources *at each stage* of the authentication flow (before password, before 2FA code, after code)—if any stage grants unauthorized access, you have found a critical bypass.