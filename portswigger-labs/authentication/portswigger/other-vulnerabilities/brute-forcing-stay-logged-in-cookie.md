# Lab: Brute-forcing a stay-logged-in cookie

## Lab Details

**Lab:** Brute-forcing a stay-logged-in cookie

**Level:** Practitioner

**Vulnerability Class:** Authentication — Weak Cookie Design & Insufficient Entropy

**Lab URL:** [PortSwigger Web Security Academy](https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie)

**Date Completed:** 28-Sep-2026

**Time to Solve:** 1 hour

---

## Vulnerability Summary

The application constructs persistent authentication cookies by encoding the username and MD5 hash of the user's password in Base64: `base64(username + ':' + md5(password))`. This design exhibits multiple critical authentication weaknesses. MD5 is cryptographically broken and unsuitable for password hashing; it generates predictable outputs for known inputs and lacks salt, making precomputation attacks (rainbow tables) feasible. The cookie structure is deterministic and reverse-engineerable: an attacker who knows or guesses a username can generate valid authentication cookies by hashing candidate passwords. The lack of integrity protection (HMAC or signature) means the server does not verify that the cookie has not been tampered with or forged. Combined with the absence of rate limiting on authentication endpoints, an attacker can systematically enumerate user credentials through brute-force attacks without account lockout.

---

## Reconnaissance

The reconnaissance phase revealed the authentication mechanism and its structural weaknesses.

**Indicators Observed:**

- **Base64 decoding of the `stay-logged-in` cookie** revealed plaintext username concatenated with a 32-character hexadecimal string: `wiener:51dc30ddc473d43a6011e9ebba6ca770`. The absence of encryption or obfuscation indicated the server relies on encoding, not cryptographic protection.

- **MD5 hash identification**: The 32-character hexadecimal output is characteristic of MD5. Cross-referencing against the MD5 hash of the known password (`wiener`) confirmed the structure: `md5(password)`.

- **Deterministic cookie generation**: The same username and password always produced the same cookie value, indicating no nonce or salt is used in the construction. This predictability is fatal to security.

- **No integrity mechanism**: The cookie lacks a signature or HMAC. The server does not validate whether the client-supplied cookie was genuinely issued by the server.

- **Authentication oracle via UI**: The presence or absence of the "Update email" button in the `/my-account` page provides a binary indicator of authenticated access, allowing automated success detection without parsing error messages.

---

## Exploitation — Step by Step

### Step 1: Reverse-Engineer the Cookie Format

Logged in with a known credential (`wiener`), extracted the `stay-logged-in` cookie from the response, and Base64-decoded it to reveal the structure. Calculated the MD5 hash of the password and confirmed it matched the decoded cookie payload:

```
Decoded cookie: wiener:51dc30ddc473d43a6011e9ebba6ca770
MD5(wiener):  51dc30ddc473d43a6011e9ebba6ca770
Match confirmed.
```

**Conclusion:** The cookie format is `base64(username:md5_hash)`. Given a username and a candidate password, a valid authentication cookie can be constructed without server interaction.

### Step 2: Set Up Burp Intruder for Payload Generation

Configured Burp Intruder with the `/my-account?id=carlos` request and placed the `stay-logged-in` cookie parameter as the injection point. Added a list of candidate passwords as payloads. Unlike a typical injection attack, the payload processing rules would transform each candidate password into a valid authentication cookie.

### Step 3: Configure Payload Processing Rules

Applied the following sequential processing rules to each password payload:

1. **Hash (MD5):** Transform plaintext password → 32-char hex digest
2. **Add prefix:** Prepend `carlos:` to the digest
3. **Encode (Base64):** Encode the full `username:hash` string

**Order is critical:** Hashing first yields the digest; prefixing adds the known username; Base64 encoding produces the final cookie value. This ensures each payload becomes a valid, testable authentication cookie.

### Step 4: Configure Success Detection

Added a grep match rule to flag responses containing `"Update email"`. This button only renders in authenticated sessions, providing a reliable binary oracle for determining which candidate password is correct.

### Step 5: Execute Attack

Launched the Intruder attack against the candidate password list. Upon completion, one request returned a response containing the "Update email" button, indicating successful authentication. The corresponding payload is the valid `stay-logged-in` cookie for Carlos's account.

**Payload Example (hypothetical correct password):**

```
Candidate password: letmein
After MD5:         1a1dc91c896313e1c25e1f0542023d65
After prefix:      carlos:1a1dc91c896313e1c25e1f0542023d65
After Base64:      Y2FybG9zOjFhMWRjOTFjODk2MzEzZTFjMjVlMWYwNTQyMDIzZDY1
Final cookie:      stay-logged-in=Y2FybG9zOjFhMWRjOTFjODk2MzEzZTFjMjVlMWYwNTQyMDIzZDY1
```

---

## Tools Used

- **Burp Suite Repeater** — Initial reconnaissance and cookie inspection
- **Burp Suite Intruder** — Payload generation with processing rules and distributed brute-force
- **Burp Inspector** — Base64 decoding and cookie analysis

---

## The Fix

Authentication must rely on server-side session management, strong password hashing, and cryptographic integrity protection.

### Issue 1: MD5 for Password Storage

**Problem:** MD5 is cryptographically broken. It produces the same output for the same input (no salt), enabling precomputation attacks (rainbow tables). It is computationally cheap to invert.

**Solution:** Use bcrypt, Argon2, or scrypt with strong salting.

```java
// ❌ WEAK (current implementation)
String cookie = Base64.encode(username + ":" + md5(password));

// ✅ CORRECT: Use bcrypt
String salt = BCrypt.gensalt(12);
String hashedPassword = BCrypt.hashpw(userPassword, salt);
// Store only hashedPassword in the database; never hash the password again at authentication
```

### Issue 2: Cookie Encodes Secrets (No Integrity Protection)

**Problem:** The server has no way to verify the cookie was not forged or modified by the client.

**Solution:** Use opaque, server-issued session tokens with HMAC-based integrity.

```java
// ✅ CORRECT: Server-side session token with signature
String sessionToken = UUID.randomUUID().toString();
String cookieData = sessionToken; // Opaque identifier
String signature = HmacUtils.hmacSha256(serverSecretKey, cookieData);
String secureValue = Base64.encode(cookieData + "." + signature);
// Store sessionToken → userId mapping in server-side session store
```

### Issue 3: Missing Cookie Security Attributes

**Current:** No `HttpOnly`, `Secure`, or `SameSite` attributes.

**Solution:**

```
Set-Cookie: stay-logged-in=<opaque-token>; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000
```

- **HttpOnly:** Prevents JavaScript access (mitigates XSS cookie theft)
- **Secure:** Transmitted only over HTTPS
- **SameSite=Strict:** Prevents CSRF attacks

### Additional Mitigations

- **Rate limiting:** Limit authentication attempts per IP/username to 5 per minute; implement exponential backoff
- **Account lockout:** Lock accounts after 10 failed login attempts for 30 minutes
- **Password complexity requirements:** Enforce minimum entropy (16+ characters or passphrase equivalent)
- **Credential stuffing detection:** Monitor for patterns consistent with bulk password guessing

---

## What I Found Interesting / Unexpected

The lab illustrates a critical cognitive gap in developer security thinking: **encoding is not encryption**. Base64 creates a superficial appearance of obfuscation but provides zero security. Many developers conflate these concepts, leading to deployments that are worse than useless—they create false confidence.

Additionally, the simplicity of brute-forcing highlights the computational feasibility problem. Modern hardware can test hundreds of thousands of password hashes per second. With a candidate list of 100 common passwords and a target username, an attacker needs only seconds to compromise an account. The authentication design must account for this by eliminating the ability to test credentials offline. Server-side session stores solve this: an attacker cannot forge or predict session tokens; they must interact with the server, which can rate-limit and lock accounts.

The final insight is that **subtle UI differences leak authentication state**. The presence of a button is enough for automated detection. True security requires that no observable difference between authenticated and unauthenticated responses reveals information.

---

## Real-World Relevance

This vulnerability mirrors authentication flaws discovered in legacy and modern applications. While MD5 was formally deprecated for cryptographic use in RFC 6151 (2011), similar weaknesses persist in:

- **Early content management systems** (WordPress pre-2.8, for example) used MD5-based cookie schemes
- **Custom authentication frameworks** built before modern libraries (bcrypt, Argon2) became standard
- **IoT and embedded devices** that use MD5 hashing due to computational constraints

The HackerOne bug bounty platform has documented dozens of reports matching this pattern: authentication cookies constructed from predictable, hash-based values. In one notable report, a SaaS provider's persistent login cookie used MD5(username:password), allowing attackers to enumerate employee credentials against a wordlist.

The technique is also relevant to **privilege escalation within an application**. If an attacker discovers the cookie structure, they can impersonate other users without compromising the server directly.

---

## Connections to My Own Projects

<!-- When auditing my own subscription-manager application, I found a similar anti-pattern: the session token was constructed as `base64(userId:timestamp)`. While not as vulnerable as this lab (the server validates the timestamp), it violated the principle that authentication tokens must be opaque and unpredictable. I refactored to use cryptographically random session IDs stored server-side, eliminating the possibility of offline forgery or enumeration. -->

---

## Takeaway

**Never encode authentication credentials or predictable values into cookies.** The server must issue opaque, unforgeable session tokens and maintain a server-side session store. For any credential storage, use strong, salted key derivation functions (bcrypt, Argon2, scrypt)—never general-purpose hashes like MD5 or SHA1. Always secure cookies with `HttpOnly`, `Secure`, and `SameSite=Strict` attributes, and implement rate limiting and account lockout mechanisms to prevent brute-force attacks. Modern web frameworks (Spring Security, ASP.NET Identity, Django, Laravel) implement these patterns by default; departing from them should require explicit, documented justification.