# Lab: <Lab Name>

---

## 1. Vulnerability Overview

**Vulnerability Type:**  
**Context (if applicable):**  
**Affected Component:**  

This lab demonstrates a <vulnerability type> where user-controlled input is processed insecurely, allowing an attacker to <impact>.

---

## 2. Vulnerability Concept

### What Is This Vulnerability?

Provide a concise technical explanation:

- What does it allow an attacker to do?
- What assumption does the application incorrectly make?
- What trust boundary is violated?

---

### Why Does It Happen?

Explain the root cause:

- Missing output encoding?
- Unsafe query construction?
- Missing server-side authorization?
- Business logic flaw?
- Insecure deserialization?
- Improper validation?

Focus on *why*, not just *what*.

---

## 3. Attack Surface & Trust Boundary

**User-controlled input:**
- Query parameters
- Form fields
- Headers
- Cookies
- JSON body
- File uploads
- etc.

**Trust boundary broken:**

Explain where untrusted input crosses into trusted execution or rendering.

Example:
> The application embeds user input directly into the HTML response without context-aware encoding.

---

## 4. Exploitation Walkthrough

### Payload Used

```html
<payload_here>
```
### Explain why it works

## 5. Impact Analysis
Beyond proof-of-concept:
- What sensitive data could be exposed?
- Could this lead to account takeover?
- Would HttpOnly cookies reduce impact?
- Could this chain with CSRF?
- Is privilege escalation possible?
- Discuss realistic consequences.

## 6. Context awareness
If this is XSS:
- HTML body context?
- Attribute context?
- JavaScript context?
- URL context?

Explain why encoding requirements depend on output context.

If access control issue:
- Horizontal vs vertical escalation?
- IDOR?
- Business logic flaw?

## 7. Secure Fix
### Primary fix:
Explain the correct architectural fix.

Examples:
- Context-aware output encoding
- Parameterized queries
- Strict server-side authorization checks
- Allowlist validation
- Be explicit and precise.

### Defense-in-Depth
Additional mitigations:
- Content Security Policy (CSP)
- HttpOnly cookies
- SameSite configuration
- Secure headers
- Logging & monitoring
- Rate limiting

Clarify that these reduce impact but do not replace the primary fix.

## 8. Secure Code Example (If Applicable)

## 9. Developer Takeaway