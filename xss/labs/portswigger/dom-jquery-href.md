# Lab: DOM XSS in jQuery anchor href attribute sink using location.search source

---

## 1. Vulnerability Overview
**Link**: [DOM XSS in jQuery](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink)

**Vulnerability Type:**  DOM XSS

**Vulnerable Parameter**: `returnPath` query parameter

**Context (if applicable):**  
**Affected Component:**  Submit feedback page — breadcrumb "back" link

**Impact:** Session hijacking, credential theft, malware distribution, account takeover, and arbitrary actions performed on behalf of the victim.

---

## 2. Vulnerability Concept

### What Is This Vulnerability?

- What does it allow an attacker to do?
An attacker can inject arbitrary JavaScript code that executes in the victim's browser within the origin of the vulnerable application. Since the code executes in the same origin, it has access to sensitive data such as session cookies, localStorage, and can perform any action the victim is authorized to perform.

- What assumption does the application incorrectly make?
The application assumes that the value supplied to the returnPath query parameter is always a safe URL. It does not validate, sanitize, or encode the parameter before using it to set the href attribute of an HTML anchor element via jQuery. This violates the principle of input validation and output encoding.

- What trust boundary is violated?
The application fails to maintain the boundary between trusted application code and untrusted user input. It treats user-supplied query parameters as if they were trusted data, directly embedding them into the DOM without any filtering or encoding. This violates the security principle that all external input is potentially malicious.

### Why Does It Happen?

Root cause analysis:

- **Missing output encoding:** The application uses jQuery's `.attr()` method to set the `href` attribute with the unsanitized `returnPath` parameter. No context-aware encoding is applied.
- **Lack of input validation:** The application does not validate that `returnPath` contains only safe URL characters or that it starts with a relative path (e.g.,` /`).
- **Unsafe DOM Manipulation:** The developers relied on the assumption that browsers would only interpret `href` values as URLs—but browsers support the `javascript:` protocol, which allows arbitrary code execution.
- **Source-to-Sink Data Flow Not Sanitized:** The data flows directly from `location.search` (untrusted source) → jQuery selector → `.attr()` method (unsafe sink) without any sanitization between them.

---

## 3. Attack Surface & Trust Boundary

**User-controlled input:** The returnPath query parameter from location.search

**Attack Vector:** Crafting a malicious URL and tricking a user into clicking it (via phishing email, malicious post, etc.)

**Trust boundary broken:**
The application embeds user-supplied input directly into an HTML attribute without context-aware encoding. The boundary between untrusted input and the rendered DOM is not enforced.

**Where the vulnerability lives:** JavaScript code that executes when the page loads, specifically the jQuery selector that sets the href attribute.

---

## 4. Exploitation Walkthrough

### Reconnaissance

**Initial Observation:**

On the Submit Feedback page, the "back" button is a link whose href is dynamically set using the `returnPath` query parameter.

**Payload Testing:**

First, I tested a simple path: `?returnPath=/test`
Result: The href became `href="/test"` — confirming the parameter is reflected directly into the attribute.

**Breaking Out of the Context:**

I attempted to break out of the href attribute with quotation marks: `?returnPath="/malicious`

**Result:** Still treated as a URL. The browser did not parse this as an attribute break because the value is already within the **href** attribute context.

**Protocol Handler Discovery:**

The key insight: the href attribute can execute JavaScript using the `javascript:` protocol handler, which is a valid protocol in browsers (though deprecated and dangerous).

### Payload Used

```html
javascript:alert(document.cookie)
```

## 5. Exploitation Steps
Construct the malicious URL:
   ``` text
   /feedback?returnPath=javascript:alert(document.cookie)
   ```
Inject the payload into the page:
The query parameter `returnPath` is read by JavaScript and inserted into the DOM:
```html
<a href="javascript:alert(document.cookie)">back</a>
```
Trigger execution:
Clicking the "back" link executes the JavaScript code because the `javascript:` protocol tells the browser to interpret the rest as executable code, not a URL.


### Explain why it works
The `href` attribute accepts the `javascript: `protocol as a valid protocol handler. When a user clicks the link, the browser does not treat it as a navigation—instead, it executes the JavaScript code in the *same security context as the page*. No encoding, validation, or Content Security Policy was in place to prevent this.

Critically, the developer did not realize that:

- URL encoding (e.g., %3A for :) was not applied, so javascript: passes through unmodified
- HTML entity encoding (e.g., &#58; for :) would not prevent this either—it only works in HTML body/attribute content, not in protocol handlers
- The href attribute is a JavaScript execution sink when the protocol is javascript:, not just a safe URL container


### Reconstructed Injected Query
```javascript
// Original code (vulnerable)
var returnPath = new URLSearchParams(location.search).get('returnPath');
$('a.back-link').attr('href', returnPath); // Unsafe sink

// What the attacker's input becomes in the DOM
<a href="javascript:alert(document.cookie)">back</a>

// When clicked, this executes:
alert(document.cookie);
```

## 6. Impact Analysis
### What Sensitive Data Could Be Exposed?
- **Session Cookies:** If not marked `HttpOnly`, session identifiers can be stolen, enabling session hijacking.
- **Authentication Tokens:** Stored in localStorage or sessionStorage, enabling account takeover.
- **CSRF Tokens:** Extracted and used to bypass CSRF protections.
- **Personal Data:** Any sensitive information displayed on the page or accessible via subsequent API calls made in the victim's session.

### Could This Lead to Account Takeover?
Yes. If the attacker successfully steals a session cookie or authentication token, they can:
- Set the stolen session cookie in their own browser
- Access the victim's account without knowing their credentials
- Change the victim's password, email, or other critical information
- Perform unauthorized transactions or data theft

### Would HttpOnly Cookies Reduce Impact?
Partially. If session cookies are marked with the HttpOnly flag, document.cookie **cannot** access them via JavaScript. However:
- The attack could still steal other sensitive data (CSRF tokens in localStorage, API keys, PII visible on the page)
- The attacker could redirect to a malicious endpoint and perform CSRF attacks on behalf of the user
- The attack could inject a keylogger or form hijacker to capture credentials or payment information

Conclusion: HttpOnly is a critical mitigation, but not sufficient alone. Defense-in-depth is required.

### Could This Chain with CSRF?
Yes. The attacker could inject JavaScript that:
- Makes an authenticated API request to change the victim's email or password
- Transfers funds (if applicable)
- Exports private data

Since the code executes in the victim's browser with their credentials, CSRF protections (CSRF tokens) are often bypassed because the token is available to the injected script.

### Could This Lead to Privilege Escalation?
Not directly from this vulnerability alone. However, if an admin visits the malicious link, the attacker gains admin-level access. Additionally, the attacker could:
- Enumerate other users and their roles via API calls
- Exploit secondary vulnerabilities with admin access

### Is Privilege Escalation Possible?
If an administrator or user with elevated privileges visits the malicious link, the attacker inherits those privileges for the duration of the session.

### Realistic Consequences
- **Session Hijacking:** Attacker steals the session cookie and impersonates the user.
- **Account Takeover:** Attacker changes the victim's credentials and locks them out.
- **Data Theft:** Attacker exfiltrates sensitive user data (PII, financial records, confidential documents).
- **Website Defacement:** Attacker modifies the page content for all visitors.
- **Malware Distribution:** Attacker injects code to deliver malware or redirect to phishing pages.
- **Credential Harvesting:** Attacker displays a fake login form to capture credentials.
 - **Keylogging:** Attacker injects a script to capture all keyboard input.

## 7. Context awareness
### What context is this vulnerability in?
This vulnerability exists in two nested contexts:

- **URL Context (Primary):** The `returnPath` parameter is intended to be a URL path. In a URL context, special characters like #, ?, : have semantic meaning and are not HTML-encoded.
- **HTML Attribute Context (Secondary):** The URL is placed inside the href attribute of an HTML anchor tag. In attribute context, characters like quotes should be encoded to &quot;. However, this encoding alone is insufficient for the href attribute when the protocol is javascript:.

### Why context matters:

- **In HTML body text:** `javascript:` would need to be encoded to `&colon;` or `&#58;` to be safe.
- **In HTML attribute:** URL encoding or HTML entity encoding of the colon is not applied by the browser when the protocol handler is present.
- **In the href attribute:** The browser parses the protocol first (before applying any HTML attribute decoding), so javascript:alert(...) is interpreted as an executable protocol, not a safe URL string.

### Why standard encoding fails here:

URL encoding `(%3A)` of the colon would produce javascript%3Aalert(...), which the browser would treat as a literal string, not a protocol. However, the application never applies URL encoding. HTML entity encoding (&#58;) would produce javascript&#58;alert(...), which also prevents execution—but again, the application applies neither.

The core issue: No encoding of any kind is applied to the output.

## 8. Secure Fix
### Primary fix: Context-Aware Output Encoding

For an href attribute containing a URL, the safest approach is:

- Validate against a whitelist: Ensure the URL starts with /, ./, or ../ (relative paths only).
- Disallow dangerous protocols: Block javascript:, data:, vbscript:, and other executable protocols.
- Use a URL parsing library: Don't rely on string matching.

### Defense-in-Depth
### 1. Content Security Policy (CSP):
```http
   Content-Security-Policy: script-src 'self'; object-src 'none';
```
This prevents inline script execution, though javascript: protocol handlers in href attributes may still execute depending on the browser and CSP version.

### 2. HttpOnly Cookies:
```http
   Set-Cookie: sessionId=...; HttpOnly; Secure; SameSite=Strict
```
Prevents JavaScript from accessing session cookies, reducing (but not eliminating) the impact of XSS.

### 3. Input Validation (Server-Side): 
Never trust client-side validation. Validate on the server that returnPath is a relative URL:
```javascript
   if (!returnPath.match(/^\/[\w\-\.\/]*$/)) {
       throw new Error('Invalid return path');
   }
```

### 4. Output Encoding Library: 
Use a battle-tested encoding library (e.g., DOMPurify for sanitization, or OWASP Encoder):
```javascript
   const DOMPurify = require('dompurify');
   const safeUrl = DOMPurify.sanitize(returnPath, {ALLOWED_TAGS: [], ALLOWED_ATTR: []});
```

## 9. Secure Code Example (If Applicable)
1. PHP - Use `htmlentities`  to escape your input when inside an HTML context
```php
<?php echo htmlentities($input, ENT_QUOTES, 'UTF-8');?>
```
2. Javascript - You need to build your own custom encoder.
```js
function htmlEncode(str){
    return String(str).replace(/[^\w. ]/gi, function(c){
        return '&#'+c.charCodeAt(0)+';';
    });
}
```

3. Using CSP:
```text
default-src 'self'; script-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none';
```

## 10. Developer Takeaway

Never assume user input is safe, even when it's a URL. Apply a whitelist validation for all URL parameters, ensuring they are relative paths or match a strict pattern. For DOM manipulation in JavaScript, validate input before using it in sinks like href, src, or as JavaScript execution contexts. Always use a templating engine with automatic escaping, and never manually concatenate user input into the DOM. Implement Content Security Policy and mark session cookies as HttpOnly to reduce the impact of DOM XSS. Finally, test for DOM XSS specifically—automated scanners often miss DOM-based flaws that only occur at runtime.

## 11. What I Found Interesting / Unexpected

**Surprising element:** The `javascript:` protocol is a valid protocol handler in HTML href attributes, despite being deprecated. Browsers still execute it, and it's not widely understood that this makes the `href` attribute a JavaScript execution sink, not merely a URL container. Many developers assume URL encoding or HTML attribute escaping is sufficient protection—neither is adequate for protocol handler injection.

Broader implications: This highlights the gap between client-side developers' understanding of URL safety and security. A developer might feel confident saying "our input is a URL," when in fact untrusted URLs can execute arbitrary code in an href context. **The lesson: treat URL parameters like any other user input—validate and whitelist ruthlessly.**