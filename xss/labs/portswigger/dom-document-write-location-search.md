# Lab: Lab: DOM XSS in document.write sink using source location.search

## 1. Vulnerability Overview
**Link**: [Link](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink)

**Vulnerability Type:**  DOM XSS

**Vulnerable Parameter:** search query parameter

**Affected Component:**  Search query tracking functionality on the home page

**Impact:** Arbitrary JavaScript execution, session hijacking, credential theft, malware distribution, and unauthorized actions performed on behalf of the victim.
---

## 2. Vulnerability Concept

### What does it allow an attacker to do?
An attacker can inject arbitrary JavaScript code that executes in the victim's browser within the origin of the vulnerable application. Since the injected code executes with the same privileges as the legitimate application code, it can access sensitive session data, perform actions on behalf of the user, and redirect to phishing pages.

### What assumption does the application incorrectly make?
The application assumes that the value supplied in the search query parameter is safe to write directly into the HTML document using document.write(). It does not sanitize, validate, or encode the parameter before using it. Critically, the developers did not recognize that document.write() is a dangerous sink that treats its input as raw HTML, allowing tag injection.

### What trust boundary is violated?
The application fails to maintain the boundary between untrusted user input (the search query parameter) and trusted application code (the JavaScript that manipulates the DOM). The developers treat user-supplied input as if it were safe to embed directly into the HTML markup, violating the principle that all external input is potentially malicious.

### Why Does It Happen?

Root Cause Analysis:

- **Use of Dangerous Sink:** The application uses `document.write()`, which is inherently dangerous because it writes raw HTML directly to the document. Unlike safer DOM manipulation methods like textContent or innerText, document.write() interprets all HTML tags and attributes.
- **No Input Validation:** The search parameter is not validated to ensure it contains only safe characters or patterns.
- **No Output Encoding:** The application does not encode the parameter before passing it to `document.write().` HTML entity encoding (e.g., &quot; for ") would prevent tag injection, but it is not applied.
- **Source-to-Sink Data Flow Not Sanitized:** Data flows directly from `location.search` (untrusted source) → JavaScript parameter extraction → `document.write()` (unsafe sink) without any filtering or encoding.
- **Placement Within HTML Attribute:** The vulnerable code writes the search parameter inside an `img src` attribute (e.g., `<img src="[search_parameter]">`). This means the attacker must break out of the attribute context first using `">` before injecting new tags.

---

## 3. Attack Surface & Trust Boundary

**User-Controlled Input:** The `search` query parameter from the URL query string (`location.search`)

**Attack Vector:** Crafting a malicious URL with a crafted search parameter and tricking a user into visiting it (via phishing email, malicious link, etc.)

**Trust Boundary Broken:** The application treats user-supplied input as safe HTML markup and writes it directly to the document using `document.write()` without any encoding or validation. The boundary between untrusted input and the rendered DOM is not enforced.

**Where the Vulnerability Lives:** JavaScript code that executes during page load, specifically the code that reads `location.search` and passes the parameter to `document.write()`.

---

## 4. Exploitation Walkthrough

### Reconnaissance

**Initial Observation:**
On the search page, a search box accepts user input and displays it dynamically. To understand where the input is reflected, I inspected the page source and found that the `search` parameter is used in a `document.write()` call:
```javascript
document.write('<img src="' + getQueryParameter('search') + '">');
```
**Testing Parameter Reflection:**
I searched for a random string like *test123*. Inspecting the HTML, I observed:

```html
<img src="test123">
```
This confirmed that the search parameter is reflected directly into the `src` attribute of an img tag without any encoding.

**Recognizing the Attribute Context:**
Since the value is inside an HTML attribute, I attempted to break out using a double quote and greater-than symbol: `">`
When I searched for test">, the HTML became:

```html
<img src="test">">[unparsed content]
```
This confirmed I could escape the src attribute.

**Discovering the Execution Method:**
Now that I could break out of the attribute and inject new HTML tags, I tested injecting an SVG element with an onload event handler:
```text
"><svg onload=alert(1)>
```

This payload:

- Breaks out of the `src` attribute with `">`
- Closes the `img` tag implicitly
- Injects an SVG element: `<svg onload=alert(1)>`
- The SVG element has an `onload` event handler that executes `alert(1)` when the SVG loads

### Payload Used
```html
"><svg onload=alert(1)>
```
Or for stealing cookies:

```html
"><svg onload=alert(document.cookie)>
```

### Why This Works

**Step-by-step breakdown:**

- **Attribute Breaking:** The double quote `"` closes the `src` attribute value
- **Tag Closing:** The greater-than symbol > closes the `<img>` tag
- **New Tag Injection:** The attacker then injects a new `<svg> `tag
- **Event Handler Execution:** The `onload` event handler is triggered when the `SVG` element is rendered, executing the JavaScript code `alert(1)`

### Why document.write() is vulnerable:

- `document.write()` treats its input as *raw HTML markup*, not as plain text
- No encoding or sanitization is applied
- It allows injection of new HTML tags and event handlers
- Unlike textContent (which would render the payload as plain text) or innerText, document.write() interprets all HTML syntax

### Why this payload specifically works:

- `SVG elements` support event handlers like `onload`, `onmouseover`, `onclick`
- These event handlers execute JavaScript immediately without user interaction (or upon user interaction)
- The `onload` handler is triggered as soon as the SVG element is added to the DOM

### Reconstructed Injected HTML
```javascript
// Vulnerable code (original)
var searchParam = new URLSearchParams(location.search).get('search');
document.write('<img src="' + searchParam + '">');

// With attacker's payload: "><svg onload=alert(1)>
// The resulting HTML becomes:
<img src=""><svg onload=alert(1)>">

// Which the browser parses as:
<img src="">           <!-- img tag with empty src -->
<svg onload="alert(1)"> <!-- SVG element with onload handler -->
">                     <!-- Unparsed text (ignored by browser) -->

// When rendered, the onload handler executes:
alert(1);
```

## 5. Impact Analysis
### What Sensitive Data Could Be Exposed?
- **Session Cookies:** If not marked `HttpOnly`, session identifiers can be stolen via `document.cookie`, enabling session hijacking
- **CSRF Tokens:** Tokens stored in the DOM or in non-HttpOnly cookies can be extracted and used to bypass CSRF protections
- **Local Storage & Session Storage:** API keys, authentication tokens, and user data stored in browser storage can be accessed
- **Form Data:** The injected code can intercept or exfiltrate data from forms before submission
- **Personal Information:** Any PII displayed on the page (email, name, account details) is accessible to the attacker's code

### Could This Lead to Account Takeover?

Yes, absolutely. The attacker can:

- **Steal Session Tokens:** Extract the session cookie (if not HttpOnly) and reuse it in their own browser to impersonate the user
- **Capture Credentials:** Inject a fake login form or keylogger to capture the user's password
- **Change Account Settings:** Perform authenticated API calls to change the user's email, password, or recovery options
- **Access Private Data:** Exfiltrate sensitive information from the user's account

The severity of account takeover depends on the sensitivity of the application. For financial, healthcare, or enterprise applications, this is a critical vulnerability.

### Would HttpOnly Cookies Reduce Impact?

Partially, yes. If session cookies are marked with the `HttpOnly` flag:

- JavaScript cannot directly access `document.cookie`, preventing direct session token theft
- However, the XSS vulnerability still allows:
    - **CSRF attacks:** The attacker can make authenticated requests on behalf of the victim (the browser automatically sends cookies)
    - **Credential harvesting:** Display fake login forms to capture passwords
    - **Malware injection:** Redirect to malicious sites or inject banking trojans
    - **Exfiltration of non-cookie data:** Steal CSRF tokens, API keys, or sensitive information stored in localStorage
    - **Keylogging:** Capture keystrokes to obtain passwords

Conclusion: HttpOnly is a critical mitigation that significantly reduces (but does not eliminate) the impact of XSS. It is not sufficient alone.

### Could This Chain with CSRF?

Yes, this is a powerful combination. The injected code executes in the victim's browser with their credentials, making CSRF protections ineffective. The attacker can:

- Make authenticated state-changing requests (POST, PUT, DELETE) using fetch() or XMLHttpRequest
- Bypass CSRF tokens by reading them from the DOM and including them in the request
- Perform sensitive operations like transferring funds, changing passwords, or deleting accounts

Example:

```javascript
// Attacker's injected code
const csrfToken = document.querySelector('input[name="csrf"]').value;
fetch('/api/change-email', {
    method: 'POST',
    credentials: 'include',  // Include session cookies
    headers: {
        'X-CSRF-Token': csrfToken,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ newEmail: 'attacker@evil.com' })
});
```
### Is Privilege Escalation Possible?

Not through this vulnerability directly. However, if an admin or privileged user visits the malicious link, the attacker inherits admin-level access for that session. Additionally, the attacker could:

- Enumerate other users and their roles via API calls
- Exploit secondary vulnerabilities with elevated access
- Modify application data to escalate other users' privileges (if the API allows)

### Realistic Consequences
- **Session Hijacking:** Attacker steals the session cookie (if `HttpOnly` is not set) and impersonates the user
- **Account Takeover:** Attacker changes the victim's password and locks them out
- **Data Theft:** Attacker exfiltrates sensitive PII, financial records, or confidential documents
- **Fraudulent Transactions:** Attacker performs unauthorized transactions (purchases, transfers, etc.)
- **Malware Distribution:** Attacker injects code to deliver ransomware, spyware, or banking trojans
- **Website Defacement:** Attacker modifies the page for all visitors, damaging the brand's reputation
- **Credential Harvesting:** Attacker displays a fake login form to harvest credentials
- **Keylogging:** Attacker records all keyboard input to capture passwords and sensitive data
- **Supply Chain Attack:** If the vulnerable app is an internal tool, the attacker could compromise multiple employees

## 6. Context awareness
### What context is this vulnerability in?

This vulnerability exists in two nested HTML contexts:

- **HTML Attribute Context (Primary):** The search parameter is written inside the `src` attribute of an `img` tag. In this context:
    - Special characters like `"` have meaning (closing the attribute)
    - Characters like `>` close the tag
    - HTML encoding alone is insufficient; attribute breaking is possible
- **HTML Body Context (Secondary):** After breaking out of the attribute, the attacker injects new tags into the HTML body. In this context:
    - HTML tags like `<svg>`, `<img>`, `<iframe>` are interpreted
    - Event handlers like `onload`, `onerror`, `onmouseover` are executed
    - HTML entity encoding (e.g., `&lt;` for `<`) would prevent tag injection

### Why context matters:

- **HTML Attribute Encoding:** If the developer had applied `htmlspecialchars($search, ENT_QUOTES)` (in PHP), it would convert `"` to `&quot;` and `< `to `&lt;`, preventing attribute breakout.
- **HTML Body Encoding:** Simply escaping special characters in the attribute context (e.g., &quot;) might prevent attribute breakout but would not prevent tag injection in the body context.
- **Multi-layered Context:** Because this vulnerability spans two contexts (attribute and body), the attacker uses a two-step payload:
    1. Break out of the attribute: `">`
    2. Inject a new tag: `<svg onload=alert(1)>`

### Why standard encoding fails (partially):

If only HTML attribute encoding were applied:

```javascript
// Vulnerable: Only attribute encoding, no entity encoding
document.write('<img src="' + htmlspecialchars($search, ENT_QUOTES) + '">');

// Payload: "><svg onload=alert(1)>
// After attribute encoding becomes: &quot;&gt;&lt;svg onload=alert(1)&gt;
// Result: <img src="&quot;&gt;&lt;svg onload=alert(1)&gt;">
// Browser renders as plain text: "&gt;<svg onload=alert(1)>"
// No execution (safe)
```
But if no encoding is applied (the current case):

```javascript
// Vulnerable: No encoding
document.write('<img src="' + $search + '">');

// Payload: "><svg onload=alert(1)>
// Result: <img src=""><svg onload=alert(1)>">
// Browser interprets as:
// <img src="">           <!-- img tag, closes properly -->
// <svg onload="alert(1)"> <!-- SVG tag with onload, EXECUTES -->
// Execution occurs (vulnerable)
```

## 7. Secure Fix
### Primary fix: Avoid document.write() and Use Safe DOM Methods

The most direct fix is to never use `document.write()` for user-controlled data. Instead, use safe DOM manipulation methods that treat input as plain text by default.

**Recommended Approach: Use textContent or innerText**
```javascript
// VULNERABLE - document.write()
var searchParam = new URLSearchParams(location.search).get('search');
document.write('<img src="' + searchParam + '">');

// SECURE - Use safe DOM methods
var searchParam = new URLSearchParams(location.search).get('search');

// Option 1: Use textContent (treats input as plain text)
var img = document.createElement('img');
img.src = '';  // Set to empty or a default image
img.alt = searchParam;  // Use textContent for display, not src
document.getElementById('search-results').textContent = searchParam;

// Option 2: Use innerHTML with validation and encoding
var container = document.getElementById('search-results');
container.innerHTML = ''; // Clear
var img = document.createElement('img');
img.src = 'default.png';
var textNode = document.createTextNode(searchParam);
container.appendChild(img);
container.appendChild(textNode);

// Option 3: Use DOMPurify for sanitization (if HTML is required)
var sanitized = DOMPurify.sanitize(searchParam, {ALLOWED_TAGS: [], ALLOWED_ATTR: []});
container.innerHTML = '<p>' + sanitized + '</p>';
```

**Alternative Fix: Proper Output Encoding**

If you must use `document.write()` (legacy code), apply HTML entity encoding:

```javascript
// SECURE - HTML entity encoding
function htmlEncode(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

var searchParam = new URLSearchParams(location.search).get('search');
document.write('<img src="' + htmlEncode(searchParam) + '">');
```
This converts:

`<` -> `&lt;`

`>` -> `&gt;`

`"`-> `&quot;`

`&` -> `&amp`;

### Preventing tag injection.

### Defense-in-Depth Mitigations
**1. Content Security Policy (CSP):**
```http
   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
```
Prevents inline script execution and restricts script sources. However, CSP cannot prevent all XSS variants, especially event handler injection in attributes.

**2. HttpOnly Cookies:**
```http
   Set-Cookie: sessionId=...; HttpOnly; Secure; SameSite=Strict
```
Prevents JavaScript from accessing session cookies, reducing the impact of XSS.

**3. Input Validation (Server-Side):** Validate the search parameter on the server to ensure it contains only expected characters:
```javascript
   if (!searchParam.match(/^[a-zA-Z0-9\s\-]{0,100}$/)) {
       throw new Error('Invalid search parameter');
   }
```

**4. Use a Template Engine with Auto-Escaping:** Most modern template engines (Handlebars, EJS, Pug) auto-escape output by default:
```handlebars
   <!-- In Handlebars: {{{ }}} for HTML, {{ }} for plain text -->
   <p>{{searchParam}}</p>  <!-- Auto-escaped -->
```

## 8. Secure Code Example
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

## 9. Developer Takeaway

Never use `document.write()` with user-controlled data—it treats input as raw HTML, making it one of the most dangerous DOM manipulation methods. Always prefer safe alternatives like `textContent`, `innerText`, or `createElement()`, which treat input as plain text by default. If you must output user input in HTML, apply **context-aware** encoding: HTML entity encoding for HTML body context, URL encoding for URL context, and JavaScript string escaping for JavaScript context. **Remember that encoding is not the primary fix—using safe DOM methods is. Finally, implement CSP with script-src 'self' and mark session cookies as HttpOnly to reduce the impact of any XSS that slips through.**

## 10 What I Found Interesting / Unexpected

**Surprising element:** The danger of `document.write()` is often underestimated because developers conflate it with `innerHTML`. While both are dangerous with untrusted input, `document.write()` is arguably more dangerous because it's older, less commonly used, and therefore less likely to be scrutinized in code reviews. Many security-minded developers focus on preventing `innerHTML` vulnerabilities but overlook `document.write()`.

**What I'd do differently:** I would have immediately searched the page source for dangerous DOM manipulation methods like `document.write()`, `innerHTML`, and `eval()` before testing the search parameter. This would have accelerated identification of the vulnerability and revealed the exact injection point.

**Broader implications:** This highlights the importance of legacy code review. Applications built with older JavaScript practices often use dangerous methods that newer developers don't recognize as threats. Security training should emphasize that older code is not safer code—it often contains more vulnerabilities.