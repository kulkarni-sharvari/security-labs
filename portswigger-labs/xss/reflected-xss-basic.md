# Lab Write-Up: Reflected XSS into HTML Context (Nothing Encoded)
## Lab Overview
**Platform**: PortSwigger Web Security Academy</br>
**Category**: Cross-Site Scripting (XSS)</br>
**Difficulty**: Apprentice </br>
**Vulnerability Type**: Reflected XSS</br>
**Context**: HTML body context (no output encoding)</br>
**Link**: https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded

## 1. Vulnerability Overview
This lab demonstrates a Reflected Cross-Site Scripting (XSS) vulnerability where user input is reflected directly into the HTML response without validation or encoding.

Because the input is inserted into the HTML body as raw markup, the browser interprets injected `<script>` tags as executable JavaScript.

## 2. Vulnerability Concept
### XSS Attack:
XSS is a client-side injection where an attacker can inject malicious browser-side malicious code, usually written in JS. The browser trusts this code because it originates from a legitimate domain,  allowing the attacker to 
- steal session token
- perform unauthorized actions on the victim’s behalf.

### Prevention:
  1. Use context-aware output encoding. Since this lab is an HTML-context attack, we use <a id="output-encoding" output-encoding>HTML encoding</a>.
  2. Apply input validation.
  3. Use appropriate HTTP headers. Example `Content-Type` and `x-content-type-options: nosniff`.
  4. Implement a strict Content Security Policy (CSP) as defense-in-depth.

### Reflected-XSS Attack:
In reflected XSS, user-controlled input from an HTTP request is immediately reflected in the HTTP response without proper validation or encoding.</br>
The attacker crafts a malicious URL containing JavaScript as part of the request. When the victim clicks the link, the server reflects the input directly in the response, and the browser executes it.

## 3. Attack Surface & Trust Boundary
### Where was the trust broken?
The trust boundary was broken between:
- Untrusted user input (HTTP request parameters)
- Server-rendered HTML response

The application treated external input as trusted data and embedded it directly into the HTML response without applying context-aware encoding.

### How is the lab vulnerable?
The vulnerability exists in the search functionality.

When a user enters a search term, the application displays:
    
    "You searched for 'search-string'"
The problem:
1. The input is not sanitized or validated.
2. The output is not HTML-encoded before being inserted into the HTML response
3. The browser interprets injected HTML/JS as active content </br>
Because the input is reflected directly inside the HTML body without encoding, arbitrary `<script>` tags are executed.

## 4. Exploitation Walkthrough
1. In the searchbox type
    
    ```html 
    <script>alert(1)</script>
    ```
2. The application reflects the input into the response.
3. The browser parses the `<script>` tag and executes it.
4. The alert confirms arbitrary JavaScript execution.

This works because special characters such as < and > are not encoded before rendering.

## 5. Impact Analysis
It can be used for:
  1. Impersonate the user
  2. Carry out action that user can perform
  3. Steal user credentials
  4. Read the data that the user can
  5. Perform defacement of the website
  6. Inject trojan functionality
  
  The actual impact depends on:
1. Whether cookies use `HttpOnly`
2. Whether `SameSite` is configured
3. Whether CSRF protections exist
4. Whether sensitive APIs are accessible via JavaScript

## 6. Context awareness
HTML context means that when a user input is reflected in a response, it appears somewhere inside the HTML document.</br>
In this lab, the input is directly placed inside the **HTML body**. Because of this, the browser parses `<script>` tags as executable code.</br>
If the input were placed inside:
- An HTML attribute → different encoding rules would apply.
- A JavaScript string → JavaScript escaping would be required.
- A URL → URL validation and scheme restrictions would be needed.

## 7. Secure Fix
1. [Output encoding](#output-encoding): Since the vulnerability occurs in an HTML body context, the application must HTML encode. Eg: 
    - < -> &lt;
    - > -> &gt;

    This ensures the browser treats input as text rather than executable code</br>
    React and many other modern frameworks handle these automatically.
2. Ensure you sanitize the user input. You can't trust that the user will not provide malicious code or invalid input. Therefore, if you are using ReactJS then you can use libraries like DOMPurify to sanitize the input.
3. Avoid using `dangerouslySetInnerHTML`.
4. Using CSP: `script-src 'self'` will only allow scripts to be loaded that are from the **same** origin. Instead of directly whitelisitng domains, we can use nonces or hashes.

    1. CSP directive can specify nonces and then same value must be used in the tag that loads a script. Nonce must be generated securely at each page load and should be undeterministic.
    2. CSP directive can specify a hash of the content of the trusted script (eg. JS function). If the hash doesn't match the value specified in the directive then those functions/scripts will not get executed. 
5. Set Cookies as HttpOnly
6. Enable X-Content-Type-Options: nosniff.
7. avoid inline JS.

## 9. Developer Takeaway
If I were implementing this search feature in a production application:
 - I would use a templating engine that automatically encodes output.
- I would never concatenate raw user input into HTML strings.
- I would enforce CSP with nonces.
- I would ensure session cookies are marked HttpOnly.

This vulnerability highlights how important it is to treat all external input as untrusted and apply context-aware encoding at output.