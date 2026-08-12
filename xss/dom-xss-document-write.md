# Lab: DOM XSS in document.write sink using source location.search
## Lab Overview
**Platform**: PortSwigger Web Security Academy</br>
**Category**: Cross-Site Scripting (XSS)</br>
**Difficulty**: Apprentice </br>
**Vulnerability Type**: DOM XSS</br>
**Context**: HTML body context</br>
**Link**: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink

---

## 1. Vulnerability Overview

**Vulnerability Type:**  DOM XSS </br>
**Context:**  HTML body context </br>
**Affected Component:**  JavaScript that reads user-controlled data from `location.search` and writes it to the DOM using `document.write`</br>
**Source:** location.search</br>
**Sink**: document.write

This lab demonstrates a **DOM XSS** where user-controlled input is processed insecurely, allowing an attacker to **inject and execute arbitrary malicious JS code in the victim's browser**.

---

## 2. Vulnerability Concept

### What Is This Vulnerability?

- What does it allow an attacker to do?</br>
    The vulnerability allows the attacker to inject malicious HTML or JS into the page DOM. When the victim visits a crafted URL containing the payload, the browser executes the attacker-controlled script in context of the vulnerable app. This enables the attacker to:
    - Steal sensitive data 
    - Perform actions on behalf of the victim
    - Deface the website
- What assumption does the application incorrectly make?</br>
    The application assumes that it is safe to insert data from `location.search` directly without validation or encoding. Because `location.search` originates from the URL query string, it is fully controlled by the user. Writing this input directly to the DOM allows attackers to inject malicious markup or scripts.
- What trust boundary is violated?</br>
    The trust boundary was broken between:
    - Untrusted user input `location.search`
    - Client-side DOM rendering `document.write`

    The application treated external input as trusted data and embedded it directly into the DOM without applying context-aware encoding.

---

### Why Does It Happen?
The application reads the data directly from the query parameters using `location.search`. This is user-controlled input. The application directly inserts it into the DOM using `document.write` without any sanitization. `document.write` interprets the string passed to it as HTML markup (and may execute JavaScript embedded in it). 

Therefore, the attacker can craft a URL that takes advantage of this vulnerability and and inject an executable code into the page.

---

## 3. Attack Surface & Trust Boundary

**User-controlled input:**
- Query parameters

**Trust boundary broken:**</br>
The trust boundary is violated between:
- Untrusted user input `location.search`
- Client-side DOM rendering `document.write`

The application treated external input as trusted data and embedded it directly into the DOM without applying context-aware encoding.

---

## 4. Exploitation Walkthrough

### Payload Used

```html
"><svg onload=alert(1)>
```
**Why this works** </br>
`"` - closes the HTML attribute `<img src=`</br>
`>` - closes the `img` tag </br>
`<svg onload=alert(1)>` injects new HTML.</br>
`onload` - event handler executes JS when the element loads.

## 5. Impact Analysis
- **CSRF bypass:** malicious scripts can read CSRF tokens and perform authenticated actions.
- **Session hijacking:** if cookies are accessible to JavaScript.
- **Credential phishing:** by injecting fake login forms.
- **Sensitive data exfiltration:** extracting information from the DOM.
- **Privilege escalation:** if an administrator triggers the payload.

## 6. Context awareness
HTML context means that when a user input is reflected in a response, it reflected in the HTML body content of the page.

In this lab, the user-controlled input is reflected directly in the **HTML body** of the page. This is known as **HTML body context**, meaning the input is inserted into the page content itself rather than inside an attribute, script, or URL. Because the input is inserted into the HTML body without encoding or sanitization, the browser parses injected HTML elements, such as `<svg onload>`, as executable code, resulting in DOM XSS.</br>

If the input were placed inside:
- An HTML attribute → different encoding rules would apply.
- A JavaScript string → JavaScript escaping would be required.
- A URL → URL validation and scheme restrictions would be needed.

## 7. Secure Fix
### Primary fix:

- **Context-aware output encoding**: Encode user-controlled input before writing it to the DOM. Example:
    - `<` -> `&lt;`
    - `>` -> `&gt;`
- **Input Sanitization**: Validate or remove unexpected characters from the user input before processing it.

### Defense-in-Depth
- **Content Security Policy (CSP)**: </br>
    Using CSP: `script-src 'self'` will only allow scripts to be loaded that are from the **same** origin. Instead of directly whitelisitng domains, we can use nonces or hashes.

    1. CSP directive can specify nonces and then same value must be used in the tag that loads a script. Nonce must be generated securely at each page load and should be undeterministic.
    2. CSP directive can specify a hash of the content of the trusted script (eg. JS function). If the hash doesn't match the value specified in the directive then those functions/scripts will not get executed. 
- **HttpOnly cookies**</br>
    Prevent JavaScript from accessing session cookies, reducing the impact of XSS stealing session data. 
- **SameSite configuration**</br>
    Prevent cookies from being sent with cross-site requests, mitigating CSRF and some XSS attack chains.

## 8. Secure Code Example (If Applicable)
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="
    default-src 'self'; 
    script-src 'self'; 
    object-src 'none';
  ">
  <title>Secure Lab Example</title>
</head>
<body>
  <div id="output"></div>

  <script>
    // Get the query parameter safely
    const params = new URLSearchParams(window.location.search);
    const searchValue = params.get('search');

    // Context-aware encoding function
    function encodeHTML(str) {
      if (!str) return '';
      return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    // Insert safely into the DOM
    const safeValue = encodeHTML(searchValue);
    const outputDiv = document.getElementById('output');
    outputDiv.textContent = safeValue; // safe insertion without parsing HTML
  </script>
</body>
</html>
```

## 9. Developer Takeaway
- **Never trust user input**: Assume all data from the client can be malicious. Never insert untrusted input into the DOM without proper validation or encoding.
- **Use context-aware encoding**:
Output encoding must match the rendering context: HTML body, HTML attributes, JavaScript, or URLs all require different escaping.
- **Avoid dangerous DOM sinks**:
Functions like document.write(), innerHTML, and eval() execute HTML/JS directly. Prefer textContent or `safe DOM APIs.
- **Defense-in-depth matters**:
Even with proper encoding, adding CSP, HttpOnly cookies, and SameSite attributes reduces the impact if a vulnerability is missed.