# Authentication

## Vulnerabilities in password-based login
### Brute-force attacks
-  attacker uses a system of trial and error to guess valid user credentials.
- Websites that rely on password-based login as their sole method of authenticating users can be highly vulnerable if they do not implement sufficient brute-force protection.
- **Brute-forcing usernames:** 
    - During auditing, check whether the website discloses potential usernames publicly. 
    - You should also check HTTP responses to see if any email addresses are disclosed.
- **Brute-forcing passwords:**
    - Passwords can be brute-forced, with the difficulty varying based on the strength of the password. 
    - Many websites adopt some form of password policy, which forces users to create high-entropy passwords that are, theoretically at least, harder to crack using brute-force alone.
- **Username enumeration:**
    - Username enumeration is when an attacker is able to observe changes in the website's behavior in order to identify whether a given username is valid.
    - While attempting to brute-force a login page, you should pay particular attention to any differences in:
        - **Status code:** if the status code returned is changed when the guessed username is right but password is incorrect
        - **Error Messages:** Sometimes the returned error message is different depending on whether both the username AND password are incorrect or only the password was incorrect.
        - **Response times:** If most of the requests were handled with a similar response time, any that deviate from this suggest that something different was happening behind the scenes.
### Protecting against brute-force
1. Locking the account that the remote user is trying to access if they have too many failed login attempts
2. Blocking the remote user's IP address if they make too many login attempts in quick succession
### Account locking
 - **Account lockout** helps protect individual accounts from repeated password-guessing attempts.
- However, it does **not fully prevent attacks targeting many different accounts**.
- Attackers can use **password spraying**:
  - Identify a list of likely valid usernames.
  - Choose a **small number of common/likely passwords** that stays within the login-attempt limit.
  - Try each password against many different usernames rather than repeatedly attacking one account.
- This can bypass per-account lockout because **no individual account exceeds its failed-attempt threshold**.
- **Key takeaway:** Account lockouts are more effective against targeted brute force than against attacks distributed across many accounts.

### User rate limiting
- Too many login requests from the same IP results in IP address getting blocked.
- SOmetimes preferred over account login because it is less prone to username enumeration

### HTTP Basic Authentication
- The browser sends the username and password in the `Authorization` header as **Base64-encoded** data:
  ```
  Authorization: Basic base64(username:password)
  ```
- **Base64 is encoding, not encryption**, so the credentials can potentially be recovered.
- Credentials are sent with **every request**, increasing exposure.
- Without proper HTTPS/HSTS protections, credentials may be vulnerable to **man-in-the-middle attacks**.
- Basic Auth implementations may lack **brute-force protection**, making password guessing easier.
- It provides **no built-in CSRF protection**, so it can be vulnerable to session-related attacks.
- Even access to a seemingly unimportant page can be valuable because the exposed credentials may be **reused elsewhere**.

 **Key takeaway:** HTTP Basic Auth is simple but provides weak security unless combined with strong protections such as HTTPS, HSTS, and brute-force defenses.