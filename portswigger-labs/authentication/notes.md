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