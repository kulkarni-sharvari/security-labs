# Vulnerabilities in other authentication mechanisms

## Keeping users logged in
- Developers create a persistent cookie to allow "Remember Me" feature.
- This cookie needs to be unique and unguessable. It can't be a combination of static values like - username and timestamp.
- Ways to protect the cookie
    - Ensure strong encryption algorithm is used to encrypt the cookie
    - don't use simple two-way encoding like Base64.
    - Use hashing with salt.

## Resetting user passwords
- sending users their current password should never be possible if a website handles passwords securely in the first place
- sending persistent passwords over insecure channels is to be avoided
    - the security relies on either the generated password expiring after a very short period
    - user changing their password again immediately
    - Otherwise, this approach is highly susceptible to man-in-the-middle attacks.

### Resetting passwords using a URL
- A more robust method of resetting passwords is to send a unique URL to users that takes them to a password reset page
- Less secure implementations of this method use a URL with an easily guessable parameter to identify which account is being reset
- A better implementation of this process is to generate a high-entropy, hard-to-guess token and create the reset URL based on that. In the best case scenario, this URL should provide no hints about which user's password is being reset.
- When the user visits this URL, the system should check whether this token exists on the back-end and, if so, which user's password it is supposed to reset. This token should expire  
    - after a short period of time and 
    - be destroyed immediately after the password has been reset.

## Changing user passwords
Password change functionality can be particularly dangerous if it allows an attacker to access it directly without being logged in as the victim user. For example, if the username is provided in a hidden field, an attacker might be able to edit this value in the request to target arbitrary users. This can potentially be exploited to enumerate usernames and brute-force passwords.
