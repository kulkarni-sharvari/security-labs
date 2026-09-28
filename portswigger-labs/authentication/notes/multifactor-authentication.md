# Multifactor authentication

- Full benefits of multi-factor authentication are only achieved by verifying multiple different factors. 
- Verifying the same factor in two different ways is not true two-factor authentication. For example, although the user has to provide a password and a verification code (sent on an email), accessing the code only relies on them knowing the login credentials for their email account. Therefore, the knowledge authentication factor is simply being verified twice.

---

## Two-factor authentication tokens
- High security application provide users with dedicated devices such as RSA token or keypad device. These devices also generate the TOTP. Therefore, they are more secure than an email of sms containing th verification code since these can be intercepted.
- Some applications also use software applications instead of physical devices, like Google Authenticator, Duo, etc

## Bypassing two-factor authentication
- Implementation flaw
- If the user is first prompted to enter a password, and then prompted to enter a verification code on a separate page, the user is effectively in a "logged in" state before they have entered the verification code. In this case, it is worth testing to see if you can directly skip to "logged-in only" pages after completing the first authentication step

## Flawed two-factor verification logic
- User A has completed the initial login step. Is User A completing the seconnd authentication step?
- Steps:
1. User A performs initaial login step with their correct initial.
2. Application returns a session cookie. This cookie is used to identify the account in the subsequent step.
3. The attacker tampers the accountID to a victims accountID when submitting the verfication code.
