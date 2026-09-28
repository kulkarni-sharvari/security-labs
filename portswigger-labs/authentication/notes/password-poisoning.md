# Password Reset Poisoning

Password reset poisoning is a technique whereby an attacker manipulates a vulnerable website into generating a password reset link pointing to a domain under their control

This leads to stealing the secret tokens required to reset arbitrary users' passwords and, ultimately, compromise their accounts.

## How does a password reset work?
1. User enters the username/email and clicks on "Forgot Password"
2. The backend checks if the user exists and then generates a temporary passwory, unique and high entropy token that is associated with the user's account in the backend
3. The website sends an email to the user containing the reset URL. This unique token generated at (2) is sent as a query param 
```
https://normal-website.com/reset?token=0a1b2c3d4e5f6g7h8i9j
```
4. When the user visits the URL in (3), the website checks whether the provided token is valid and uses it to determine which account is being reset. If everything checks out - the validity of the token and user, the password is updated.

Password reset poisoning is a method of stealing this token in order to change another user's password.

## How to construct a password reset poisoning attack
If the URL that is sent to the user is **dynamically generated based on controllable input**, such as the Host header, it may be possible to construct a password reset poisoning attack as follows:
1. The attacker obtains the username/email of the victim (maybe via social engineering) and request for reset password.
2. The attacker manipulates the HTTP header so that the packet points to the server that the attacker controls.
3. The victim clicks on this link. The attacker receives the genuine reset token of the user which he/she uses to reset the victim's password.
