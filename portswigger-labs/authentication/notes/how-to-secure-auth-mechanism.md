# How to secure your authentication mechanisms

## 1. Take care with the user credentials.
- Never send login credentials over unencrypted connections
- Ensure you enforce redirecting any attempted HTTP requests to HTTPS
- Ensure no username/email addresses are disclosed through publicly accessible profiles or reflected HTTP responses

## 2. DOnt count on users for security
- Implement an effective password policy.
- Implement a password checker which allows users to experiment with passwords and provide feedback about their strength in real time. E.g. zxcvbn

## 3. Prevent username enumeration
- Regardless of whether an attempted username is valid, it is important to use identical, generic error messages, and make sure they really are identical
- You should always return the same HTTP status code with each login request and, finally, make the response times in different scenarios as indistinguishable as possible

## 4. Implement robust brute-force protection
- Implement strict, IP based rate limiting
- Ideally - complete the captcha test with every login after a certain limit is reached.

## 5k Implement proper multi-factor authentication
- When done properly, it is more secure than password-based login alone.
- Remember that verifying multiple instances of the same factor is not true multi-factor authentication
- SMS-based 2FA is technically verifying two factors (something you know and something you have). However, the potential for abuse through SIM swapping, for example, means that this system can be unreliable.
- Ideally, 2FA should be implemented using a dedicated device or app that generates the verification code directly.