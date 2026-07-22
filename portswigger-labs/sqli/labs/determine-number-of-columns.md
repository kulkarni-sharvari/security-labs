# Determine number of columns
## Goal: 
The application is vulnerable to a SQL Injection UNION attack in the product category filter. Because user input is passed to the database without proper sanitization, and the database response is directly rendered on the front end, an attacker can inject a UNION SELECT query to retrieve data from other database tables. For the attack to succeed, the injected query must return the same number of columns and compatible data types as the original query.

## Additional Notes

A SQL Injection UNION attack uses the `UNION` keyword to combine results from another query with the original query, allowing attackers to extract data from other database tables.

For a `UNION SELECT` attack to succeed, the injected query must match the original query in:

- number of columns
- compatible data types

Two common techniques for finding the column count:
1. ORDER BY enumeration
2. UNION SELECT NULL enumeration

## Lab Details: 
Name: SQL injection UNION attack, determining the number of columns returned by the query

Level: Practitioner

Vulnerability Class: SQL Injection

Lab URL: [Lab link](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns)

Date Completed: 13-May-2026

Time to Solve: 1 hours.

## Reconnaissance
The lab decription mentioned that category filter is susceptible to SQL Union Attack.
- Single quote ' caused a 500 error — indicates unsanitized input reaching SQL parser
- Column count determined via ORDER BY incrementing by 1 each time
- Column count determined via Union enumeration


## Exploitation — Step by Step
### Step 1: Using Order By Enumeration
The following payloads were injected into the vulnerable parameter:

```sql
'+ORDER+BY+1--+
```

```sql
'+ORDER+BY+2--+
```

```sql
'+ORDER+BY+3--+
```

```sql
'+ORDER+BY+4--+
```

The application responded normally for payloads `1`, `2`, and `3`, but returned an internal server error for `4`.

This indicates that the underlying query contains **3 columns**, since attempting to sort by a non-existent fourth column caused the database query to fail.

### Explanation

`ORDER BY n` instructs the database to sort the results using the `n`th column in the `SELECT` statement.

For example:

- `ORDER BY 1` → sort by first column
- `ORDER BY 2` → sort by second column
- `ORDER BY 3` → sort by third column

If the specified column index exceeds the number of columns returned by the query, the database throws an error.

### Step 2: Using Union Enumeration
The following payloads were injected into the vulnerable parameter:

```sql
SELECT name, description, price FROM products WHERE category = 'Gifts'
UNION SELECT NULL,NULL,NULL--'
``````

```sql
'+UNION+SELECT+NULL,NULL--+
```

```sql
'+UNION+SELECT+NULL,NULL,NULL--+
``````

The application responded with `Internal Server Error` for payloads `NULL` and `NULL,NULL` but works normally for `NULL,NULL,NULL`.

This indicates that the underlying query contains **3 columns**.

### Key Payload(s)
- With `ORDER BY`
```sql
SELECT name, description, price FROM products WHERE category = 'Gifts' ORDER BY 4 --'
```
- With `UNION SELECT`
```sql
SELECT name, description, price FROM products WHERE category = 'Gifts'
UNION SELECT NULL,NULL,NULL--'
```
### Tools Used
 Manual (Burp Suite Repeater)

## The Fix
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


## What I Found Interesting / Unexpected
I assumed UNION attacks were theoretical or required direct database access — something you'd only run in a dev console. What surprised me is that the database parser makes no distinction between a developer's legitimate query and an attacker's injected one. Once input reaches SQL unsanitized, the engine executes it with full trust. I spend some time into understanding why NULL is used instead of real values — turns out data type mismatches silently fail, so NULL acts as a type-agnostic probe. That's not obvious from reading about it; you have to hit the error to understand it.

## Real-World Relevance
### CVE-2023-34362 – MOVEit Transfer SQL Injection Analysis

In May 2023, the CL0P ransomware group exploited a critical SQL injection vulnerability tracked as CVE-2023-34362 in the MOVEit Transfer application. The vulnerability enabled attackers to deploy a malicious web shell known as **LEMURLOOT**, which was later used for data theft and persistent access.

MOVEit Transfer is a managed file transfer solution designed to securely exchange files using encrypted protocols such as FTP and SFTP. The platform also provides automation, analytics, and failover capabilities for enterprise environments.

Within MOVEit, "packages" are used to securely exchange sensitive files between users and organizations.

On May 31, 2023, Progress Software publicly disclosed the vulnerability and warned customers about active exploitation in the wild. According to the advisory, CVE-2023-34362 allowed attackers to:

- Escalate privileges
- Access and download sensitive database information
- Retrieve Azure-related configuration secrets
- Deploy malicious files and backdoors
- Create privileged administrator accounts

The attackers ultimately installed the **LEMURLOOT** web shell, which provided the ability to:

- Enumerate the backend SQL database
- Read and write files on the MOVEit server
- Extract system configuration details
- Create administrator-level accounts for persistence

---
### Attack Path to the Vulnerable Function

The SQL injection vulnerability was reachable through an unauthenticated request to:

```text
guestaccess.aspx
```

Specifically, exploitation occurred when the `Transaction` parameter was set to:

```text
secmsgpost
```

The request execution followed the following call chain:

```text
guestaccess.aspx
 └── SILGuestAccess
      └── SILGuestAccess.PerformAction()
           └── MsgEngine.MsgPostForGuest()
                └── UserEngine.UserGetSelfProvisionUserRecipsWithEmailAddress()
                     └── UserEngine.UserGetUsersWithEmailAddress()
```

The core issue originated from unsafe handling of session variables. During processing, the application executed:

```text
this.m_pkginfo.LoadFromSession()
```

This function loaded internal variables directly from session data that attackers could manipulate through `session_setvars`.

One of the manipulated variables, `SelfProvisionedRecips`, contained a comma-separated list of email addresses. The application failed to properly sanitize this value before using it in a SQL query.

---

### Vulnerable SQL Query

Inside the `UserGetUsersWithEmailAddress()` function, the SQL query was dynamically constructed as follows:

```sql
SELECT Username, Permissions, LoginName, Email
FROM users
WHERE InstID=9389
  AND Deleted=0
  AND (
        Email='<EmailAddress>'
        OR Email LIKE (%EscapeLikeForSQL(<EmailAddress>))
        OR Email LIKE (EscapeLikeForSQL(<EmailAddress>))
      );
```

The vulnerable portion of the query was:

```sql
Email='<EmailAddress>'
```

Because the `EmailAddress` parameter was directly inserted into the query without proper sanitization or parameterized statements, attackers could inject arbitrary SQL commands.

---

### Exploitation Details

**Injection Constraints**

A key limitation during exploitation was that the `SelfProvisionedRecips` variable was split using commas:

```text
,
```

As a result, payloads containing commas would break execution.

To bypass this limitation, attackers avoided comma characters entirely and instead performed multiple sequential SQL injections. This allowed them to chain database operations step by step, such as:

1. Executing an `INSERT` statement
2. Following it with an `UPDATE`
3. Gradually modifying permissions and records

This staged exploitation technique enabled reliable SQL injection even under input restrictions.

### Key Takeaways

- The vulnerability originated from improper sanitization of user-controlled session variables.
- Dynamic SQL query construction enabled direct SQL injection.
- The vulnerable endpoint could be exploited without authentication.
- Attackers bypassed input restrictions by using staged SQL operations.
- The LEMURLOOT web shell provided persistence and extensive post-exploitation capabilities.

---

### Sources

1. Palo Alto Unit 42 – Threat Brief on MOVEit CVE-2023-34362  
   https://unit42.paloaltonetworks.com/threat-brief-moveit-cve-2023-34362/

2. Hack The Box – CVE-2023-34362 Explained  
   https://www.hackthebox.com/blog/cve-2023-34362-explained

3. Horizon3.ai – MOVEit Transfer CVE-2023-34362 Deep Dive  
   https://horizon3.ai/attack-research/attack-blogs/moveit-transfer-cve-2023-34362-deep-dive-and-indicators-of-compromise/


## Connections to My Own Projects
TBD

## Takeaway
Parameterized queries stop the injection, but this lab also shows that raw 500 errors hand attackers a free reconnaissance tool. The error response itself confirmed the column count. Production apps should return generic error pages, log the details server-side, and never expose database errors to the client. Defense requires fixing both the injection point and the information leakage.

Even if one layer sanitizes input, alternative code paths may bypass it.