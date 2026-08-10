# Blind SQL Injection

## 1. What is Blind SQL Injection?

**Blind SQL injection (Blind SQLi)** occurs when an application is vulnerable to SQL injection, but **the query results are not directly reflected in the HTTP response**.

Because the attacker cannot simply retrieve rows using a `UNION SELECT`, they infer information indirectly by observing a **side channel**:

| Technique            | What attacker observes                               |
| -------------------- | ---------------------------------------------------- |
| Conditional response | Page content / status changes                        |
| Conditional error    | Database/application error                           |
| Time-based           | Response delay                                       |
| Out-of-band (OAST)   | DNS/HTTP interaction with attacker-controlled server |

### Core idea

```text
Inject SQL condition
       ↓
Database evaluates condition
       ↓
Observable side effect
       ↓
Attacker determines TRUE/FALSE
       ↓
Repeat character-by-character / bit-by-bit
       ↓
Extract data
```

---

# 2. Conditional Response / Boolean-Based Blind SQLi

Works when the application's response changes depending on whether the SQL query returns data.

### Basic test

```sql
xyz' AND '1'='1'--
xyz' AND '1'='2'--
```

Possible result:

```text
TRUE  → "Welcome back"
FALSE → no "Welcome back"
```

The attacker has established a **boolean oracle**.

### Extracting a character

```sql
xyz' AND
SUBSTRING(
    (SELECT Password
     FROM Users
     WHERE Username='Administrator'),
    1,
    1
) > 'm'--
```

If the response indicates TRUE:

```text
first character > 'm'
```

If FALSE:

```text
first character <= 'm'
```

The attacker can perform repeated comparisons—often using **binary search**—to recover the value efficiently.

### Important assumption

This technique requires a **reliable observable difference** between TRUE and FALSE.

---

# 3. String Substring Syntax

| Database   | Syntax                      |
| ---------- | --------------------------- |
| Oracle     | `SUBSTR('foobar', 4, 2)`    |
| PostgreSQL | `SUBSTRING('foobar', 4, 2)` |
| MySQL      | `SUBSTRING('foobar', 4, 2)` |
| SQL Server | `SUBSTRING('foobar', 4, 2)` |

Example:

```sql
SUBSTRING('foobar', 4, 2)
```

returns:

```text
ba
```

### Other useful functions

| Database   | Alternative         |
| ---------- | ------------------- |
| MySQL      | `SUBSTR()`, `MID()` |
| PostgreSQL | `SUBSTR()`          |
| Oracle     | `SUBSTR()`          |
| SQL Server | `SUBSTRING()`       |

---

# 4. Conditional-Error Blind SQLi

### When?

Use this when:

```text
TRUE condition  → database error
FALSE condition → no error
```

This is useful when the application response **doesn't change based on whether rows are returned**, but database errors produce an observable difference.

### Example

```sql
xyz' AND
(
    SELECT CASE
        WHEN (1=1)
        THEN 1/0
        ELSE 'a'
    END
)='a
```

Conceptually:

```text
condition TRUE
      ↓
1/0
      ↓
Database error
```

Whereas:

```sql
CASE
    WHEN (1=2)
    THEN 1/0
    ELSE 'a'
END
```

produces:

```text
'a'
↓
No divide-by-zero error
```

### Extracting data

```sql
xyz' AND
(
    SELECT CASE
        WHEN (
            Username='Administrator'
            AND SUBSTRING(Password,1,1) > 'm'
        )
        THEN 1/0
        ELSE 'a'
    END
    FROM Users
)='a
```

The attacker observes whether an error occurs and uses that as the TRUE/FALSE signal.

> **AppSec distinction:** This is still a blind inference technique because the sensitive query result itself isn't returned. The attacker is observing an error side channel.

---

# 5. Verbose SQL Error Messages

This is related to SQL injection but is **not necessarily blind SQLi**.

A poorly configured application may expose database errors such as:

```text
Unterminated string literal...
SELECT * FROM tracking WHERE id = '...'
```

This can reveal:

* SQL dialect
* Table/column names
* Query structure
* Application-generated SQL
* Sometimes sensitive data

### Data extraction through type conversion

For example:

```sql
CAST(
    (SELECT example_column
     FROM example_table)
    AS INT
)
```

If the database attempts to convert:

```text
Example data
```

into an integer, an error may reveal:

```text
invalid input syntax for type integer: "Example data"
```

### AppSec takeaway

**Never expose raw database errors to users.**

Use:

```text
User → Generic application error
             ↓
        Server-side logs
             ↓
      Detailed DB error
```

rather than:

```text
User → Raw SQL/database error
```

---

# 6. Time-Based Blind SQLi

Use this when:

```text
Boolean response → no observable difference
Database error   → suppressed
```

Instead, make the database **delay execution only when a condition is TRUE**.

The attacker compares response times:

```text
TRUE  → ~10 second response
FALSE → normal response
```

## SQL Server

```sql
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```

TRUE → approximately 10-second delay.

```sql
'; IF (1=2) WAITFOR DELAY '0:0:10'--
```

FALSE → no intentional delay.

### Important correction to your notes

Your original note says:

```text
1=1 → delay because 1 == 2
```

That should be:

```text
1=1 → delay because 1 == 1
1=2 → no delay because 1 != 2
```

---

## Common DB-specific delay mechanisms

| Database   | Typical mechanism                                                           |
| ---------- | --------------------------------------------------------------------------- |
| SQL Server | `WAITFOR DELAY`                                                             |
| PostgreSQL | `pg_sleep()`                                                                |
| MySQL      | `SLEEP()`                                                                   |
| Oracle     | `DBMS_PIPE.RECEIVE_MESSAGE()` / other delay mechanisms depending on context |

Examples:

### PostgreSQL

```sql
SELECT pg_sleep(10);
```

### MySQL

```sql
SELECT SLEEP(10);
```

The exact payload depends heavily on **where the injection occurs and how the original SQL statement is structured**.

---

# 7. Out-of-Band SQL Injection / OAST

### What is OAST?

**Out-of-band (OOB/OAST) SQLi** uses a separate communication channel to detect or exploit SQL injection.

Instead of:

```text
SQL query
   ↓
HTTP response
```

the flow becomes:

```text
HTTP request
     ↓
Vulnerable application
     ↓
Database
     ↓
External DNS/HTTP interaction
     ↓
Attacker-controlled server
```

For example:

```text
Application
     |
     | DNS lookup
     ↓
attacker.example.com
```

The attacker observes the interaction and knows that the injected SQL executed.

### Why is this useful?

Especially useful when:

* SQL executes asynchronously
* HTTP response doesn't contain useful information
* Database errors are suppressed
* Response timing is unreliable
* The database can make external network requests

### Important correction

OAST is **not simply "when SQL executes asynchronously."**

Asynchronous execution is one situation where OAST can be particularly useful, but OAST is fundamentally about using an **external side channel** to receive evidence/data.

### Data exfiltration concept

An attacker may construct a hostname containing database data:

```text
<extracted-data>.attacker-controlled-domain
```

Then:

```text
Database
   ↓
DNS request
   ↓
Attacker's DNS/OAST server
```

The attacker can observe the requested hostname.

> **Lab note:** Tools such as Burp Collaborator are commonly used in security labs to detect these interactions.

---

# 8. SQL Injection in Different Input Contexts

SQL injection is **not limited to query-string parameters**.

Potential injection points include:

```text
URL query parameters
POST parameters
JSON
XML
HTTP headers
Cookies
GraphQL variables
Path parameters
Custom API fields
```

Example JSON:

```json
{
  "username": "xyz' OR '1'='1"
}
```

The important question is:

> **Does attacker-controlled input eventually become part of a SQL query?**

---

# 9. WAF / Input-Filter Evasion

Some weak defenses search for suspicious strings such as:

```text
SELECT
UNION
OR
AND
```

Attackers may attempt:

* URL encoding
* Alternate encodings
* Case variations
* XML escaping
* Whitespace manipulation
* SQL comments
* Database-specific syntax

Example concept:

```text
SELECT
```

may be represented differently depending on the input/parser context.

### Critical AppSec lesson

**WAF filtering is not a primary SQL injection defense.**

Bad:

```text
User input
    ↓
Keyword blacklist
    ↓
SQL query
```

Better:

```text
User input
    ↓
Parameterized query
    ↓
Database
```

A WAF should be considered **defense-in-depth**, not the fundamental fix.

---

# 10. Second-Order SQL Injection

### First-order SQLi

Malicious input is injected and executed immediately:

```text
Attacker input
      ↓
SQL query
      ↓
Exploit
```

### Second-order SQLi

Malicious input is first **stored**, then later retrieved and used unsafely in another SQL query.

```text
Step 1:
Attacker input
      ↓
Application
      ↓
Database stores payload

Step 2:
Application retrieves stored value
      ↓
Builds another SQL query unsafely
      ↓
Payload executes
```

### Why it is dangerous

The input may initially look harmless because it isn't executed when submitted.

The vulnerability occurs later when another application component trusts the stored value.

### AppSec lesson

**Parameterize queries at the point of SQL execution—not only at the point where data enters the system.**

---

# 11. SQLi Decision Tree

```text
SQL injection confirmed
          |
          v
Can query results be observed?
       /       \
     YES        NO
      |          |
   UNION /     Blind SQLi
   direct       |
   extraction   +---------------------------+
                |            |              |
                v            v              v
          Boolean       Conditional      Time-based
          response         error
                |            |              |
                +------------+--------------+
                             |
                             v
                       OAST available?
                             |
                            YES
                             |
                             v
                       Out-of-band
```

---

# 12. How Attackers Extract One Character

Suppose:

```text
Password = "S3cret..."
```

The attacker can ask questions such as:

```text
Is character 1 > 'm'?
Is character 1 > 't'?
Is character 1 > 'p'?
...
```

Each request gives:

```text
TRUE / FALSE
```

Eventually:

```text
character 1 = S
```

Then:

```text
character 2?
character 3?
...
```

### Optimization

Instead of testing every possible character sequentially:

```text
a
b
c
d
...
z
```

use comparisons/binary search where possible.

This reduces the number of requests substantially.

---

# 13. Primary Fix for SQL Injection

## Use parameterized queries / prepared statements

### Node.js — PostgreSQL

```javascript
const result = await db.query(
  'SELECT * FROM users WHERE username = $1',
  [username]
);
```

### Python — parameterized query

```python
cursor.execute(
    "SELECT * FROM users WHERE username = %s",
    (username,)
)
```

### Java — JDBC

```java
PreparedStatement stmt =
    connection.prepareStatement(
        "SELECT * FROM users WHERE username = ?"
    );

stmt.setString(1, username);
```

### SQLAlchemy

```python
query = text(
    "SELECT * FROM users WHERE username = :username"
)

db.execute(query, {"username": username})
```

---

# 14. Defense-in-Depth

Parameterized queries are the primary control.

Also consider:

### Database permissions

Application account should have:

```text
minimum required privileges
```

Avoid:

```text
application → DBA/root account
```

### Error handling

Don't expose:

```text
SQL syntax
database stack traces
table names
column names
connection details
```

Return:

```text
Generic error → detailed server-side logging
```

### Monitoring

Detect:

* Repeated SQL errors
* Abnormal request patterns
* Unusual query latency
* Unexpected database access
* OAST/DNS activity
* Large numbers of malformed requests

### Input validation

Useful for:

* IDs
* enums
* numeric fields
* expected formats

But remember:

> **Input validation does not replace parameterized queries.**

---

# 15. Developer Takeaways

### Dangerous

```javascript
const query =
  `SELECT * FROM users WHERE username = '${username}'`;
```

### Safe

```javascript
const query =
  'SELECT * FROM users WHERE username = $1';

db.query(query, [username]);
```

### Remember

```text
Escaping          → fragile
Blacklist/WAF     → bypassable
Input validation  → defense-in-depth
Parameterized SQL → primary defense
Least privilege   → limits impact
Safe errors       → reduces information leakage
Monitoring        → detects exploitation
```

---

# 16. AppSec Interview Questions

### Q: Why can't UNION attacks always be used?

Because UNION-based SQLi generally requires the application's response to expose the query results. In blind SQLi, the result is not directly returned.

### Q: How would you exploit blind SQLi?

Identify an observable side channel:

```text
Boolean response
      ↓
Conditional error
      ↓
Time delay
      ↓
OAST
```

Then use that oracle to infer information.

### Q: Boolean vs time-based SQLi?

**Boolean-based:**

```text
TRUE → response A
FALSE → response B
```

**Time-based:**

```text
TRUE → delayed response
FALSE → normal response
```

### Q: What is second-order SQLi?

Malicious input is stored first and executed later when another component uses that stored value unsafely in SQL.

### Q: What's the primary fix?

**Parameterized queries / prepared statements.**

### Q: Is escaping enough?

No. Escaping is context- and database-dependent and is much more error-prone than parameterization.

### Q: Does a WAF prevent SQLi?

No. A WAF can provide defense-in-depth, but it should not be relied upon as the primary SQLi control.

---

# 17. Real-World AppSec Perspective

The vulnerability isn't fundamentally:

> "The attacker entered `OR 1=1`."

The underlying vulnerability is:

> **Untrusted data was allowed to influence SQL syntax.**

Therefore, the security boundary should be:

```text
UNTRUSTED DATA
      ↓
Application
      ↓
Parameterized query
      ↓
SQL engine
```

not:

```text
UNTRUSTED DATA
      ↓
Blacklist
      ↓
WAF
      ↓
String concatenation
      ↓
SQL engine
```

### Severity considerations

When assessing a real SQLi finding, determine:

1. Can SQL syntax be controlled?
2. Which database is affected?
3. What database account does the application use?
4. Can the attacker read data?
5. Can the attacker modify/delete data?
6. Can they access other tenants' data?
7. Can the DB make outbound network requests?
8. Can the DB account execute privileged functions?
9. Is sensitive data stored in the affected database?
10. Is the vulnerability exploitable without authentication?

The **impact depends heavily on database privileges and application architecture**, not merely on the existence of SQL injection.

---

# 18. 30-Second Recall

```text
BLIND SQLi
│
├── No direct query results
│
├── Boolean
│     └── TRUE/FALSE → response difference
│
├── Conditional Error
│     └── TRUE/FALSE → DB error difference
│
├── Time-Based
│     └── TRUE/FALSE → response delay
│
├── OAST
│     └── SQL → DNS/HTTP → attacker-controlled server
│
└── Second-Order
      └── Store payload → retrieve later → unsafe SQL execution


PRIMARY FIX
└── Parameterized queries / Prepared Statements

DEFENSE IN DEPTH
├── Least-privilege DB accounts
├── Safe error handling
├── Input validation
├── Monitoring
└── WAF as defense-in-depth
```
