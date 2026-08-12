# SQL Injection — Cheat Sheet

## Table of Contents

| # | Section |
|---|---------|
| 1 | [What is SQLi?](#1-what-is-sqli) |
| 2 | [Impact (CIA)](#2-impact-cia) |
| 3 | [Find & Exploit Workflow](#3-find--exploit-workflow) |
| 4 | [Common Injection Locations](#4-common-injection-locations) |
| 5 | [Attack Techniques](#5-attack-techniques) |
| 6 | [Blind SQLi Detection](#6-blind-sqli-detection) |
| 7 | [Second-Order SQLi](#7-second-order-sqli) |
| 8 | [SQLi in JSON / XML](#8-sqli-in-json--xml) |
| 9 | [Prevention](#9-prevention) |

---

## 1. What is SQLi?

**SQL Injection (SQLi)** — a web vulnerability where an application incorporates **untrusted user input** into an SQL query without proper validation or parameterized queries.

- The attacker injects SQL that **alters the structure or logic** of the intended query.
- The database then executes unintended commands.
- If user input can modify the query, the app is vulnerable.

---

## 2. Impact (CIA)

| Impact | Description | CIA Property |
|--------|-------------|--------------|
| **Read sensitive data** | Passwords, credit cards, PII, private records | Confidentiality |
| **Modify data** | Insert / update / delete records without authorization | Integrity |
| **Bypass auth** | Log in as another user or access restricted resources | — |
| **Admin DB operations** | Privileged actions if the DB account has excessive permssion | — |
| **Compromise server** | Escalate beyond DB to OS commands / server control | — |
| **Denial of Service** | Resource-heavy or destructive queries crash the DB | Availability |

> **Summary:** SQLi can compromise all three sides of the **CIA triad** depending on the app and DB permissions.

---

## 3. Find & Exploit Workflow

### Step 1 — Identify Injection Points

Test **every** location that accepts user input:

- URL query parameters
- Form fields (login, search, registration, …)
- Cookies
- HTTP headers
- Hidden form fields
- JSON / XML request bodies
- API parameters

> **Rule:** Treat every user-controlled input as a potential SQLi point until proven otherwise.

### Step 2 — Detect SQLi

| Technique | Payload | What to look for | Purpose |
|-----------|---------|------------------|---------|
| **SQL errors** | `'` | DB errors, HTTP 500, unexpected behavior, response differences | Is input parsed as SQL? |
| **Boolean conditions** | `OR 1=1` vs `OR 1=2` | Different responses between the two | Confirm input influences query logic |
| **Blind / time-based** | Time-delay payloads | Consistently slower response | Detect SQLi when no errors/output shown |

### Step 3 — Exploit

Once confirmed, depending on DB permissions you may:

- Retrieve sensitive data
- Enumerate databases, tables, columns
- Bypass authentication
- Modify or delete data
- Perform admin DB operations
- Compromise the underlying server
- Cause DoS

### Testing Workflow at a Glance

1. Identify every user-controlled input.
2. Test whether the input is interpreted as SQL by:
   - Triggering SQL errors.
   - Injecting TRUE/FALSE conditions.
   - Using time-based payloads for blind SQLi.
3. Confirm the SQL query can be manipulated.
4. Determine impact (read/modify data, bypass auth, admin ops).

> **Key Concept:** SQLi exists whenever **untrusted user input is included in an SQL query without proper validation or parameterized queries**.

---

## 4. Common Injection Locations

SQLi can occur anywhere untrusted input reaches an SQL query.

### 4.1 `WHERE` clause in `SELECT`

Most common — user input filters query results.

```sql
SELECT * FROM users WHERE username = '<user_input>';
```

### 4.2 Table / Column names in `SELECT`

Queries dynamically built with user-supplied identifiers.

```sql
SELECT <column_name> FROM users;
```

### 4.3 `ORDER BY` clause

User input determines sort order.

```sql
SELECT * FROM products ORDER BY <user_input>;
```

### 4.4 `UPDATE` statements

Injection possible in updated values **or** the `WHERE` clause.

```sql
UPDATE users SET email = '<user_input>' WHERE id = '<user_input>';
```

### 4.5 `INSERT` statements

User input inserted directly into a record.

```sql
INSERT INTO users (username, email) VALUES ('<user_input>', '<user_input>');
```

---

## 5. Attack Techniques

### 5.1 Retrieving Hidden Data

**Vulnerability:** User input is directly concatenated into an SQL query instead of using parameterized queries.

| | Request | Resulting Query |
|---|---------|-----------------|
| **Normal** | `?category=Gifts` | `SELECT * FROM products WHERE category = 'Gifts' AND released = 1;` |
| **Malicious** | `?category=Gifts'--` | `SELECT * FROM products WHERE category = 'Gifts' -- AND released = 1;` |

**What happens?**

- `'` closes the string.
- `--` comments out the rest of the query.
- `AND released = 1` is ignored.

**Effective query:**

```sql
SELECT * FROM products WHERE category = 'Gifts';
```

**Result:** Returns **all** products in `Gifts` — including unreleased ones. The attacker has modified query logic to bypass the app's restriction.

> **Takeaway:** SQLi occurs when user input changes the intended SQL query, allowing the DB to execute unintended commands.

---

### 5.2 Subverting Application Logic (Auth Bypass)

**Vulnerability:** Credentials concatenated directly into the SQL query.

| | Value | Query |
|---|-------|-------|
| **Normal** | `username=admin`, `password=password` | `SELECT * FROM users WHERE username = 'admin' AND password = 'password'` |
| **Malicious input** | `username: admin'--` | `SELECT * FROM users WHERE username = 'admin' -- AND password = 'password'` |

**What happens?**

- `'` closes the username string.
- `--` comments out the password check.

**Effective query:**

```sql
SELECT * FROM users WHERE username = 'admin';
```

**Result:** If `admin` exists, the DB returns the record **without validating the password** — auth bypassed.

> **Takeaway:** SQLi can subvert application logic by changing how auth queries are evaluated.

---

### 5.3 Retrieving Data From Other Tables (`UNION`)

**Vulnerability:** If the app displays query results, `UNION` can pull data from other tables.

| | Value |
|---|-------|
| **Original query** | `SELECT name, description FROM products WHERE category = 'Gifts'` |
| **Attacker input** | `' UNION SELECT username, password FROM users--` |
| **Resulting query** | `SELECT name, description FROM products WHERE category = '' UNION SELECT username, password FROM users--';` |

**What happens?**

- `UNION` combines two `SELECT` result sets.
- The second query pulls from `users`.
- Combined rows are rendered as if part of the original query.

**Result:** Usernames and passwords returned alongside product data.

> **Takeaway:** `UNION`-based SQLi extracts data from other tables when the app response includes query results.

---

## 6. Blind SQLi Detection

**Vulnerability:** The app is injectable but **does not return query results or DB errors**. The attacker **infers** behavior instead.

| Type | Payload example | Observe for |
|------|-----------------|-------------|
| **Boolean-based** | `AND 1=1` vs `AND 1=2` | Different page content, HTTP status, presence/absence of data |
| **Error-based** | `CASE WHEN (condition) THEN 1/0 ELSE 1 END` | Generic error pages, response changes when condition true |
| **Time-based** | Payloads that delay the DB response | Consistent delays; faster response when condition is false |

> **Takeaway:** Blind SQLi confirms itself through **differences in responses, errors, or response times** — not visible output.

---

## 7. Second-Order SQLi

**Vulnerability:** The app **stores user input** (typically in the DB) and later **uses it in an SQL query without sanitization**. The payload doesn't execute on store — only on later retrieval and reuse.

### Attack Flow

1. Attacker submits malicious input.
2. App stores it — no SQLi triggered yet.
3. App later retrieves the stored input.
4. Stored input is unsafely concatenated into a new SQL query.
5. Injected SQL executes.

### Possible outcomes

- Retrieve sensitive data
- Modify or delete data
- Bypass application logic
- Any action permitted by the vulnerable query

> **Takeaway:** In second-order SQLi, the payload is **stored first, executed later** when the app reuses it in another query.

---

## 8. SQLi in JSON / XML

**Concept:** SQLi is **not limited to URL params or form fields**. Any user-controlled input that reaches an SQL query is fair game — including JSON and XML bodies.

### Bypassing Input Filters

Some apps/WAFs match on SQL keywords (`SELECT`, `UNION`, `WHERE`). Attackers evade by **encoding/escaping characters** so the payload looks clean during inspection but is decoded before execution.

**Example (XML):**

```xml
<stockCheck>
    <productId>123</productId>
    <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```

- `&#x53;` = XML escape for **`S`**.
- Server decodes the payload to:

```sql
SELECT * FROM information_schema.tables
```

- The decoded SQL is then processed by the DB.

> **Takeaway:** SQLi can be delivered through **any controllable input**. Encoding tricks in JSON/XML payloads can bypass weak filters/WAFs before the payload is decoded and executed.

---

## 9. Prevention

### 9.1 Use Parameterized Queries (Prepared Statements)

**Primary defense** — user input is treated as **data**, not executable SQL.

```java
PreparedStatement statement =
    connection.prepareStatement(
        "SELECT * FROM products WHERE category = ?"
    );

statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```

### 9.2 Where They Work vs Don't Work

| Works for (data values) | Does NOT work for (identifiers) |
|---------------------------|-----------------------------------|
| `WHERE` clause values | Table names |
| `INSERT` values | Column names |
| `UPDATE` values | `ORDER BY` column / direction |
| `DELETE` values | SQL keywords |

For identifiers → **whitelist** known-permitted values, or map user input to predefined SQL values via app logic.

### 9.3 Best Practices

- **Always** use a hard-coded SQL query template.
- **Never** concatenate user input into the SQL query string.
- **Never** assume any input is "trusted" — parameterize all user-controlled data.
- If parameterization is not possible (e.g., table names / `ORDER BY`) → strict allowlist validation.

> **Key Takeaway:** Keep the **SQL query structure fixed** and pass **all user input as parameters**. If user input can change the query's structure, SQLi becomes possible.
