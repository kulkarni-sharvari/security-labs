# Determine database type and version
## Goal: 
Determine that the backend database is MySQL and Microsoft and retrieve its version information using a `UNION SELECT` attack.


## Lab Details: 
Name: SQL injection attack, querying the database type and version on MySQL and Microsoft

Level: Practitioner

Vulnerability Class: SQL Injection

Lab URL: [Lab link](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft)

Date Completed: 23-Jul-2026

Time to Solve: 15 minutes.

## Reconnaissance
The lab decription mentioned that **category** filter is vulnerable to SQL Union Attack.
- Single quote ' caused a **HTTP 500 Internal Server Error**, indicating unsanitized input reaching SQL parser
- Column count determined via `UNION SELECT` payloads.


## Exploitation — Step by Step
### Step 1: Determining the Number of Columns with `UNION SELECT`
The following payloads were injected into the vulnerable parameter:

```sql
'
```

```sql
'+UNION+SELECT+NULL#
```

```sql
' UNION SELECT NULL, NULL#
```

```sql
' UNION SELECT @@version, NULL#
```

#### Observations 
- The application returned an **HTTP 500 Internal Server Error** when the payload `'` was supplied, confirming that the category parameter was vulnerable to SQL injection. 
- The payload below executed successfully: 
```sql 
'+UNION SELECT @@version, NULL#
``` 
- This confirmed that the original query returns **two columns** and that **both columns accept string data**. With this information, the following payload was used to retrieve the mysql and microsoft database version: 
```sql 
'+UNION SELECT @@version, NULL#
```

### Explanation

`UNION SELECT` combines the result sets of two or more `SELECT` statements into a single response.

For example: `UNION SELECT 'abc' from table` → This appends the value `'abc'` to the original query's result set.

For a `UNION` query to execute successfully: - Both `SELECT` statements must return the **same number of columns**. - Corresponding columns must have **compatible data types**. Otherwise, the database returns an error.

## Key Payload(s)
- With `UNION SELECT`
```sql
SELECT name, description, price FROM products WHERE category = 'Gifts'
UNION SELECT @@version, NULL #'
```
## Tools Used
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
I initially assumed that database version information could only be retrieved by authenticated users with direct access to the database instance. This lab demonstrated that if an application is vulnerable to SQL injection and the application's database account has sufficient privileges, an attacker can retrieve database metadata without authenticating directly to the database.

## Real-World Relevance
Database metadata (schema, version, table names, column names) is valuable because it enables reconnaissance. While metadata disclosure alone is rarely the end goal, it significantly simplifies subsequent SQL injection attacks by helping attackers identify the database type, understand its structure, and target sensitive data more efficiently.



## Connections to My Own Projects
TBD

## Takeaway
Parameterized queries are the primary defense against SQL injection because they prevent user input from altering the structure of SQL queries. In addition, database hardening should be used as a defense-in-depth measure. This includes applying the principle of least privilege, disabling unnecessary database features, and using separate database accounts with only the permissions required by the application.