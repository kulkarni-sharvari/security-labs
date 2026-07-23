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