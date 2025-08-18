## SHA3 for Oracle PL/SQL

This package implements SHA3, Keccak, and SHAKE hash functions fully in Oracle PL/SQL.

## Features

* SHA3-224/256/384/512
* Keccak-224/256/384/512
* SHAKE128/SHAKE256 with custom bit length
* Input types: RAW, VARCHAR2, NVARCHAR2, CLOB, NCLOB, BLOB

## Install
```
-- sql
@SHA3.pck
```
## Examples
```SQL
-- RAW data
select sha3.sha3_256('F71837502BA8E108') from dual;
-- TEXT data with default codepage (AL32UTF8)
select sha3.sha3_256('The quick brown fox jumps over the lazy dog', 'TXT') from dual;
-- TEXT data with codepage (CL8MSWIN1251)
select sha3.sha3_256('SQL — декларативна мова програмування', 'TXT', 'CL8MSWIN1251') from dual;
-- TEXT data in national character set
select sha3.sha3_256(n'Specification of θ', 'TXT') from dual;
-- CLOB data
select sha3.sha3_256(to_clob('The quick brown fox jumps over the lazy dog')) from dual;
-- BLOB data
select sha3.sha3_256(to_blob('F71837502BA8E108')) from dual;
-- TEXT data with varaible output
select sha3.shake_128('The quick brown fox jumps over the lazy dog', 24, 'TXT') from dual;
```
## Notes

Designed for Oracle 12c+

Includes basic input validation
