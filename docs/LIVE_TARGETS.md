# Live Target Validation

## Juice Shop — SQLi endpoint
- **Endpoint:** `/rest/products/search?q=apple`
- **Outcome:** 1 CRITICAL finding (`sqli:sql_injection`)
- **Evidence:** See dev.to post-mortem.

## DVWA — SQLi module (low security)
- **Endpoint:** `/vulnerabilities/sqli/?id=1&Submit=Submit`
- **Authentication:** Session cookie (PHPSESSID) + security=low
- **Outcome:** 8 CRITICAL findings in 1 group (`sqli:sql_injection`)
- **Raw output:**

```text
  Findings:        8 in 1 group
  Findings:
    F-001  CRITICAL sqli:sql_injection  (param=id)
           - [sql_single_quote] db_error: MYSQL error signature matched
           - [sql_union_null] db_error: MYSQL error signature matched
           - [sql_sleep_mysql] db_error: MYSQL error signature matched
           - [sql_sleep_pg] db_error: MYSQL error signature matched
           - [sql_paren_quote] db_error: MYSQL error signature matched
           - [sql_paren_double] db_error: MYSQL error signature matched
           - [sql_paren_union] db_error: MYSQL error signature matched
           - [sql_paren_or] db_error: MYSQL error signature matched
```

