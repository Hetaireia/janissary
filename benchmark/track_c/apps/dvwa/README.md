# DVWA - Damn Vulnerable Web Application

| | |
|---|---|
| Base URL | http://127.0.0.1:4280 |
| Image | vulnerables/web-dvwa |
| Auth | admin / password |
| Security level | low (set via /security.php) |
| Port | 4280 |

## Classes exercised

- `sqli` - /vulnerabilities/sqli/?id=test&Submit=Submit
- `sqli_blind` - /vulnerabilities/sqli_blind/?id=test&Submit=Submit
- `xss` (reflected) - /vulnerabilities/xss_r/?name=test
- `traversal` - /vulnerabilities/fi/?page=include.php&Submit=Submit

## Start

    docker compose -f benchmark/track_c/docker-compose.yml up -d dvwa

The first request to /login.php creates the database; the healthcheck in
docker-compose.yml polls this endpoint with retry 30 so the service is not
marked ready until DVWA is serving.

## Runner configuration

Authoritative entry: ../apps.json["dvwa"]. Do not duplicate it here - if
the two drift, the corpus is wrong. The apps.json entry sets
security_level: "low" and includes the two-step login
(/login.php -> /security.php) needed to reach the injectable endpoints.

## Cases

Row sources in ../cases.csv with app=dvwa. All live at security_level=low;
the runner relies on the login flow above to put the session there.