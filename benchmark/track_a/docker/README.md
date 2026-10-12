# Track A target container

## Image

`janissary/owasp-benchmark:20cbf3d-ldapfix`

Derived from `janissary/owasp-benchmark:20cbf3d` (built 2026-09-28) with two
entrypoint fixes applied and committed:

1. **HSQLDB schema init.** The upstream entrypoint ran
   `mvn antrun:run@database-init -DskipTests` with no active Maven profile.
   The `database-init` execution is defined only inside `deploy*` profiles
   in `pom.xml`, so without `-P` Maven silently no-ops and the HSQLDB
   stored procedures used by `sqli-*` tests are never created. The
   container now runs `mvn -q -Pdeploywhcl antrun:run@database-init`.

2. **LDAPServer startup.** The upstream entrypoint never started the
   embedded ApacheDS instance. Every `ldapi-*` endpoint failed with
   `javax.naming.CommunicationException: localhost:10389 [Connection
   refused]` on every request, including baseline. The container now
   starts LDAPServer as a background daemon on port 10389 and waits
   for the port to bind before starting Tomcat.

## Entrypoint

The container's `/entrypoint.sh` is version-controlled at
`benchmark/track_a/docker/entrypoint.sh`. To regenerate the image from
a fresh base:

    docker run -d --name janissary-owasp -p 8080:8080 janissary/owasp-benchmark:20cbf3d
    docker cp benchmark/track_a/docker/entrypoint.sh janissary-owasp:/entrypoint.sh
    docker exec janissary-owasp bash -c "sed -i \"s/\\r$//\" /entrypoint.sh; chmod +x /entrypoint.sh"
    docker commit --change 'ENTRYPOINT [\"/entrypoint.sh\"]' janissary-owasp janissary/owasp-benchmark:20cbf3d-ldapfix

## Startup sequence

1. HSQLDB started in background, port 9001
2. `mvn -Pdeploywhcl antrun:run@database-init` creates stored procedures
3. LDAPServer started in background, port 10389
4. Tomcat started on 0.0.0.0:8080
5. 2740 servlets deployed (~3 minutes)

## Verification

    docker exec janissary-owasp bash -c "(exec 3<>/dev/tcp/localhost/10389) 2>/dev/null && echo OPEN 10389 || echo CLOSED 10389"
    docker exec janissary-owasp bash -c "(exec 3<>/dev/tcp/localhost/8080) 2>/dev/null && echo OPEN 8080 || echo CLOSED 8080"
    curl.exe -s -o NUL -w "%{http_code}\n" "http://127.0.0.1:8080/benchmark/ldapi-00/BenchmarkTest00021?BenchmarkTest00021=JNSRY"

Both ports must be OPEN and the curl must return 200 before any Track A
run. If either check fails, the container is dead — restart it and wait
240 seconds before retrying.
