#!/bin/bash
set -e

cd /owasp/BenchmarkJava

WAR=target/benchmark.war
if [ ! -f "$WAR" ]; then
  echo "[entrypoint] missing $WAR" >&2
  exit 1
fi

rm -rf "$CATALINA_HOME/webapps/benchmark" "$CATALINA_HOME/webapps/benchmark.war"

# Cargo's zip extraction does not preserve the +x bit on shell scripts.
chmod +x "$CATALINA_HOME/bin/"*.sh 2>/dev/null || true

echo "[entrypoint] starting HSQLDB in background"
HSQLDB_JAR=/root/.m2/repository/org/hsqldb/hsqldb/2.7.4/hsqldb-2.7.4.jar
if [ ! -f "$HSQLDB_JAR" ]; then
  echo "[entrypoint] missing $HSQLDB_JAR" >&2
  exit 1
fi
mkdir -p /owasp/BenchmarkJava/target/db
nohup java -cp "$HSQLDB_JAR" org.hsqldb.Server \
  --database.0 file:/owasp/BenchmarkJava/target/db/benchmarkDataBase \
  --dbname.0 benchmarkDataBase \
  --port 9001 > /tmp/hsqldb.log 2>&1 &
HSQLDB_PID=$!
echo "[entrypoint] HSQLDB PID=$HSQLDB_PID"

echo "[entrypoint] waiting for HSQLDB to bind :9001"
for i in $(seq 1 30); do
  if (exec 3<>/dev/tcp/localhost/9001) 2>/dev/null; then
    exec 3<&- 3>&-
    echo "[entrypoint] HSQLDB up after ${i}s"
    break
  fi
  sleep 1
done

echo "[entrypoint] initialising schema (via pom antrun task)"
mvn -q -Pdeploywhcl antrun:run@database-init -DskipTests

echo "[entrypoint] starting LDAPServer in background"
nohup java -cp 'target/classes:target/benchmark/WEB-INF/lib/*:target/benchmark/WEB-INF/classes' \
  org.owasp.benchmark.helpers.LDAPServer > /tmp/ldap.log 2>&1 &
LDAP_PID=$!
echo "[entrypoint] LDAPServer PID=$LDAP_PID"

echo "[entrypoint] waiting for LDAPServer to bind :10389"
for i in $(seq 1 60); do
  if (exec 3<>/dev/tcp/localhost/10389) 2>/dev/null; then
    exec 3<&- 3>&-
    echo "[entrypoint] LDAPServer up after ${i}s"
    break
  fi
  sleep 1
done

echo "[entrypoint] installing Tomcat config from src/config/local/"
cp src/config/local/server.xml  "$CATALINA_HOME/conf/server.xml"
cp src/config/local/context.xml "$CATALINA_HOME/conf/context.xml"

# The shipped server.xml binds HTTPS on 127.0.0.1:8443. We want plain
# HTTP on 0.0.0.0:8080 so the container port mapping works and clients
# outside the container can reach Tomcat.
sed -i 's|address="127.0.0.1" SSLEnabled="true"|address="0.0.0.0" SSLEnabled="false"|' "$CATALINA_HOME/conf/server.xml"
sed -i 's|port="8443"|port="8080"|g'                                                 "$CATALINA_HOME/conf/server.xml"
sed -i 's|scheme="https" secure="true" sslProtocol="TLS"|scheme="http" secure="false"|' "$CATALINA_HOME/conf/server.xml"
grep -q 'port="8080"' "$CATALINA_HOME/conf/server.xml"

echo "[entrypoint] copying WAR to $CATALINA_HOME/webapps/"
cp "$WAR" "$CATALINA_HOME/webapps/benchmark.war"

echo "[entrypoint] starting Tomcat 9.0.120 on port 8080 (JIT enabled)"
echo "[entrypoint] first boot takes 2-5 min: 2740 servlets to deploy"
exec "$CATALINA_HOME/bin/catalina.sh" run
