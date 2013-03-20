To use access valve with Tomcat (6.0.26)

```bash
mvn package
cp target/  x-forwarded-for-remote-address-filter-<version>.jar $CATALINA_HOME/lib
```

Locate file containing value org.apache.catalina.valves.AccessLogValve in either $CATALINA_HOME
or $CATALINA_BASE and change to package containing AccessLogValve, e.g org.evildethow.valves.AccessLogValve.