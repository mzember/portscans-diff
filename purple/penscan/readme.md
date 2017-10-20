To run:

```./gradlew run```

To run, testing a single vulnerability:

```./gradlew run -Pvulnerability=LSV-0```

To run, testing all host vulnerabilities associated with a ticket:

```./gradlew rescan -Pticket=LRINFOSEC-0```

To run, testing a single vulnerability associated with a ticket:

```./gradlew rescan -Pticket=LRINFOSEC-0 -Pvulnerability=LSV-0```

To test:

```./gradlew test```

Create ```penscan-ext.properties``` with:
```
jiraHost=
jiraPassword=
jiraUsername=
```