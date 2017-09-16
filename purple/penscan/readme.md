To run, ```./gradlew run```.

To test, ```./gradlew test```.

To use on prod, add ```penscan-ext.properties``` with the following properties set
```
jiraHost
jiraPassword
jiraUsername
```

Then, ```./gradlew run```.

To use with your own credentials on UAT, add ```penscan-ext.properties``` with the following properties set
```
jiraPassword
jiraUsername
```
Then, ```./gradlew run```.