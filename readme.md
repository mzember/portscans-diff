# Readme

## How to

### Local Testing

* ./gradlew test --tests *"do not allow log in to host"
* ./gradlew test --tests *"do not allow vm owner"

### Generate src/main/resources/sites file

* ./gradlew generateResourceSites

### Update Jenkins jobs on cloud-10-50-0-251

* ./gradlew -p jenkins/ updateJenkinsItems"lfris-security"