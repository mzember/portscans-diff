# Readme

## How to

### Local Testing

* ./gradlew test --tests \*LoginSpec\*do\ not\ allow\ log\ in\ to\ host\*
* ./gradlew test --tests \*UtilSpec\*do\ not\ allow\ vm\ owner\*

### Jenkins Testing

* Commit a change to a jenkins/jobs file and push to upstream master
* Wait a minute
* Go to http://cloud-10-50-0-251/
* On the left, click "Manage Jenkins"
* Click "Reload Configuration from Disk"
* Go to http://cloud-10-50-0-251/
* All jobs in jenkins/jobs should now be there