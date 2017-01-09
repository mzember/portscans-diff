Veracode Documentation
======================

## Quarterly Scanning
**Steps:**

1. email Peter Shin (peter.shin@liferay.com) to update the database for www-veracode.liferay.com
   * if necessary, ask what day the database dump is from and make sure to update the ticket (should usually be on the latest UAT environment)
   * in order to make sure marketplace client is pointing to itself, the marketplace portlet-ext.properties should set the following (this is most likely already set by default): `marketplace.url=https://www-veracode.liferay.com`
   * navigate to Control Panel > Marketplace > Store, if marketplace set up does not appear, email Peter to update the marketplace plugin to the latest

2. check to see if the marketplace plugin on the Veracode server is running on the latest data
  * navigate to Marketplace Admin -> Apps -> sort by Modified Date
  * since the environment should be based off of UAT data, there should be QA marketplace apps seen

3. create a new user:
  * screenName: `security.user`
  * emailAddress: `security.user@liferay.com.broken`
  * password: `securitytest`
  * make sure to give them the "Verified User" role

4. navigate to OSB Admin -> Partners tab -> Add Partner -> SECURITYTEST1, US Support Region, phone number, an Address -> Save
5. search and click on SECURITYTEST1 partner, assign workers -> update associations for your new user
6. navigate to OSB Admin -> Projects tab -> Add Project -> SECURITYTEST code, Security Test Project Name, select an industry, put more than 0 Maximum Contacts, an Address -> Save
7. search and click on SECURITYTEST project, assign customers -> update associations for your new user
8. in the SECURITYTEST project, select View Orders button -> Add Order -> select SECURITYTEST project and purchase order -> Save -> go back to order page -> click on Add Offering Bundle -> select an offering bundle
9. register as a MP developer at www-veracode.liferay.com/marketplace/become-a-developer
  * signed up for individual developer account as it will auto-approve

10. sign in as the admin and navigate to Control Panel -> Sites -> Add Blank Site (make sure to add the user to this site) -> create a private site, SECURITYSITE -> navigate to the Site Pages for SECURITYSITE -> create a private page -> navigate to https://www-veracode.liferay.com/group/securitysite -> Add a Blogs Entry portlet to the page -> Add a new Entry with "Verification Text" in it
  * this step is needed for privileged user scan

11. sign into https://analysiscenter.veracode.com/# and Start a Scan -> select the liferay.com application -> in the Start a Scan drop down -> select Start a DynamicDS Scan -> check to make sure the target URL is correct -> skip, fill out, or change the contact info -> Save & Continue -> make sure required login is selected if doing privileged user scan
  * we normally do dynamic scans rather than static ones
  * if doing a privileged user scan, you will need a Selenium script to tell Veracode how to perform a sign in (step needed if last configuration script does not work in the pre-scan), see [Selenium Login](../../master/documentation/veracode.md#selenium-login) for the script example

12. once the pre-scan is successful, you can now schedule a scan
  * set to default 30-day scan unless instructed otherwise via security meeting or LRINFOSEC ticket

13. once scan has been complete, you should receive an email from Veracode
  * after security meeting discussion or analysis of the scans, create any necessary LRINFOSEC tickets for vulnerabilities we need to address


## Selenium Login
Following code may need to be updated.
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head profile="http://selenium-ide.openqa.org/profiles/test-case">
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<link rel="selenium.base" href="https://www-veracode.liferay.com" />
<title>www-veracode</title>
</head>
<body>
<table cellpadding="1" cellspacing="1" border="1">
<thead>
<tr><td rowspan="1" colspan="3">www-veracode</td></tr>
</thead><tbody>
<tr>
	<td>open</td>
	<td>/sign-in</td>
	<td></td>
</tr>
<tr>
	<td>type</td>
	<td>//input[@id='_58_login']</td>
	<td>security.user@liferay.com.broken</td>
</tr>
<tr>
	<td>type</td>
	<td>//input[@id='_58_password']</td>
	<td>securitytest</td>
</tr>
<tr>
	<td>clickAtAndWait</td>
	<td>//input[@value='Sign In']</td>
	<td></td>
</tr>

</tbody></table>
</body>
</html>
```