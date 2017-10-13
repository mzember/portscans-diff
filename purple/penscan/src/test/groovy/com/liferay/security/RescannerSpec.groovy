package com.liferay.security

import org.json.JSONObject
import spock.lang.Specification

class RescannerSpec extends Specification {

	def "processJiraIssueJSONObject"() {
		setup:
		Properties properties = new Properties()

		properties.put("jiraTicketScriptLabelsCustomFieldId", "19627")

		def rescanner = new Rescanner(properties)

		when:
		def issueJSONObjectStringFile = new File(this.getClass().classLoader.getResource("processJiraIssueJSONObjectString").file)

		def issueJSONObject = new JSONObject(issueJSONObjectStringFile.text)

		def hostsVulnerabilities = rescanner.processJiraIssue(issueJSONObject)

		then:
		hostsVulnerabilities == [
			"cloud-10-1-0-13":
				["LSV-278", "LSV-322"],
			"cloud-10-50-0-230":
				["LSV-322"]]
	}

}