package com.liferay.security

import java.util.Properties
import java.util.logging.Logger

import org.json.JSONObject

import getIssueJSONObject
import getProperties
import getResourceFile
import isVulnerable

fun main(args: Array<String>) {
	if (args.isEmpty()) {
		println("You must specify a JIRA ticket. For example: \"-Pticket=LRINFOSEC-123\"")

		return
	}

	val properties = getProperties("penscan.properties")

	val rescanner = Rescanner(properties)

	rescanner.rescan(args[0])
}

class Rescanner(properties: Properties = Properties()) {
	companion object {
		val logger = Logger.getLogger(Rescanner::javaClass.name)!!
	}

	private val properties = Properties()

	init {
		logger.fine("")

		(this.properties).putAll(properties)
	}

	fun rescan(issueKey: String) {
		logger.info("")

		val jiraHost: String by properties
		val jiraPassword: String by properties
		val jiraUsername: String by properties

		val issueJSONObject = getIssueJSONObject(issueKey, jiraHost, jiraPassword, jiraUsername)

		val issueHostVulnerabilities = getIssueHostVulnerabilities(issueJSONObject)

		val issueHostVulnerabilitiesJSONObject = JSONObject(issueHostVulnerabilities)

		println(issueHostVulnerabilitiesJSONObject.toString(4))
	}

	private fun getIssueHostVulnerabilities(jiraIssueJSONObject: JSONObject): MutableMap<String, MutableList<String>> {
		logger.fine("")

		val hostVulnerabilities = mutableMapOf<String, MutableList<String>>()

		val fieldsJSONObject = jiraIssueJSONObject.getJSONObject("fields")

		val jiraTicketScriptLabelsCustomFieldId: String by properties

		val labelsJSONArray = fieldsJSONObject.getJSONArray("customfield_$jiraTicketScriptLabelsCustomFieldId")

		for (labelJSONString in labelsJSONArray) {
			val label = (labelJSONString as String)

			if (label.startsWith(LABEL_VULNERABLE_HOST_PREFIX)) {
				val hostVulnerability = label.substring(LABEL_VULNERABLE_HOST_PREFIX.length)

				val hostVulnerabilityArray = hostVulnerability.split(";")

				val host = hostVulnerabilityArray[0]
				val vulnerability = hostVulnerabilityArray[1]

				val vulnerabilityDetectionFile = getResourceFile(vulnerability, RESOURCE_LIFERAY_VULNERABILITIES_PATH)

				if (isVulnerable(host, vulnerabilityDetectionFile.path)) {
					if (hostVulnerabilities.containsKey(host)) {
						val vulnerabilities = hostVulnerabilities[host]!!

						vulnerabilities.add(vulnerability)
					}
					else {
						hostVulnerabilities.put(host, mutableListOf(vulnerability))
					}
				}
			}
		}

		return hostVulnerabilities
	}
}