package com.liferay.security

import java.util.Properties
import java.util.logging.Logger

import org.json.JSONObject

fun main(args: Array<String>) {
	if (args.isEmpty()) {
		println("You must specify a JIRA ticket. For example: \"-Pticket=LRINFOSEC-123\"")

		return
	}

	val properties = getProperties("penscan.properties")

	if ((args.size % 2) != 0) {
		throw Exception("Bad args")
	}

	var i = 0

	while (i < args.size) {
		properties.setProperty(args[i], args[i + 1])

		i += 2
	}

	val rescanner = Rescanner(properties)

	rescanner.rescan()
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

	fun rescan() {
		logger.info("")

		val ticket: String by properties
		val jiraHost: String by properties
		val jiraPassword: String by properties
		val jiraUsername: String by properties

		val issueJSONObject = getIssueJSONObject(ticket, jiraHost, jiraPassword, jiraUsername)

		val issueHostVulnerabilities = getIssueHostVulnerabilities(issueJSONObject)

		println("{panel:title=Rescan Vulnerabilities}")

		for ((key, value) in issueHostVulnerabilities.toSortedMap()) {
			value.sort()

			val valueString = value.joinToString("], [", "[", "]")

			println("$key: $valueString")
		}

		println("{panel}")
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
				val vulnerability = getActualVulnerability(hostVulnerabilityArray[1])

				val rescanVulnerability = properties.getProperty("vulnerability")

				if (!rescanVulnerability.isNullOrEmpty() && (rescanVulnerability != vulnerability)) {
					continue
				}

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