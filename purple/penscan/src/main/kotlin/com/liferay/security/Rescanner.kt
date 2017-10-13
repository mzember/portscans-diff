package com.liferay.security

import com.liferay.security.jira.*
import com.liferay.security.util.*

import java.io.File
import java.util.Properties
import java.util.logging.Logger

import org.json.JSONObject

fun main(args: Array<String>) {
	if (args.isEmpty()) {
		println("You must specify a JIRA ticket. For example: \"-Pticket=LRIS-123\"")

		return
	}

	val properties = Properties()

	val propertiesFile = File("penscan.properties")

	properties.load(propertiesFile.inputStream())

	loadExtProperties(properties, propertiesFile)

	val rescanner = Rescanner(properties = properties)

	rescanner.rescan(args[0])
}

private fun loadExtProperties(properties: Properties, propertiesFile: File) {
	val propertiesFilePath = propertiesFile.path

	val propertiesExtFilePath = propertiesFilePath.replace(Regex("\\.properties$"), "-ext.properties")

	val propertiesExtFile = File(propertiesExtFilePath)

	if (propertiesExtFile.exists()) {
		properties.load(propertiesExtFile.inputStream())
	}
}

class Rescanner(properties: Properties = Properties()) {
	companion object {
		val logger = Logger.getLogger(Rescanner::javaClass.name)!!
	}

	val properties = Properties()

	init {
		logger.fine("")

		(this.properties).putAll(properties)
	}

	val jiraRestUtil = JiraRestUtil(properties = properties)

	fun rescan(issueKey: String) {
		val issueJSONObject = jiraRestUtil.getIssueJSONObject(issueKey)

		val issueHostVulnerabilities = processJiraIssue(issueJSONObject)

		val issueHostVulnerabilitiesJSONObject = JSONObject(issueHostVulnerabilities)

		println(issueHostVulnerabilitiesJSONObject.toString(4))
	}

	fun processJiraIssue(jiraIssueJSONObject: JSONObject): MutableMap<String, MutableList<String>> {
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

				val vulnerabilityDetectionFile = getResourceFile(RESOURCE_LIFERAY_VULNERABILITIES_PATH, vulnerability)

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