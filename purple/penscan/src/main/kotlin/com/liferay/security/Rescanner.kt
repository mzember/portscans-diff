package com.liferay.security

import com.liferay.security.jira.*
import org.json.JSONObject

import java.io.File
import java.util.Properties
import java.util.logging.Logger

val LABEL_VULNERABLE_HOST_PREFIX = "host-vulnerability:"

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

	val jiraRestUtil = JiraRestUtil(properties = properties)

	fun rescan(issueKey: String) {
		val issueJSONObject = jiraRestUtil.getIssueJSONObject(issueKey)

		val issueHostVulnerabilities = processJiraIssueJSONObject(issueJSONObject)
	}

	fun processJiraIssueJSONObject(jiraIssueJSONObject: JSONObject): MutableMap<String, MutableList<String>> {
		val hostVulnerabilities = mutableMapOf<String, MutableList<String>>()

		val fieldsJSONObject = jiraIssueJSONObject.getJSONObject("fields")

		val labelsJSONArray = fieldsJSONObject.getJSONArray("labels")

		for (i in 0..labelsJSONArray!!.length() - 1) {
			val label = labelsJSONArray.getString(i)

			if (label.startsWith(LABEL_VULNERABLE_HOST_PREFIX)) {
				val hostVulnerability = label.substring(LABEL_VULNERABLE_HOST_PREFIX.length)

				val hostVulnerabilityArray = hostVulnerability.split(";")

				val host = hostVulnerabilityArray[0]
				val vulnerability = hostVulnerabilityArray[1]

				if (hostVulnerabilities.containsKey(host)) {
					val vulnerabilities = hostVulnerabilities[host]!!

					vulnerabilities.add(vulnerability)
				}
				else {
					hostVulnerabilities.put(host, mutableListOf(vulnerability))
				}
			}
		}

		return hostVulnerabilities
	}
}