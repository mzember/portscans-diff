package com.liferay.security.jira

import com.liferay.security.*

import java.io.ByteArrayOutputStream
import java.util.Properties
import java.util.logging.Logger

import org.json.JSONObject

class JiraRestUtil(properties: Properties = Properties()) {
	companion object {
		val logger = Logger.getLogger(JiraRestUtil::javaClass.name)!!
	}

	val properties = Properties()

	init {
		(this.properties).putAll(properties)
	}

	fun getIssue(issueKey: String): JSONObject {
		val jiraHost: String by properties
		val jiraPassword: String by properties
		val jiraUsername: String by properties

		val url = "https://$jiraHost/rest/api/2/issue/$issueKey"

		val byteArrayOutputStream = ByteArrayOutputStream()

		exec("curl", listOf("--silent", "--user", "$jiraUsername:$jiraPassword", "--header", "Content-Type: application/json", url), standardOutput = byteArrayOutputStream, skipPrintCommandLine = true)

		val jsonObject = JSONObject(byteArrayOutputStream.toString())

		logger.finest(jsonObject.toString())

		if (jsonObject.has("errorMessages")) {
			val jsonArray = jsonObject.getJSONArray("errorMessages")

			throw Exception(jsonArray.toString())
		}

		return jsonObject
	}
}