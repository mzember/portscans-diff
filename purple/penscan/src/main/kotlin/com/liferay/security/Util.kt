@file:Suppress("LiftReturnOrAssignment")

package com.liferay.security

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.util.Properties

import org.json.JSONObject

fun getActualVulnerability(vulnerability: String): String {
	if (vulnerability == "LSV-322") {
		return "LSV-329"
	}

	return vulnerability
}

fun getIssueJSONObject(issueKey: String, jiraHost: String, jiraPassword: String, jiraUsername: String): JSONObject {
	val url = "https://$jiraHost/rest/api/2/issue/$issueKey"

	val byteArrayOutputStream = ByteArrayOutputStream()

	exec("curl", listOf("--silent", "--user", "$jiraUsername:$jiraPassword", "--header", "Content-Type: application/json", url), standardOutput = byteArrayOutputStream, skipPrintCommandLine = true)

	val jsonObject = JSONObject(byteArrayOutputStream.toString())

	if (jsonObject.has("errorMessages")) {
		val jsonArray = jsonObject.getJSONArray("errorMessages")

		throw Exception(jsonArray.toString())
	}

	return jsonObject
}

fun getProperties(propertiesFileName: String): Properties {
	val properties = Properties()

	val propertiesFile = File(propertiesFileName)

	properties.load(propertiesFile.inputStream())

	loadExtProperties(properties, propertiesFile)

	return properties
}

fun getResourceDir(resourcePath: String): File {
	val classLoader = object {}.javaClass.classLoader

	val resourceURL = classLoader.getResource(resourcePath)!!

	return File(resourceURL.file)
}

fun getResourceFile(fileNameWithoutExtension: String, resourcePath: String): File {
	val resourceDir = getResourceDir(resourcePath)

	val resourceFiles = resourceDir.listFiles()

	for (resourceFile in resourceFiles) {
		var fileName = resourceFile.name

		val pos = fileName.lastIndexOf(".")

		if (pos > 0) {
			fileName = fileName.substring(0, pos)
		}

		if (fileName == fileNameWithoutExtension) {
			return resourceFile
		}
	}

	throw FileNotFoundException("Unable to find $fileNameWithoutExtension in $resourcePath")
}

fun isVulnerable(host: String, vulnerabilityDetectionFilePath: String): Boolean {
	val exitValue = exec("sh", listOf(vulnerabilityDetectionFilePath, host), exceptionOnExitValue = false, skipPrintCommandLine = true)

	if (exitValue == 0) {
		return true
	}
	else {
		return false
	}
}

private fun loadExtProperties(properties: Properties, propertiesFile: File) {
	val propertiesFilePath = propertiesFile.path

	val propertiesExtFilePath = propertiesFilePath.replace(Regex("\\.properties$"), "-ext.properties")

	val propertiesExtFile = File(propertiesExtFilePath)

	if (propertiesExtFile.exists()) {
		properties.load(propertiesExtFile.inputStream())
	}
}