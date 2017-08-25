@file:Suppress("FoldInitializerAndIfToElvis", "LoopToCallChain")

package com.liferay.security

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.logging.Logger
import java.util.Properties
import javax.script.ScriptEngineManager
import pl.allegro.finance.tradukisto.ValueConverters

fun main(args: Array<String>) {
	val properties = Properties()

	val propertiesFile = File("penscan.properties")

	properties.load(propertiesFile.inputStream())

	loadExtProperties(properties, propertiesFile)

	val penscan = Penscan(properties = properties)

	penscan.penscan()
}

private fun loadExtProperties(properties: Properties, propertiesFile: File) {
	val propertiesFilePath = propertiesFile.path

	val propertiesExtFilePath = propertiesFilePath.replace(Regex("\\.properties$"), "-ext.properties")

	val propertiesExtFile = File(propertiesExtFilePath)

	if (propertiesExtFile.exists()) {
		properties.load(propertiesExtFile.inputStream())
	}
}

class Penscan(data: MutableList<MutableMap<String, Any>> = mutableListOf<MutableMap<String, Any>>(), properties: Properties = Properties()) {
	companion object {
		val logger = Logger.getLogger(Penscan::javaClass.name)!!
	}

	val data = mutableListOf<MutableMap<String, Any>>()
	val properties = Properties()

	init {
		logger.info("")

		(this.data).addAll(data)
		(this.properties).putAll(properties)
	}

	fun createIssue(assignee: String, description: String, scriptLabels: List<String>, summary: String): String {
		logger.info("")

		val jiraPassword: String by properties
		val jiraUsername: String by properties

		val jiraHost: String by properties

		val jiraUrl = "https://$jiraHost/rest/api/2/issue"

		val args = mutableListOf("--silent", "--user", "$jiraUsername:$jiraPassword", "--header", "Content-Type: application/json", jiraUrl)

		val jiraProjectComponent: String by properties
		val jiraProjectKey: String by properties
		val jiraTicketIssueType: String by properties
		val jiraTicketScriptLabelsCustomFieldId: String by properties

		val scriptLabelsString = scriptLabels.joinToString("\",\"")

		val data = listOf("--data", """{"fields":{"project":{"key":"$jiraProjectKey"},"components":[{"name":"$jiraProjectComponent"}],"assignee":{"name":"$assignee"},"summary":"$summary","description":"$description","issuetype":{"name":"$jiraTicketIssueType"},"customfield_$jiraTicketScriptLabelsCustomFieldId":["$scriptLabelsString"]}}""")

		args.addAll(data)

		val byteArrayOutputStream = ByteArrayOutputStream()

		exec("curl", args, standardOutput = byteArrayOutputStream, skipPrintCommandLine = true)

		val byteArrayOutputString = byteArrayOutputStream.toString()

		val jsonObject = JSONObject(byteArrayOutputString)

		val jiraTicket = jsonObject.get("key")

		return jiraTicket as String
	}

	fun createTickets(data: MutableList<MutableMap<String, Any>> = this.data) {
		logger.info("")

		val jiraHost: String by properties

		val tickets = mutableListOf<String>()

		findNewVulnerabilities()

		val scanDate = Date()

		val scanID = SimpleDateFormat("yyyyMMddHHmmss").format(scanDate)

		val jiraTicketScriptLabelTool: String by properties
		val jiraTicketScriptLabelToolVersion: String by properties
		val jiraTicketScriptLabelType: String by properties

		val defaultScriptLabels = mutableListOf("type:$jiraTicketScriptLabelType", "tool:$jiraTicketScriptLabelTool", "tool-version:$jiraTicketScriptLabelToolVersion", "scanID:$scanID")

		val selectOwners = selectValue(data, "owner")

		val owners = selectOwners.distinct()

		for (owner in owners) {
			owner as String

			val newHostVulnerabilities = mutableMapOf<String, MutableList<String>>()

			val hosts = mutableSetOf<String>()

			val vulnerabilityTickets = mutableSetOf<String>()

			val scriptLabels = mutableListOf<String>()

			val ownersData = lookupList(data, "owner", owner)

			for (ownersDatum in ownersData) {
				var hostBestKey = "name"

				if (!ownersDatum.containsKey(hostBestKey)) {
					hostBestKey = "ip"
				}

				val host = (ownersDatum[hostBestKey] as String)

				val vulnerabilitiesData = (ownersDatum["vulnerabilities"] as MutableList<*>)

				for (vulnerabilitiesDatum in vulnerabilitiesData) {
					vulnerabilitiesDatum as MutableMap<*, *>

					if (vulnerabilitiesDatum["new"] == "yes") {
						val vulnerabilityName = (vulnerabilitiesDatum["name"] as String)

						logger.info("$host vulnerable to $vulnerabilityName")

						val scriptLabel = "host-vulnerability:$host;$vulnerabilityName"

						scriptLabels.add(scriptLabel)

						hosts.add(host)

						vulnerabilityTickets.add(vulnerabilityName)

						if (!newHostVulnerabilities.containsKey(host)) {
							newHostVulnerabilities.put(host, mutableListOf(vulnerabilityName))
						}
						else {
							val hostVulnerabilityTickets = newHostVulnerabilities[host]!!

							hostVulnerabilityTickets.add(vulnerabilityName)
						}
					}
				}
			}

			if (scriptLabels.isEmpty()) {
				continue
			}

			scriptLabels.addAll(defaultScriptLabels)

			var assignee = owner

			if (owner == "unassigned") {
				assignee = ""
			}

			val description = buildDescription(vulnerabilityTickets, hosts, newHostVulnerabilities, scanDate)

			val summary = buildSummary(vulnerabilityTickets, hosts, assignee)

			val issue = createIssue(assignee, description, scriptLabels, summary)

			logger.info("Created issue https://$jiraHost/browse/$issue")

			tickets.add(issue)
		}

		if (!tickets.isEmpty()) {
			val jiraTicketScriptLabelsCustomFieldId: String by properties

			logger.info("${tickets.size} issues created.")
			logger.info("View the issues created here: https://$jiraHost/issues/?jql=cf%5B$jiraTicketScriptLabelsCustomFieldId%5D%20%3D%20scanID%3A$scanID")
		}
	}

	fun buildDescription(vulnerabilityTickets: MutableSet<String>, hosts: MutableSet<String>, newHostVulnerabilities: MutableMap<String, MutableList<String>>, scanDate: Date): String {
		val jiraTicketDescriptionPrefix: String by properties

		var description = jiraTicketDescriptionPrefix + "||host||"

		val vulnerabilityTicketsSorted = vulnerabilityTickets.sorted()

		for (vulnerabilityTicket in vulnerabilityTicketsSorted) {
			description += "$vulnerabilityTicket||"
		}

		description += "\\n"

		val hostsSorted = hosts.sorted()

		for (host in hostsSorted) {
			description += "|[http://$host]|"

			val vulnerabilities = (newHostVulnerabilities[host] as List<String>)

			for (vulnerabilityTicket in vulnerabilityTicketsSorted) {
				if (vulnerabilities.contains(vulnerabilityTicket)) {
					description += "* |"
				}
				else {
					description += " |"
				}
			}

			description += "\\n"
		}

		description += "\\n"

		val calendar = Calendar.getInstance()

		calendar.time = scanDate

		calendar.add(Calendar.DAY_OF_YEAR, Integer.parseInt("14"))

		val twoWeeksTime = calendar.time

		val recycleCandidateDate = SimpleDateFormat("EEEE, MMMM dd, yyyy").format(twoWeeksTime)

		description += "If you don't respond to us on this ticket within two weeks (by $recycleCandidateDate), the above VM resources will be deactivated until the issue can be resolved.\\n"
		return description
	}

	fun buildSummary(vulnerabilityTickets: MutableSet<String>, hosts: MutableSet<String>, assignee: String): String {
		val vulnerabilitySize = vulnerabilityTickets.size

		var vulnerabilityWords = "vulnerability was"

		if (vulnerabilitySize > 1) {
			vulnerabilityWords = "vulnerabilities were"
		}

		val vulnerabilitySizeWords = ValueConverters.ENGLISH_INTEGER.asWords(vulnerabilitySize)

		val hostSize = hosts.size

		var hostWord = "host"

		if (hostSize > 1) {
			hostWord = "hosts"
		}

		val hostSizeWords = ValueConverters.ENGLISH_INTEGER.asWords(hostSize)

		var summaryOwner = "no one"

		if (assignee != "") {
			val (firstName, secondName) = assignee.split(".")

			summaryOwner = "${firstName.capitalize()} ${secondName.capitalize()}"
		}

		val summary = "${vulnerabilitySizeWords.capitalize()} $vulnerabilityWords found on $hostSizeWords $hostWord owned by $summaryOwner"

		return summary
	}

	fun detectVulnerabilities(data: MutableList<MutableMap<String, Any>> = this.data) {
		logger.info("")

		val classLoader = javaClass.classLoader

		val liferayVulnerabilitiesURL = classLoader.getResource("vulnerabilities/liferay")!!

		val liferayVulnerabilitiesDir = File(liferayVulnerabilitiesURL.file)

		val liferayVulnerabilityFiles = liferayVulnerabilitiesDir.listFiles()

		for (datum in data) {
			val vulnerabilities = mutableListOf<MutableMap<String, String>>()

			var hostBestKey = "name"

			if (!datum.containsKey(hostBestKey) || (datum[hostBestKey] == "")) {
				hostBestKey = "ip"
			}

			val datumBestKeyValue = datum[hostBestKey] as String

			for (liferayVulnerabilityFile in liferayVulnerabilityFiles) {
				val vulnerabilityFileNameRegex = Regex("([A-Z]+-[0-9]+)\\..*")

				val matchResult = vulnerabilityFileNameRegex.matchEntire(liferayVulnerabilityFile.name)

				val (vulnerabilityTicket) = matchResult!!.destructured

				val exitValue = exec(
					executable = "sh",
					args = listOf(liferayVulnerabilityFile.path, datumBestKeyValue),
					exceptionOnExitValue = false,
					skipPrintCommandLine = true)

				val vulnerable: String

				if (exitValue == 0) {
					vulnerable = "yes"
				}
				else {
					vulnerable = "no"
				}

				vulnerabilities.add(mutableMapOf("name" to vulnerabilityTicket, "vulnerable" to vulnerable))
			}

			datum.put("vulnerabilities", vulnerabilities)
		}
	}

	fun findNewVulnerabilities(data: MutableList<MutableMap<String, Any>> = this.data) {
		logger.info("")

		val jiraHost: String by properties
		val jiraPassword: String by properties
		val jiraUsername: String by properties

		val knownVulnerabilitiesJSONObject = getKnownVulnerabilitiesJSONObject(jiraHost, jiraPassword, jiraUsername)

		val selectOwners = selectValue(data, "owner")

		val owners = selectOwners.distinct()

		for (owner in owners) {
			val ownerData = lookupList(data, "owner", owner)

			for (ownerDatum in ownerData) {
				val name = ownerDatum["name"] as String

				val knownVulnerabilities = getKnownVulnerabilities(name, knownVulnerabilitiesJSONObject)

				val vulnerabilitiesData = (ownerDatum["vulnerabilities"] as MutableList<*>)

				for (vulnerability in vulnerabilitiesData) {
					@Suppress("UNCHECKED_CAST")
					vulnerability as MutableMap<String, Any>

					val vulnerabilityName = vulnerability["name"]

					if (vulnerability["vulnerable"] != "yes") {
						vulnerability["new"] = "not-applicable"

						continue
					}

					for (knownVulnerability in knownVulnerabilities) {
						if (vulnerabilityName == knownVulnerability) {
							vulnerability["new"] = "no"

							break
						}
					}

					if (!vulnerability.containsKey("new")) {
						vulnerability["new"] = "yes"
					}
				}
			}
		}
	}

	fun getExtIpNameStatusMaps(data: MutableList<MutableMap<String, Any>> = this.data) {
		logger.info("")

		val scriptEngineManager = ScriptEngineManager()

		val ktsEngine = scriptEngineManager.getEngineByExtension("kts")

		val classLoader = javaClass.classLoader

		val listOfIpNameStatusMapsURL = classLoader.getResource("data/listOfIpNameStatusMaps.kts")!!

		val listOfIpNameStatusMapsFile = File(listOfIpNameStatusMapsURL.file)

		val listOfIpNameStatusMapsText = listOfIpNameStatusMapsFile.readText()

		@Suppress("UNCHECKED_CAST")
		val listOfNameOwnerMaps = (ktsEngine.eval(listOfIpNameStatusMapsText) as MutableList<MutableMap<String, Any>>)

		data.addAll(listOfNameOwnerMaps)
	}

	fun getIpNameStatus(data: MutableList<MutableMap<String, Any>> = this.data) {
		logger.info("")

		val pingScanOutputFile = File("pingScanOutput.gnmap")

		val nmapTargetSpecificationFile = File("nmapTargetSpecification")

		val byteArrayOutputStream = ByteArrayOutputStream()

		exec("nmap", listOf("-oG", pingScanOutputFile.path, "-iL", nmapTargetSpecificationFile.path, "-sn"), standardOutput = byteArrayOutputStream)

		val ipNameStatusMaps = getIpNameStatusMaps(pingScanOutputFile)

		normalizeNames(ipNameStatusMaps)

		getExtIpNameStatusMaps(data)

		data.addAll(ipNameStatusMaps)
	}

	fun getIpNameStatusMaps(pingScanOutputFile: File): MutableList<MutableMap<String, Any>> {
		val ipNameStatusMaps = mutableListOf<MutableMap<String, Any>>()

		val pingScanGreppableOutputLineRegex = Regex("^Host: (.*) \\((.*)\\)\\tStatus: (.*)$")

		val pingScanOutputLines = pingScanOutputFile.readLines()

		for (pingScanOutputLine in pingScanOutputLines) {
			val matchResult = pingScanGreppableOutputLineRegex.matchEntire(pingScanOutputLine)

			if (matchResult == null) {
				continue
			}

			val (ip, name, status) = matchResult.destructured

			val ipNameStatusMap = hashMapOf<String, Any>(
				"ip" to ip,
				"name" to name,
				"status" to status)

			ipNameStatusMaps.add(ipNameStatusMap)
		}

		return ipNameStatusMaps
	}

	fun getKnownVulnerabilities(name: String, responseJSONObject: JSONObject): MutableList<String> {
		val vulnerabilities = mutableListOf<String>()

		val issuesJSONArray = JSONArray(responseJSONObject.get("issues").toString())

		for (issue in issuesJSONArray) {
			val issueJSONObject = (issue as JSONObject)

			val issueFieldsJSONObject = issueJSONObject.get("fields") as JSONObject

			val customfield_19627JSONObject = issueFieldsJSONObject.get("customfield_19627")

			@Suppress("UNCHECKED_CAST")
			val issueLabels = (customfield_19627JSONObject as JSONArray).toList() as List<String>

			for (issueLabel in issueLabels) {
				val hostVulnerabilityLabelRegex = Regex("^host-vulnerability:(.*);(.*)$")

				val matchResult = hostVulnerabilityLabelRegex.matchEntire(issueLabel)

				if (matchResult == null) {
					continue
				}

				val (host, vulnerability) = matchResult.destructured

				if (host != name) {
					continue
				}

				vulnerabilities.add(vulnerability)
			}
		}

		return vulnerabilities
	}

	fun getKnownVulnerabilitiesJSONObject(host: String, password: String, user: String): JSONObject {
		val url = """https://$host/rest/api/2/search?jql=cf\[19627\]%20in%20("scan:owner-host-vulnerabilities","type:generated")%20and%20status%20not%20in%20(closed)"""

		val byteArrayOutputStream = ByteArrayOutputStream()

		exec("curl", listOf("--silent", "--user", "$user:$password", "--header", "Content-Type: application/json", url), standardOutput = byteArrayOutputStream)

		val byteArrayOutputString = byteArrayOutputStream.toString()

		return JSONObject(byteArrayOutputString)
	}

	fun getOwners(data: MutableList<MutableMap<String, Any>> = this.data) {
		logger.info("")

		val scriptEngineManager = ScriptEngineManager()

		val ktsEngine = scriptEngineManager.getEngineByExtension("kts")

		val classLoader = javaClass.classLoader

		val listOfNameOwnerMapsKtsURL = classLoader.getResource("data/listOfNameOwnerMaps.kts")!!

		val listOfNameOwnerMapsKtsFile = File(listOfNameOwnerMapsKtsURL.file)

		val listOfNameOwnerMapsKtsFileText = listOfNameOwnerMapsKtsFile.readText()

		val listOfNameOwnerMaps = (ktsEngine.eval(listOfNameOwnerMapsKtsFileText) as List<*>)

		for (nameOwner in listOfNameOwnerMaps) {
			val nameOwnerMap = (nameOwner as Map<*, *>)

			val nameValue = nameOwnerMap["name"] as String

			val ownerValue = nameOwnerMap["owner"] as String

			insert(data, "name", nameValue, mapOf("owner" to ownerValue))
		}

		for (datum in data) {
			if (datum.containsKey("owner")) {
				continue
			}

			datum["owner"] = "unassigned"
		}
	}

	fun getTargets(data: MutableList<MutableMap<String, Any>> = this.data) {
		logger.info("")

		getIpNameStatus(data)
	}

	fun insert(data: MutableList<MutableMap<String, Any>> = this.data, keyName: String, keyValue: String, valueMap: Map<String, String>) {
		loop@
		for (datum in data) {
			for ((key, value) in datum) {
				if (key == keyName && value == keyValue) {
					datum.putAll(valueMap)

					break@loop
				}
			}
		}
	}

	fun lookupList(data: MutableList<MutableMap<String, Any>> = this.data, keyName: String, keyValue: Any): MutableList<MutableMap<String, Any>> {
		val list = mutableListOf<MutableMap<String, Any>>()

		loop@
		for (datum in data) {
			for ((key, value) in datum) {
				if ((key == keyName) && (value == keyValue)) {
					list.add(datum)
				}
			}
		}

		return list
	}

	fun normalizeNames(ipNameStatusMaps: MutableList<MutableMap<String, Any>>) {
		for (ipNameStatusMap in ipNameStatusMaps) {
			var name = ipNameStatusMap["name"] as String

			val normalizedNameValueRegex = Regex("^(.*)\\.lax\\.liferay\\.com")

			val matchResult = normalizedNameValueRegex.matchEntire(name)

			if (matchResult != null) {
				val matchResultValues = matchResult.groupValues

				name = matchResultValues[1]

				ipNameStatusMap.put("name", name)
			}
		}
	}

	fun penscan() {
		getTargets()
		getOwners()
		detectVulnerabilities()
		createTickets()
	}

	fun selectValue(data: MutableList<MutableMap<String, Any>> = this.data, keyName: String): MutableList<Any> {
		val list = mutableListOf<Any>()

		loop@
		for (datum in data) {
			for ((key, value) in datum) {
				if (key == keyName) {
					list.add(value)
				}
			}
		}

		return list
	}
}