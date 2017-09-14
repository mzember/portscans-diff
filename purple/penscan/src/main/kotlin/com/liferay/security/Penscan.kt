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

	fun penscan() {
		aquireTargets()
		associateOwnersWithTargets()
		attemptVulnerabilityDetections()
		associateKnownVulnerabilitiesWithTargets()
		createJiraTicketsForNewVulnerabilities()
	}

	private fun attemptVulnerabilityDetections(data: MutableList<MutableMap<String, Any>> = this.data) {
		val liferayVulnerabilityDetectionFiles = getResourceNameFiles("vulnerabilities/liferay")

		checkAndSetVulnerabilitiesData(data, liferayVulnerabilityDetectionFiles)
	}

	private fun associateKnownVulnerabilitiesWithTargets(data: MutableList<MutableMap<String, Any>> = this.data) {
		logger.info("")

		val jiraHost: String by properties
		val jiraPassword: String by properties
		val jiraUsername: String by properties

		val knownVulnerabilitiesJSONObject = getKnownVulnerabilitiesJSONObject(jiraHost, jiraPassword, jiraUsername)

		val selectOwners = dataKeySelectValues(data, "owner")

		val owners = selectOwners.distinct()

		for (owner in owners) {
			val ownerData = dataKeyValueFetchData(data, "owner", owner)

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

	private fun associateOwnersWithTargets(data: MutableList<MutableMap<String, Any>> = this.data) {
		val nameOwnerMaps = getKtsResourceData("nameOwnerMaps.kts")

		setOwnersData(data, nameOwnerMaps)
	}

	private fun aquireTargets(data: MutableList<MutableMap<String, Any>> = this.data) {
		val nmapIpNameStatusMaps = getNmapIpNameStatusMaps()

		normalizeNmapIpNameStatusMaps(nmapIpNameStatusMaps)

		data.addAll(nmapIpNameStatusMaps)

		val ipNameStatusMapsExt = getKtsResourceData("ipNameStatusMaps-ext.kts")

		data.addAll(ipNameStatusMapsExt)
	}

	private fun checkAndSetVulnerabilitiesData(data: MutableList<MutableMap<String, Any>> = this.data, liferayVulnerabilityDetectionFiles: List<File>) {
		logger.info("")

		for (datum in data) {
			val vulnerabilities = mutableListOf<MutableMap<String, String>>()

			var hostBestKey = "name"

			if (!datum.containsKey(hostBestKey) || (datum[hostBestKey] == "")) {
				hostBestKey = "ip"
			}

			val hostBestKeyValue = datum[hostBestKey] as String

			for (liferayVulnerabilityDetectionFile in liferayVulnerabilityDetectionFiles) {
				val vulnerabilityDetectionFileNameRegex = Regex("([A-Z]+-[0-9]+)\\..*")

				val matchResult = vulnerabilityDetectionFileNameRegex.matchEntire(liferayVulnerabilityDetectionFile.name)

				val (vulnerabilityTicket) = matchResult!!.destructured

				val vulnerable: String

				if (checkVulnerability(hostBestKeyValue, liferayVulnerabilityDetectionFile.path)) {
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

	private fun checkVulnerability(host: String, vulnerabilityDetectionFilePath: String): Boolean {
		val exitValue = exec("sh", listOf(vulnerabilityDetectionFilePath, host), exceptionOnExitValue = false, skipPrintCommandLine = true)

		@Suppress("RedundantIf")
		if (exitValue == 0) {
			return true
		}
		else {
			return false
		}
	}

	private fun createJiraTicketsForNewVulnerabilities(data: MutableList<MutableMap<String, Any>> = this.data) {
		logger.info("")

		val jiraHost: String by properties

		val tickets = mutableListOf<String>()

		val scanDate = Date()

		val scanID = SimpleDateFormat("yyyyMMddHHmmss").format(scanDate)

		val jiraTicketScriptLabelTool: String by properties
		val jiraTicketScriptLabelToolVersion: String by properties
		val jiraTicketScriptLabelType: String by properties

		val defaultScriptLabels = mutableListOf("type:$jiraTicketScriptLabelType", "tool:$jiraTicketScriptLabelTool", "tool-version:$jiraTicketScriptLabelToolVersion", "scanID:$scanID")

		val selectOwners = dataKeySelectValues(data, "owner")

		val owners = selectOwners.distinct()

		for (owner in owners) {
			owner as String

			val newHostVulnerabilities = mutableMapOf<String, MutableList<String>>()

			val hosts = mutableSetOf<String>()

			val vulnerabilityTickets = mutableSetOf<String>()

			val scriptLabels = mutableListOf<String>()

			val ownersData = dataKeyValueFetchData(data, "owner", owner)

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

			val description = buildDescription(hosts, newHostVulnerabilities, scanDate, vulnerabilityTickets)

			val summary = buildSummary(assignee, hosts, vulnerabilityTickets)

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

	private fun createIssue(assignee: String, description: String, scriptLabels: List<String>, summary: String): String {
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

	private fun buildDescription(hosts: MutableSet<String>, newHostVulnerabilities: MutableMap<String, MutableList<String>>, scanDate: Date, vulnerabilityTickets: MutableSet<String>): String {
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

	private fun buildSummary(assignee: String, hosts: MutableSet<String>, vulnerabilityTickets: MutableSet<String>): String {
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

	private fun getIpNameStatusMaps(pingScanOutputFile: File): MutableList<MutableMap<String, Any>> {
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

	private fun getKnownVulnerabilities(name: String, responseJSONObject: JSONObject): MutableList<String> {
		val jiraTicketScriptLabelsCustomFieldId: String by properties

		val vulnerabilities = mutableListOf<String>()

		val issuesJSONArray = JSONArray(responseJSONObject.get("issues").toString())

		for (issue in issuesJSONArray) {
			val issueJSONObject = (issue as JSONObject)

			val issueFieldsJSONObject = issueJSONObject.get("fields") as JSONObject

			val customfield_IdJSONObject = issueFieldsJSONObject.get("customfield_$jiraTicketScriptLabelsCustomFieldId")

			@Suppress("UNCHECKED_CAST")
			val issueLabels = (customfield_IdJSONObject as JSONArray).toList() as List<String>

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

	private fun getKnownVulnerabilitiesJSONObject(host: String, password: String, user: String): JSONObject {
		val url = """https://$host/rest/api/2/search?jql=cf\[19627\]%20in%20("scan:owner-host-vulnerabilities","type:generated")%20and%20status%20not%20in%20(closed)"""

		val byteArrayOutputStream = ByteArrayOutputStream()

		exec("curl", listOf("--silent", "--user", "$user:$password", "--header", "Content-Type: application/json", url), standardOutput = byteArrayOutputStream, skipPrintCommandLine = true)

		val byteArrayOutputString = byteArrayOutputStream.toString()

		return JSONObject(byteArrayOutputString)
	}

	private fun getKtsResourceData(name: String): MutableList<MutableMap<String, Any>> {
		val scriptEngineManager = ScriptEngineManager()

		val ktsEngine = scriptEngineManager.getEngineByExtension("kts")

		val classLoader = javaClass.classLoader

		val listOfNameOwnerMapsKtsURL = classLoader.getResource("data/$name")!!

		val listOfNameOwnerMapsKtsFile = File(listOfNameOwnerMapsKtsURL.file)

		val listOfNameOwnerMapsKtsFileText = listOfNameOwnerMapsKtsFile.readText()

		@Suppress("UNCHECKED_CAST")
		return ktsEngine.eval(listOfNameOwnerMapsKtsFileText) as MutableList<MutableMap<String, Any>>
	}

	private fun getNmapIpNameStatusMaps(): MutableList<MutableMap<String, Any>> {
		logger.info("")

		val pingScanOutputFile = File("pingScanOutput.gnmap")

		val nmapTargetSpecificationFile = File("nmapTargetSpecification")

		val byteArrayOutputStream = ByteArrayOutputStream()

		exec("nmap", listOf("-oG", pingScanOutputFile.path, "-iL", nmapTargetSpecificationFile.path, "-sn"), standardOutput = byteArrayOutputStream, skipPrintCommandLine = true)

		return getIpNameStatusMaps(pingScanOutputFile)
	}

	private fun getResourceNameFiles(name: String): MutableList<File> {
		val classLoader = javaClass.classLoader

		val liferayVulnerabilitiesURL = classLoader.getResource(name)!!

		val liferayVulnerabilitiesDir = File(liferayVulnerabilitiesURL.file)

		val liferayVulnerabilityFiles = liferayVulnerabilitiesDir.listFiles()

		return liferayVulnerabilityFiles.toMutableList()
	}

	private fun dataKeySelectValues(data: MutableList<MutableMap<String, Any>> = this.data, keyName: String): MutableList<Any> {
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

	private fun dataKeyValueFetchData(data: MutableList<MutableMap<String, Any>> = this.data, keyName: String, keyValue: Any): MutableList<MutableMap<String, Any>> {
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

	private fun dataKeyValuePutAll(data: MutableList<MutableMap<String, Any>> = this.data, keyName: String, keyValue: String, valueMap: Map<String, String>) {
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

	private fun normalizeNmapIpNameStatusMaps(nmapIpNameStatusMaps: MutableList<MutableMap<String, Any>>) {
		for (nmapIpNameStatusMap in nmapIpNameStatusMaps) {
			normalizeNmapIpNameStatusMapsName(nmapIpNameStatusMap)
			normalizeNmapIpNameStatusMapStatus(nmapIpNameStatusMap)
		}
	}

	private fun normalizeNmapIpNameStatusMapsName(nmapIpNameStatusMap: MutableMap<String, Any>) {
		var name = nmapIpNameStatusMap["name"] as String

		val normalizedNameValueRegex = Regex("^(.*)\\.lax\\.liferay\\.com")

		val matchResult = normalizedNameValueRegex.matchEntire(name)

		if (matchResult != null) {
			val matchResultValues = matchResult.groupValues

			name = matchResultValues[1]

			nmapIpNameStatusMap.put("name", name)
		}
	}

	private fun normalizeNmapIpNameStatusMapStatus(nmapIpNameStatusMap: MutableMap<String, Any>) {
		var status = nmapIpNameStatusMap["status"] as String

		status = status.decapitalize()

		nmapIpNameStatusMap.put("status", status)
	}

	private fun setOwnersData(data: MutableList<MutableMap<String, Any>> = this.data, nameOwnerMaps: MutableList<MutableMap<String, Any>>) {
		logger.info("")

		for (nameOwnerMap in nameOwnerMaps) {
			val nameOwner = nameOwnerMap

			val nameValue = nameOwner["name"] as String

			val ownerValue = nameOwner["owner"] as String

			dataKeyValuePutAll(data, "name", nameValue, mapOf("owner" to ownerValue))
		}

		for (datum in data) {
			if (datum.containsKey("owner")) {
				continue
			}

			datum["owner"] = "unassigned"
		}
	}
}