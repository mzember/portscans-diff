package com.liferay.security

import spock.lang.Specification

class MainSpec extends Specification {

//	def "selectValue"() {
//		setup:
//		def penscan = new Penscan().penscan()
//
//		when:
//		def data = [[
//			"owner": "one"],[
//			"owner": "one"],[
//			"owner": "two"],[
//			"owner": "three"]]
//
//		def value = penscan.selectValue(data, "owner")
//
//		then:
//		value == ["one", "one", "two", "three"]
//	}
//
//	def "getKnownVulnerabilities"() {
//		setup:
//		def penscan = new Penscan().penscan()
//
//		when:
//		def knownVulnerabilitiesJSONObject = penscan.getKnownVulnerabilitiesJSONObject("issues.liferay.com", "", "")
//
//		def knownVulnerabilities = penscan.getKnownVulnerabilities("cloud-10-0-40-22", knownVulnerabilitiesJSONObject)
//
//		then:
//		knownVulnerabilities == ""
//	}
//
//	def "getTargets"() {
//
//	}

//	def "getTargets"() {
//		setup:
//		def penscan = new Penscan()
//
//		when:
//		def data = new ArrayList<Map<String, Object>>()
//
//		penscan.getTargets(data)
//
//		then:
//		data == [[:]]
//	}

	def "createIssue"() {
		setup:
		Properties properties = new Properties()

		properties.put("jiraHost", "issues-uat.liferay.com")
		properties.put("jiraPassword", "")
		properties.put("jiraUsername", "")
		properties.put("jiraProjectComponent", "Blue Team")
		properties.put("jiraProjectKey", "LRINFOSEC")
		properties.put("jiraTicketIssueType", "Bug")
		properties.put("jiraTicketScriptLabelsCustomFieldId", "19627")

		def penscan = new Penscan(new ArrayList<Map<String, Object>>(), properties)

		when:
		def issue = penscan.createIssue("", "testdescription", ["a", "b", "c"], "testsummary")

		then:
		issue ==~ /^[A-Z]+-[0-9]+/
	}

	def "createIssues"() {
		setup:
		Properties properties = new Properties()

		properties.put("jiraHost", "issues-uat.liferay.com")
		properties.put("jiraPassword", "")
		properties.put("jiraUsername", "")
		properties.put("jiraProjectComponent", "Blue Team")
		properties.put("jiraProjectKey", "LRINFOSEC")
		properties.put("jiraTicketIssueType", "Bug")
		properties.put("jiraTicketScriptLabelsCustomFieldId", "19627")
		properties.put("jiraTicketScriptLabelTool", "liferay-vulnerability-scanner")
		properties.put("jiraTicketScriptLabelToolVersion", "3.0.0")
		properties.put("jiraTicketScriptLabelType", "generated")

		def penscan = new Penscan(new ArrayList<Map<String, Object>>(), properties)

		when:
		def issue = penscan.createIssues()

		then:
		issue ==~ /^[A-Z]+-[0-9]+/
	}

//	def "setOwnersData"() {
//		setup:
//		def penscan = new Penscan()
//
//		when:
//		def data = new ArrayList<Map<String, Object>>()
//
//		penscan.penscanTargets(data)
//		penscan.setOwnersData(data)
//
//		then:
//		data == [[:]]
//	}

//	def "setOwnersData"() {
//		setup:
//		def penscan = new Penscan()
//
//		when:
//		def data = new ArrayList<Map<String, Object>>()
//
//		penscan.penscanTargets(data)
//		penscan.setOwnersData(data)
//
//		then:
//		data == [[:]]
//	}

//	def "setOwnersData"() {
//		setup:
//		def penscan = new Penscan()
//
//		when:
//		def data = new ArrayList<Map<String, Object>>()
//
//		penscan.setOwnersData(data)
//
//		then:
//		data == [[:]]
//	}

//	def "lookup"() {
//		val data = mutableListOf<MutableMap<String, Any>>()
//
//		data.add(mutableMapOf("ip" to "127.0.0.1", "name" to "localhost", "status" to "up"))
//		data.add(mutableMapOf("ip" to "", "name" to "operations-vm-3", "status" to "up"))
//		data.add(mutableMapOf("name" to "operations-vm-4", "status" to "up"))
//
//		println("data = ${data}")
//
//		insert(data, "ip", "127.0.0.1", mapOf("owner" to "m.e"))
//		insert(data, "ip", "127.0.0.1", mapOf("owner" to "yo.u"))
//		insert(data, "name", "localhost", mapOf("owner" to "hi.m"))
//		insert(data, "name", "operations-vm-3", mapOf("owner" to "hi.m"))
//		insert(data, "name", "operations-vm-4", mapOf("owner" to "hi.m"))
//
//		println("data = ${data}")
//
//		val lookup = lookup(data, "owner", "hi.m")
//
//		println("lookup = ${lookup}")
//
//		val lookupList = lookupList(data, "owner", "hi.m")
//
//		println("lookupList = ${lookupList}")
//
//		val select = select(data, "status")
//
//		println("select = ${select}")
//	}
//
//	def "testKts"() {
//		val scriptEngineManager = ScriptEngineManager()
//
//		val ktsEngine = scriptEngineManager.getEngineByExtension("kts")
//
//		val listOfNameOwnerMapsKtsFile = File("listOfNameOwnerMaps.kts")
//
//		val listOfNameOwnerMaps = (ktsEngine.eval(listOfNameOwnerMapsKtsFile.readText()) as List<*>)
//
//		for (nameOwner in listOfNameOwnerMaps) {
//			val nameOwnerMap = (nameOwner as Map<*, *>)
//
//			println("nameOwnerMap = ${nameOwnerMap}")
//		}
//	}
//
//	def "testing"() {
//		logger.info("")
//
//		val data = mutableListOf<MutableMap<String, String>>()
//
//		val pingScanOutputFile = File("pingScanOutput.gnmap")
//
//		val nmapTargetSpecificationFile = File("nmapTargetSpecification")
//
//		exec("nmap", listOf("-oG", pingScanOutputFile.path, "-iL", nmapTargetSpecificationFile.path, "-sn"))
//
//		val targetIpNames = getIpNameStatus()
//
//		val liferayTargets = getLiferayTargets(targetIpNames.keys)
//
//		val (ownerHosts, hostVulnerabilities) = getHostVulnerabilities(liferayTargets, targetIpNames)
//
//		val ownerHostsVulnerabilities = getOwnerHostsVulnerabilities(hostVulnerabilities, ownerHosts)
//
//		val knownHostVulnerabilities = getKnownHostVulnerabilities("issues.liferay.com", "", "", "19627")
//
//		val filterOwnerHostsVulnerabilities = filterOwnerHostsVulnerabilities(ownerHostsVulnerabilities, knownHostVulnerabilities)
//	}

}