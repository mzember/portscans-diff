package com.liferay.security

import org.json.JSONObject
import spock.lang.Specification

class PenscanSpec extends Specification {

	def "associateKnownVulnerabilitiesWithTargets"() {
		setup:
		Properties properties = new Properties()

		properties.put("jiraTicketScriptLabelsCustomFieldId", "19627")

		def penscan = new Penscan(properties)

		def data = [
			["name": "one", "ip": "1", "status": "up", "owner": "alpha.beta", "vulnerabilities": [
				["name": "VULNERABILITY-0", "vulnerable": "yes"],
				["name": "VULNERABILITY-1", "vulnerable": "yes"]]],
			["name": "two", "ip": "2", "status": "up", "owner": "alpha.beta", "vulnerabilities": [
				["name": "VULNERABILITY-1", "vulnerable": "yes"],
				["name": "VULNERABILITY-2", "vulnerable": "yes"],
				["name": "VULNERABILITY-3", "vulnerable": "no"]]]]

		when:
		def knownVulnerabilitiesJSONObjectStringFile = new File(this.getClass().classLoader.getResource("getKnownVulnerabilitiesJSONObjectString").file)

		def knownVulnerabilitiesJSONObject = new JSONObject(knownVulnerabilitiesJSONObjectStringFile.text)

		penscan.associateKnownVulnerabilitiesWithTargets(knownVulnerabilitiesJSONObject, data)

		then:
		data == [
			["name": "one", "ip": "1", "status": "up", "owner": "alpha.beta", "vulnerabilities": [
				["name": "VULNERABILITY-0", "vulnerable": "yes", "new": "yes"],
				["name": "VULNERABILITY-1", "vulnerable": "yes", "new": "no"]]],
			["name": "two", "ip": "2", "status": "up", "owner": "alpha.beta", "vulnerabilities": [
				["name": "VULNERABILITY-1", "vulnerable": "yes", "new": "yes"],
				["name": "VULNERABILITY-2", "vulnerable": "yes", "new": "no"],
				["name": "VULNERABILITY-3", "vulnerable": "no", "new": "not-applicable"]]]]
	}

	def "dataKeySelectValues"() {
		setup:
		def penscan = new Penscan()

		def data = [
			["name": "one", "ip": "1", "status": "up", "owner": "alpha.beta", "vulnerabilities": [
				["name": "VULNERABILITY-0", "vulnerable": "yes", "new": "yes"],
				["name": "VULNERABILITY-1", "vulnerable": "yes", "new": "no"]]],
			["name": "two", "ip": "2", "status": "up", "owner": "alpha.beta", "vulnerabilities": [
				["name": "VULNERABILITY-1", "vulnerable": "yes", "new": "yes"],
				["name": "VULNERABILITY-2", "vulnerable": "yes", "new": "no"],
				["name": "VULNERABILITY-3", "vulnerable": "no", "new": "not-applicable"]]]]

		when:
		def values = penscan.dataKeySelectValues(data, "name")

		then:
		values.sort() == ["one", "two"].sort()
	}

	def "dataKeyValueFetchData"() {
		setup:
		def penscan = new Penscan()

		def data = [
			["name": "one", "ip": "1", "status": "up", "owner": "alpha.beta", "vulnerabilities": [
				["name": "VULNERABILITY-0", "vulnerable": "yes", "new": "yes"],
				["name": "VULNERABILITY-1", "vulnerable": "yes", "new": "no"]]],
			["name": "two", "ip": "2", "status": "up", "owner": "alpha.beta", "vulnerabilities": [
				["name": "VULNERABILITY-1", "vulnerable": "yes", "new": "yes"],
				["name": "VULNERABILITY-2", "vulnerable": "yes", "new": "no"],
				["name": "VULNERABILITY-3", "vulnerable": "no", "new": "not-applicable"]]]]

		when:
		def fetchData = penscan.dataKeyValueFetchData(data, "name", "two")

		then:
		fetchData == [
			["name": "two", "ip": "2", "status": "up", "owner": "alpha.beta", "vulnerabilities": [
				["name": "VULNERABILITY-1", "vulnerable": "yes", "new": "yes"],
				["name": "VULNERABILITY-2", "vulnerable": "yes", "new": "no"],
				["name": "VULNERABILITY-3", "vulnerable": "no", "new": "not-applicable"]]]]
	}

	def "dataKeyValuePutAll"() {
		setup:
		def penscan = new Penscan()

		def data = [
			["name": "one", "ip": "1", "status": "up"],
			["name": "two", "ip": "2", "status": "up"],
			["name": "three", "ip": "3"]]

		when:
		penscan.dataKeyValuePutAll(data, "name", "three", ["status": "up"])

		then:
		data == [
			["name": "one", "ip": "1", "status": "up"],
			["name": "two", "ip": "2", "status": "up"],
			["name": "three", "ip": "3", "status": "up"]]
	}

	def "getIpNameStatusMaps"() {
		setup:
		def penscan = new Penscan()

		def nmapPingScanOutputFile = new File(this.getClass().classLoader.getResource("pingScanOutput.gnmap").file)

		when:
		def ipNameStatusMaps = penscan.getIpNameStatusMaps(nmapPingScanOutputFile)

		then:
		ipNameStatusMaps.size() == 899
		ipNameStatusMaps[0] == ["name": "cloud-10-0-0-10.lax.liferay.com", "ip": "10.0.0.10", "status": "Up"]
		ipNameStatusMaps[898] == ["name": "", "ip": "172.16.169.251", "status": "Up"]
	}

	def "getKnownVulnerabilities"() {
		setup:
		Properties properties = new Properties()

		properties.put("jiraTicketScriptLabelsCustomFieldId", "19627")

		def penscan = new Penscan(properties)

		when:
		def knownVulnerabilitiesJSONObjectStringFile = new File(this.getClass().classLoader.getResource("getKnownVulnerabilitiesJSONObjectString").file)

		def knownVulnerabilitiesJSONObject = new JSONObject(knownVulnerabilitiesJSONObjectStringFile.text)

		def knownVulnerabilities = penscan.getKnownVulnerabilities(knownVulnerabilitiesJSONObject, "one")

		then:
		knownVulnerabilities.sort() == ["VULNERABILITY-1", "VULNERABILITY-2"].sort()
	}

/*
	def "getKnownVulnerabilitiesJSONObject"() {
		setup:
		Properties properties = new Properties()

		properties.put("jiraHost", "issues-uat.liferay.com")
		properties.put("jiraPassword", "")
		properties.put("jiraUsername", "")

		def penscan = new Penscan(properties)

		when:
		def jsonObject = penscan.getKnownVulnerabilitiesJSONObject()

		then:
		def keys = ((JSONObject) jsonObject).keySet()

		keys.sort() == ["expand", "total", "maxResults", "issues", "startAt"].sort()
	}
*/

	def "normalizeNmapIpNameStatusMapsName"() {
		setup:
		def penscan = new Penscan()

		when:
		def nmapIpNameStatusMap = ["ip": "1", "name": "one.lax.liferay.com", "status": "Up"]

		penscan.normalizeNmapIpNameStatusMapName(nmapIpNameStatusMap)

		then:
		nmapIpNameStatusMap == ["ip": "1", "name": "one", "status": "Up"]
	}

	def "normalizeNmapIpNameStatusMapsStatus"() {
		setup:
		def penscan = new Penscan()

		when:
		def nmapIpNameStatusMap = ["ip": "1", "name": "one", "status": "Up"]

		penscan.normalizeNmapIpNameStatusMapStatus(nmapIpNameStatusMap)

		then:
		nmapIpNameStatusMap == ["ip": "1", "name": "one", "status": "up"]
	}

	def "setOwnersData"() {
		setup:
		def penscan = new Penscan()

		def data = [
			["name": "one", "ip": "1", "status": "up"],
			["name": "two", "ip": "2", "status": "up"],
			["name": "three", "ip": "3", "status": "up"]]

		def owners = [
			["name": "one", "owner": "alpha.beta"],
			["name": "two", "owner": "alpha.beta"],
			["name": "three", "owner": "charlie.delta"]]

		when:
		penscan.setOwnersData(data, owners)

		then:
		data == [
			["name": "one", "ip": "1", "status": "up", "owner": "alpha.beta"],
			["name": "two", "ip": "2", "status": "up", "owner": "alpha.beta"],
			["name": "three", "ip": "3", "status": "up", "owner": "charlie.delta"]]
	}

}