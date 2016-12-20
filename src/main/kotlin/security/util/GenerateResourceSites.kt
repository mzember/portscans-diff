package security.util

import groovy.json.JsonSlurper
import groovy.json.internal.LazyMap
import plugins.exec
import java.io.ByteArrayOutputStream
import java.io.File

fun main(args: Array<String>) {
	generateResourceSites("src/main/resources/sites", ByteArrayOutputStream())
}

fun generateResourceSites(sitesFilePath: String, outputStream: ByteArrayOutputStream) {
	val token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjI4MTc0LCJkZXZpY2UiOiJscmlzLXNlY3VyaXR5IiwicmV2b2thYmxlIjp0cnVlLCJpYXQiOjE0ODEwNjkwMjJ9.ZO0i5rXhhBjuZi4Q7-N3UehusIEwx_asfJVsc8Sni38"

	exec(
		executable = "curl",
		args = listOf("-s", "-H", "Authorization: Bearer " + token, "https://loop.liferay.com/home/-/loop/divisions/332967/viewChildLoopDivisions.json?_1_WAR_loopportlet_start=-1&_1_WAR_loopportlet_end=-1"),
		standardOutput = outputStream,
		errorOutput = outputStream,
		skipPrintCommandLine = false
	)

	val sitesFile = File(sitesFilePath)

	val jsonSlurper = JsonSlurper()

	val outputString = outputStream.toString()

	val parseText = jsonSlurper.parseText(outputString) as LazyMap

	val data = parseText.get("data")

	@Suppress("UNCHECKED_CAST")
	val sites = (data as ArrayList<LazyMap>)

	sitesFile.printWriter().use { out ->
		for (site in sites) {
			val siteName = site.get("name")

			out.println(siteName as String)
		}
	}
}