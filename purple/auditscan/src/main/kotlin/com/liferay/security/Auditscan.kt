package com.liferay.security

import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

import java.net.URL

import java.text.SimpleDateFormat

import java.util.Date;
import java.util.TreeMap
import java.util.logging.Logger

import org.json.JSONArray
import org.json.JSONObject

import pl.allegro.finance.tradukisto.ValueConverters
import java.net.HttpURLConnection

fun main(args: Array<String>) {
	if (args.size != 2) {
		throw Exception("Bad args")
	}

	val auditscan = Auditscan()

	auditscan.commitHTTPScoreReport(args[0], args[1])
	auditscan.commitSPFScoreReport(args[0], args[1])
}

class Auditscan() {
	companion object {
		val logger = Logger.getLogger(Auditscan::javaClass.name)!!
	}

	fun commitHTTPScoreReport(projectDir: String, siteURL: String) {
		logger.fine("")

		val response = createHTTPScoreReport(siteURL)

		val jsonObject = JSONObject(response)

		val resultsJSONArray = jsonObject.get("results") as JSONArray

		val resultsMap = TreeMap<String, Int>()

		for (i in 0..(resultsJSONArray.length() - 1)) {
			val resultJSONObject = resultsJSONArray.getJSONObject(i)

			resultsMap.put(resultJSONObject.getString("title"), resultJSONObject.getInt("score"))
		}

		resultsMap.put("totalScore", jsonObject.getInt("Score"))

		val csvFile = File(projectDir + "/reports/http_scores/" + siteURL + ".csv")

		appendCSV(csvFile, resultsMap)

		commit(csvFile, "LRINFOSEC-192 Generated HTTP Score Report")
	}

	fun commitSPFScoreReport(projectDir: String, siteURL: String) {
		logger.fine("")

		var result = "fail"

		val response = createSPFScoreReport(siteURL)

		println("response = ${response}")

		if (response.contains("pass")) {
			result = "pass"
		}

		val csvFile = File(projectDir + "/reports/spf_scores/" + siteURL + ".csv")

		csvFile.appendText("\r\n" + siteURL + ',' + result)

		commit(csvFile, "LRINFOSEC-192 Generated SPF Score Report")
	}

	private fun appendCSV(csvFile: File, resultsMap: Map<String, Int>) {
		logger.fine("")

		val row = ArrayList<String>()

		row.add(SimpleDateFormat("yyyy-MM-dd").format(Date()))

		for ((key, value) in resultsMap) {
			row.add(value.toString())
		}

		csvFile.appendText("\r\n" + row.joinToString(","))
	}

	private fun commit(file: File, message: String) {
		var args = mutableListOf("add", file.getCanonicalPath())

		exec("git", args)

		args = mutableListOf("commit", "-m", message)

		exec("git", args)

		args = mutableListOf("pull", "--rebase", "upstream", "master")

		exec("git", args)

		args = mutableListOf("push", "origin", "HEAD:master")

		exec("git", args)
	}

	private fun createHTTPScoreReport(siteURL: String): String {
		logger.fine("")

		val response = StringBuffer()

		val url = URL("https://httpsecurityreport.com/analyze?url=" + siteURL)

		val connection = url.openConnection()

		val bufferedReader = BufferedReader(InputStreamReader(connection.getInputStream()))

		var input = bufferedReader.readLine()

		while (input != null) {
			response.append(input)

			input = bufferedReader.readLine()
		}

		bufferedReader.close()

		logger.finest("Response: " + response.toString())

		return response.toString()
	}

	private fun createSPFScoreReport(siteURL: String): String {
		logger.fine("")

		val response = StringBuffer()

		val url = URL("http://www.kitterman.com/getspf2.py?domain=$siteURL&serial=fred12")

		val connection = url.openConnection() as HttpURLConnection

		connection.requestMethod = "POST"

		val bufferedReader = BufferedReader(InputStreamReader(connection.getInputStream()))

		var input = bufferedReader.readLine()

		while (input != null) {
			response.append(input)

			input = bufferedReader.readLine()
		}

		bufferedReader.close()

		logger.finest("Response: " + response.toString())

		return response.toString()
	}

}