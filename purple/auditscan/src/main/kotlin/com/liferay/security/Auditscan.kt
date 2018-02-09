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

fun main(args: Array<String>) {
	if (args.size != 2) {
		throw Exception("Bad args")
	}

	val auditscan = Auditscan()

	auditscan.scan(args[0], args[1])
}

class Auditscan() {
	companion object {
		val logger = Logger.getLogger(Auditscan::javaClass.name)!!
	}

	fun scan(projectDir: String, siteURL: String) {
		logger.fine("")

		val response = sendRequest(siteURL)

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

		pushCSV(csvFile)
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

	private fun pushCSV(csvFile: File) {
		var args = mutableListOf("add", csvFile.getCanonicalPath())

		exec("git", args)

		args = mutableListOf("commit", "-m", "LRINFOSEC-192 auto audit scan")

		exec("git", args)

		args = mutableListOf("pull", "--rebase", "upstream", "master")

		exec("git", args)

		args = mutableListOf("push", "origin", "HEAD:master")

		exec("git", args)
	}

	private fun sendRequest(siteURL: String): String {
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

}