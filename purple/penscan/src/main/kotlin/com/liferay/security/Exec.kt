package com.liferay.security

import java.io.BufferedReader
import java.io.File
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.io.PrintStream

fun exec(executable: String, args: List<String> = listOf(), environment: Map<String, String> = mapOf(), standardOutput: OutputStream = System.out, workingDir: File? = null, skipPrintCommandLine: Boolean = false, exceptionOnExitValue: Boolean = true): Int {
	val commandLine = mutableListOf<String>()

	commandLine.add(executable)

	commandLine.addAll(args)

	val processBuilder = ProcessBuilder(commandLine)

	processBuilder.directory(workingDir)

	var processWorkingDir = processBuilder.directory()

	if (processWorkingDir == null) {
		processWorkingDir = File(System.getProperty("user.dir"))
	}

	if (!skipPrintCommandLine) {
		println(" > ${processWorkingDir.absolutePath}\$ ${commandLine.joinToString(" ")}")
	}

	val processEnvironment = processBuilder.environment()

	processEnvironment.putAll(environment)

	processBuilder.redirectErrorStream(true)

	val process = processBuilder.start()

	_redirectStream(process.inputStream, standardOutput)

	val exitValue = process.waitFor()

	if (exceptionOnExitValue && (exitValue != 0)) {
		throw Exception("The process returned the unexpected exit value of $exitValue.")
	}

	return exitValue
}

private fun _redirectStream(inputStream: InputStream, outputStream: OutputStream) {
	val outputStreamReader = BufferedReader(InputStreamReader(inputStream))

	val printStream = PrintStream(outputStream)

	var line = outputStreamReader.readLine()

	while (line != null) {
		printStream.println(line)

		line = outputStreamReader.readLine()
	}
}