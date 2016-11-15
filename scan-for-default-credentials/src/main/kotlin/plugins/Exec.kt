package plugins

import java.io.BufferedReader
import java.io.File
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.nio.charset.Charset

fun exec(executable: String, args: List<String> = listOf(), environment: Map<String, String> = mapOf(), standardOutput: OutputStream = System.out, errorOutput: OutputStream = System.err, workingDir: File? = null, skipPrintCommandLine: Boolean = true): Int {
	val commandLine = mutableListOf<String>()

	commandLine.add(executable)

	val argsList = args.toList()

	commandLine.addAll(argsList)

	val processBuilder = ProcessBuilder(commandLine)

	processBuilder.directory(workingDir)

	var processWorkingDir = processBuilder.directory()

	if (processWorkingDir == null) {
		processWorkingDir = File(System.getProperty("user.dir"))
	}

	if (!skipPrintCommandLine) {
		println(">${processWorkingDir.absolutePath}\$ ${commandLine.joinToString(" ")}")
	}

	val processEnvironment = processBuilder.environment()

	processEnvironment.putAll(environment)

	val process = processBuilder.start()

	_redirectStream(process.inputStream, standardOutput)
	_redirectStream(process.errorStream, errorOutput)

	process.waitFor()

	return process.exitValue()
}

private fun _redirectStream(inputStream: InputStream, outputStream: OutputStream) {
	val outputStreamBuffer = StringBuffer()

	_bufferStream(inputStream, outputStreamBuffer)

	val outputStreamString = outputStreamBuffer.toString()

	val outputStreamByteArray = outputStreamString.toByteArray(Charset.defaultCharset())

	outputStream.write(outputStreamByteArray)
}

private fun _bufferStream(inputStream: InputStream, stringBuffer: StringBuffer) {
	val outputStreamReader = BufferedReader(InputStreamReader(inputStream));

	var line = outputStreamReader.readLine();

	while (line != null) {
		stringBuffer.append(line)
		stringBuffer.append("\n")

		line = outputStreamReader.readLine()
	}
}