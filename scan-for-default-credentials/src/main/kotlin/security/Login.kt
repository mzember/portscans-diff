package security

import plugins.exec
import java.io.ByteArrayOutputStream

fun loginWithCredentials(protocol: String, host: String, login: String, password: String): String {
	val path = "c/portal/login"

	val parameters = "login=$login&password=$password"

	val url = "$protocol://$host/$path?$parameters"

	val outputStream = ByteArrayOutputStream()

	val exitValue = exec(
		executable = "curl",
		args = listOf("-v", "-s", "-H", "'Cookie: COOKIE_SUPPORT=true'", "--max-time", "3", "--url", url),
		errorOutput = outputStream,
		standardOutput = outputStream,
		skipPrintCommandLine = false
	)

	val outputString = outputStream.toString()

	if (exitValue != 0) {
		println("[!] Exit value $exitValue")

		println(outputString)

		throw Exception("Exited with value: $exitValue")
	}

	return outputString
}