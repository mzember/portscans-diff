package security

import plugins.exec
import java.io.OutputStream

fun loginWithCredentials(protocol: String, host: String, login: String, password: String, errorOutput: OutputStream, standardOutput: OutputStream): Int {
	val path = "c/portal/login"

	val parameters = "login=$login&password=$password"

	val url = "$protocol://$host/$path?$parameters"

	return exec(
		executable = "curl",
		args = listOf("-v", "-s", "-L", "-H", "'Cookie: COOKIE_SUPPORT=true'", "--max-time", "3", "--url", url),
		errorOutput = errorOutput,
		standardOutput = standardOutput,
		skipPrintCommandLine = false
	)
}