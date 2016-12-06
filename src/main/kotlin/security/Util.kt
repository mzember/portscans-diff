package security

import plugins.exec
import java.io.OutputStream

fun getUser(user: String, username: String, password: String, errorOutput: OutputStream, standardOutput: OutputStream): Int {
	var credentials = "$username:$password"
	val url = "https://loop-uat.liferay.com/web/guest/home/-/loop/people/_$user/view.json"

	return exec(
		executable = "curl",
		args = listOf("--max-time", "3", "-s", "-u", credentials, "--url", url),
		errorOutput = errorOutput,
		standardOutput = standardOutput,
		skipPrintCommandLine = false
	)
}