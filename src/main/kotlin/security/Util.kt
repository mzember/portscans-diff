package security

import plugins.exec
import java.io.ByteArrayOutputStream

fun getUser(screenname: String, errorStream: ByteArrayOutputStream, outputStream: ByteArrayOutputStream): Int {
	val token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjI4MTc0LCJkZXZpY2UiOiJscmlzLXNlY3VyaXR5IiwicmV2b2thYmxlIjp0cnVlLCJpYXQiOjE0ODEwNjkwMjJ9.ZO0i5rXhhBjuZi4Q7-N3UehusIEwx_asfJVsc8Sni38"

	return exec(
		executable = "curl",
		args = listOf("-H", "Authorization: Bearer $token", "https://loop.liferay.com/web/guest/home/-/loop/people/_${screenname}/view.json"),
		standardOutput = outputStream,
		errorOutput = errorStream,
		skipPrintCommandLine = false
	)
}