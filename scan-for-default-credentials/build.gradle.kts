import org.gradle.api.tasks.Exec
import java.io.ByteArrayOutputStream

description = "LRINFOSEC-52 Check the use of default user credentials"
group = "LRINFOSEC"

var servers = listOf<String>()

val projectServers by project

val projectServersFilePath by project

if (projectServersFilePath != "") {
	val serversFileText = file(projectServersFilePath).readText()

	servers = serversFileText.split("\n")
}
else {
	val serversProperty = (projectServers as String)

	servers = serversProperty.split(",")
}

val projectProtocols by project
val protocols = (projectProtocols as String).split(",")

val projectLogins by project
val logins = (projectLogins as String).split(",")

val projectPassword by project

for (server in servers) {
	for(protocol in protocols) {
		for(login in logins) {
			val execOutput = ByteArrayOutputStream()

			task<Exec>("LRINFOSEC-52 $protocol $server $login") {
				executable("curl")
				args("-v", "-s", "-H", "'Cookie: COOKIE_SUPPORT=true'", "--max-time", "3", "$protocol://$server/c/portal/login?login=$login&password=$projectPassword")
				standardOutput = execOutput
				errorOutput = execOutput
				isIgnoreExitValue = true
				doFirst {
					println("$workingDir\$ ${commandLine.joinToString(" ")}")
				}
				doLast {
					val exitValue = execResult.exitValue

					if (exitValue != 0) {
						throw Exception("[~] Untested. Curl returned exit value $exitValue.")
					}

					val execOutputString = execOutput.toString()

					val execOutputLines = execOutputString.lines()

					execOutputLines.forEach {
						if (it.startsWith("< Location: ") && !it.contains("c/portal")) {
							throw Exception("[!] $protocol://$server is vulnerable to LRINFOSEC-52 (https://issues.liferay.com/browse/LRINFOSEC-52)}")
						}
					}
				}
			}
		}
	}
}

defaultTasks = project.tasks.map { it.name }