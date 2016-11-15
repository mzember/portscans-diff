import security.LoginKt
import spock.lang.Specification
import spock.lang.Unroll

class LoginSpec extends Specification {

	@Unroll
	def "do not allow log in to host #host using protocol #protocol with login #login and password #password"() {
		when:
		def outputString = LoginKt.loginWithCredentials(protocol, host, login, password)

		then:
		def outputLines = outputString.readLines()

		for (outputLine in outputLines) {
			assert !(outputLine.contains("Location") && !outputLine.contains("c/portal"))
		}

		where:
		[host] << new CSVDataProvider("src/main/resources/hosts")

		login = "test"
		password = "test"
		protocol = "http"
	}

	@Unroll
	def "do not allow log in to host #host using protocol #protocol with login #login and password #password"() {
		when:
		def outputString = LoginKt.loginWithCredentials(protocol, host, login, password)

		then:
		def outputLines = outputString.readLines()

		for (outputLine in outputLines) {
			assert !(outputLine.contains("Location") && !outputLine.contains("c/portal"))
		}

		where:
		[host] << new CSVDataProvider("src/main/resources/hosts")

		login = "test"
		password = "test"
		protocol = "https"
	}

	@Unroll
	def "do not allow log in to host #host using protocol #protocol with login #login and password #password"() {
		when:
		def outputString = LoginKt.loginWithCredentials(protocol, host, login, password)

		then:
		def outputLines = outputString.readLines()

		for (outputLine in outputLines) {
			assert !(outputLine.contains("Location") && !outputLine.contains("c/portal"))
		}

		where:
		[host] << new CSVDataProvider("src/main/resources/hosts")

		login = "test@liferay.com"
		password = "test"
		protocol = "http"
	}

	@Unroll
	def "do not allow log in to host #host using protocol #protocol with login #login and password #password"() {
		when:
		def outputString = LoginKt.loginWithCredentials(protocol, host, login, password)

		then:
		def outputLines = outputString.readLines()

		for (outputLine in outputLines) {
			assert !(outputLine.contains("Location") && !outputLine.contains("c/portal"))
		}

		where:
		[host] << new CSVDataProvider("src/main/resources/hosts")

		login = "test@liferay.com"
		password = "test"
		protocol = "https"
	}

}