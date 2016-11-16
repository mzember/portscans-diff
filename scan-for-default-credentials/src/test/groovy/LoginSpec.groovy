import org.junit.internal.AssumptionViolatedException
import plugins.ExecKt
import security.LoginKt
import spock.lang.IgnoreIf
import spock.lang.Requires
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class LoginSpec extends Specification {
	private static boolean isPortalInstance() {
		true
	}

	@Shared
	File dataFile = File.createTempFile("data", ".csv");

	def setupSpec() {
		def hostsFile = new File("src/main/resources/hosts")

		def lines = hostsFile.readLines().sort { a, b ->
			def sa1 = (a =~ /(.*)(\d+)\W(\d+)\W(\d+)\W(\d+)(.*)/)[0][1] as String
			def sb1 = (b =~ /(.*)(\d+)\W(\d+)\W(\d+)\W(\d+)(.*)/)[0][1] as String

			def na1 = (a =~ /(.*)(\d+)\W(\d+)\W(\d+)\W(\d+)(.*)/)[0][2] as Integer
			def nb1 = (b =~ /(.*)(\d+)\W(\d+)\W(\d+)\W(\d+)(.*)/)[0][2] as Integer

			def na2 = (a =~ /(.*)(\d+)\W(\d+)\W(\d+)\W(\d+)(.*)/)[0][3] as Integer
			def nb2 = (b =~ /(.*)(\d+)\W(\d+)\W(\d+)\W(\d+)(.*)/)[0][3] as Integer

			def na3 = (a =~ /(.*)(\d+)\W(\d+)\W(\d+)\W(\d+)(.*)/)[0][4] as Integer
			def nb3 = (b =~ /(.*)(\d+)\W(\d+)\W(\d+)\W(\d+)(.*)/)[0][4] as Integer

			def na4 = (a =~ /(.*)(\d+)\W(\d+)\W(\d+)\W(\d+)(.*)/)[0][5] as Integer
			def nb4 = (b =~ /(.*)(\d+)\W(\d+)\W(\d+)\W(\d+)(.*)/)[0][5] as Integer

			def sa2 = (a =~ /(.*)(\d+)\W(\d+)\W(\d+)\W(\d+)(.*)/)[0][6] as String
			def sb2 = (b =~ /(.*)(\d+)\W(\d+)\W(\d+)\W(\d+)(.*)/)[0][6] as String

			sa1 <=> sb1 ?: na1 <=> nb1 ?: na2 <=> nb2 ?: na3 <=> nb3 ?: na4 <=> nb4 ?: sa2 <=> sb2
		}

		lines.each {
			dataFile.append("http,$it,test,test\n")
			dataFile.append("https,$it,test,test\n")
			dataFile.append("http,$it,test@liferay.com,test\n")
			dataFile.append("https,$it,test@liferay.com,test\n")
		}
	}

	@Unroll
	def "do not allow log in to host #host using protocol #protocol with login #login and password #password"() {
		when:
		def byteArrayOutputStream = new ByteArrayOutputStream()

		def exitValue = LoginKt.loginWithCredentials(protocol, host, login, password, byteArrayOutputStream, byteArrayOutputStream)

		then:
		if (exitValue == 0) {
			def outputString = byteArrayOutputStream.toString()

			def outputLines = outputString.readLines()

			if (outputLines.grep(~/.*Liferay-Portal: .*/)) {
				def grep1 = outputLines.grep(~/.*Location.*/)
				def grep2 = grep1.grep(~".*c/portal.*")
				def grep3 = grep2.grep(~"^((?!c/portal/login).)*\$")

				assert grep3.isEmpty()
			}
		}

		where:
		[protocol, host, login, password] << new CSVDataProvider(dataFile)
	}

}