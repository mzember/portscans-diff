import groovy.json.JsonSlurper
import security.UtilKt
import spock.lang.Specification
import spock.lang.Unroll

class UtilSpec extends Specification {

	@Shared
	File dataFile = File.createTempFile("data", ".csv");

	def setupSpec() {
		def ownersFile = new File("src/main/resources/owners")

		ownersFile.forEachLine() { line ->
			def user = (line =~ /,(.*)/)[0] as String

			def username = user + "@liferay.com"
			def password = "weloveliferay"

			dataFile.append(user,username,password)
		}
	}

	@Unroll
	def "do not return data to api requests for inactive user #user"() {
		when:
		def byteArrayOutputStream = new ByteArrayOutputStream()

		def exitValue = UtilKt.getUser(user, username, password, byteArrayOutputStream, byteArrayOutputStream)

		then:
		if (exitValue == 0) {
			def outputString = byteArrayOutputStream.toString()

			def jsonSlurper = new JsonSlurper()

			def outputJSONObject = jsonSlurper.parseText(outputString)

			assert outputJSONObject.data.inactive == false
		}

		where:
		[user, username, password] << new CSVDataProvider(dataFile)
	}

}