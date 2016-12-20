import groovy.json.JsonSlurper
import security.test.UtilKt
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class UtilSpec extends Specification {

	@Shared
	File dataFile = File.createTempFile("data", ".csv");

	def setupSpec() {
		def screennames = []

		def ownersFile = new File("src/main/resources/owners")

		def readLines = ownersFile.readLines()

		for (readline in readLines) {
			def screenname = (readline =~ /,(.*)/)[0][1] as String

			if (screennames.contains(screenname)) {
				continue
			}

			screennames.add(screenname)

			dataFile.append(screenname)
			dataFile.append("\n")
		}
	}

	@Unroll
	def "do not allow vm owner #screenname to be inactive"() {
		when:
		def byteArrayOutputStream = new ByteArrayOutputStream()

		def exitValue = UtilKt.getUser(screenname, byteArrayOutputStream, byteArrayOutputStream)

		then:
		if (exitValue == 0) {
			def jsonSlurper = new JsonSlurper()

			def outputString = byteArrayOutputStream.toString()

			def outputJSONObject = jsonSlurper.parseText(outputString)

			assert outputJSONObject.data.inactive == false
		}

		where:
		[screenname] << new CSVDataProvider(dataFile)
	}

}