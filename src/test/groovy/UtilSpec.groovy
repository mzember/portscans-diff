import groovy.json.JsonSlurper
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import plugins.ExecKt
import security.test.UtilKt
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class UtilSpec extends Specification {
	@Rule
	TemporaryFolder temporaryFolder = new TemporaryFolder()

	@Shared
	File screennamesFile = File.createTempFile("screennames", ".csv")

	@Shared
	File domainNameFile = File.createTempFile("domains", ".csv")

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

			screennamesFile.append(screenname)
			screennamesFile.append("\n")
		}

		def sitesFile = new File("src/main/resources/sites")

		domainNameFile.text = sitesFile.text
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
		[screenname] << new CSVDataProvider(screennamesFile)
	}

	@Unroll
	def "ssllabs score for #domainName should be A- or above"() {
		when:
		def byteArrayOutputStream = new ByteArrayOutputStream()

		ExecKt.exec("./ssllabs-scan", ["--quiet", domainName], [:], byteArrayOutputStream, byteArrayOutputStream, new File("tools"), false)

		def jsonSlurper = new JsonSlurper()

		def outputString = byteArrayOutputStream.toString()

		def outputJSONObject = jsonSlurper.parseText(outputString)

		def liferayDotComGrades = outputJSONObject.endpoints[0].grade

		then:
		for (liferayDotComGrade in liferayDotComGrades) {
			assert (liferayDotComGrade == "A-") || (liferayDotComGrade == "A") || (liferayDotComGrade == "A+")
		}

		where:
		[domainName] << new CSVDataProvider(domainNameFile)
	}

}