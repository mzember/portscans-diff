buildscript {
	repositories {
		mavenCentral()
		gradleScriptKotlin()
	}

	dependencies {
		classpath(kotlinModule("gradle-plugin"))
	}
}

repositories {
	mavenCentral()
	gradleScriptKotlin()
}

apply {
	plugin("kotlin")
	plugin("groovy")
	plugin<ApplicationPlugin>()
}

configure<ApplicationPluginConvention>() {
	mainClassName = "security.tests.MainKt"
}

dependencies {
	compile(kotlinModule("stdlib"))
	compile("cglib:cglib:2.2")
	compile("org.codehaus.groovy:groovy-all:2.4.1")
	testCompile("org.spockframework:spock-core:1.0-groovy-2.4")
	testCompile("org.springframework.boot:spring-boot:1.2.1.RELEASE")
}

defaultTasks("test")