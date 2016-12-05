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
}

dependencies {
	compile(kotlinModule("stdlib"))
	compile("org.codehaus.groovy:groovy-all:2.4.7")
	testCompile("org.spockframework:spock-core:1.0-groovy-2.4")
}

defaultTasks("test")