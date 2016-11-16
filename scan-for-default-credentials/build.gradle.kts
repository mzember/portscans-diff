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
}

dependencies {
	compile(kotlinModule("stdlib"))
	testCompile("org.spockframework:spock-core:1.0-groovy-2.4")
}

defaultTasks("test")