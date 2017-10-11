package com.liferay.security.util

import java.io.File

fun getResourceFiles(resourcePath: String): MutableList<File> {
	val classLoader = object {}.javaClass.classLoader

	val resourceURL = classLoader.getResource(resourcePath)!!

	val resourceDirectory = File(resourceURL.file)

	val resourceFiles = resourceDirectory.listFiles()

	return resourceFiles.toMutableList()
}