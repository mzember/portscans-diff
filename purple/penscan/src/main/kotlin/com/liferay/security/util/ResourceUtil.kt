package com.liferay.security.util

import java.io.File
import java.io.FileNotFoundException

fun getResourceFile(resourcePath: String, fileNameWithoutExtension: String): File {
	val resourceFiles = getResourceFiles(resourcePath)

	for (resourceFile in resourceFiles) {
		var fileName = resourceFile.getName()

		val pos = fileName.lastIndexOf(".")

		if (pos > 0) {
			fileName = fileName.substring(0, pos)
		}

		if (fileName.equals(fileNameWithoutExtension)) {
			return resourceFile
		}
	}

	throw FileNotFoundException("Unable to find " + fileNameWithoutExtension + " in " + resourcePath)
}

fun getResourceFiles(resourcePath: String): MutableList<File> {
	val classLoader = object {}.javaClass.classLoader

	val resourceURL = classLoader.getResource(resourcePath)!!

	val resourceDirectory = File(resourceURL.file)

	val resourceFiles = resourceDirectory.listFiles()

	return resourceFiles.toMutableList()
}