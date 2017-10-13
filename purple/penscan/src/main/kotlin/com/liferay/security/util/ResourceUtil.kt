package com.liferay.security.util

import java.io.File
import java.io.FileNotFoundException

fun getResourceFile(resourcePath: String, fileNameWithoutExtension: String): File {
	val resourceDir = getResourceDir(resourcePath)

	val resourceFiles = resourceDir.listFiles()

	for (resourceFile in resourceFiles) {
		var fileName = resourceFile.name

		val pos = fileName.lastIndexOf(".")

		if (pos > 0) {
			fileName = fileName.substring(0, pos)
		}

		if (fileName == fileNameWithoutExtension) {
			return resourceFile
		}
	}

	throw FileNotFoundException("Unable to find " + fileNameWithoutExtension + " in " + resourcePath)
}

fun getResourceDir(resourcePath: String): File {
	val classLoader = object {}.javaClass.classLoader

	val resourceURL = classLoader.getResource(resourcePath)!!

	return File(resourceURL.file)
}