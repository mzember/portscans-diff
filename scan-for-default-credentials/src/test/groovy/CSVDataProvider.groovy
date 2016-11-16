class CSVDataProvider implements Iterable<Iterable<String>> {
	File dataFile

	CSVDataProvider(File file) {
		dataFile = file
	}

	@Override
	Iterator<Iterable<String>> iterator() {
		List<List<String>> list = new ArrayList<List<String>>()

		def lines = dataFile.readLines()

		for (line in lines) {
			def cellArray = line.split(",")

			def cells = cellArray.toList()

			list.add(cells)
		}

		return list.iterator()
	}

}