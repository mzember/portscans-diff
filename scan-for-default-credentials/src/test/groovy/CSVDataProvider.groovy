class CSVDataProvider implements Iterable<Iterable<String>> {
	File file

	CSVDataProvider(String path) {
		file = new File(path)
	}

	@Override
	Iterator<Iterable<String>> iterator() {
		List<List<String>> list = new ArrayList<List<String>>()

		def lines = file.readLines()

		for (line in lines) {
			def cellArray = line.split(",")

			def cells = cellArray.toList()

			list.add(cells)
		}

		return list.iterator()
	}

}