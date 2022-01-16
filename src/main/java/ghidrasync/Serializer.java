package ghidrasync;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

public class Serializer {
	public void serialize(File dir, State state) throws IOException {
		serializeFunctions(dir, state);
		serializeData(dir, state);
	}
	
	private void serializeFunctions(File dir, State state) throws IOException {
		var printer = createPrinter(dir, "functions.csv");
		printer.printRecord("addr", "prototype");
		for (var f : state.funcs) {
			printer.printRecord(f.toRecord());
		}
		printer.close();
	}

	private void serializeData(File dir, State state) throws IOException {
		var printer = createPrinter(dir, "data.csv");
		printer.printRecord("addr", "name", "type");
		for (var f : state.data) {
			printer.printRecord(f.toRecord());
		}
		printer.close();
	}

	private CSVPrinter createPrinter(File dir, String filename) throws IOException {
		var writer = Files.newBufferedWriter(Path.of(dir.toString(), filename), StandardCharsets.UTF_8);
		return new CSVPrinter(writer, CSVFormat.RFC4180);
	}
}
