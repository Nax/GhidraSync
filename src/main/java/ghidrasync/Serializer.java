package ghidrasync;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import ghidrasync.state.ISerializable;

public class Serializer {
	public void serialize(File dir, State state) throws IOException {
		serializeList(dir, "functions.csv", new String[]{"addr", "prototype"}, state.funcs);
		serializeList(dir, "data.csv", new String[]{"addr", "name", "type"}, state.data);
		serializeList(dir, "comments.csv", new String[]{"addr", "type", "comment"}, state.comments);
		serializeList(dir, "structs.csv", new String[]{"uuid", "name", "size", "union"}, state.structs);
		serializeList(dir, "typedefs.csv", new String[]{"uuid", "name", "typedef"}, state.typedefs);
	}

	private void serializeList(File dir, String filename, String[] header, Iterable<? extends ISerializable> list) throws IOException {
		var printer = createPrinter(dir, filename);
		printer.printRecord((Object[])header);
		for (var x : list) {
			printer.printRecord(x.toRecord());
		}
		printer.close();
	}

	private CSVPrinter createPrinter(File dir, String filename) throws IOException {
		var writer = Files.newBufferedWriter(Path.of(dir.toString(), filename), StandardCharsets.UTF_8);
		return new CSVPrinter(writer, CSVFormat.RFC4180);
	}
}
