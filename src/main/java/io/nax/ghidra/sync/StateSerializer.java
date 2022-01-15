package io.nax.ghidra.sync;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class StateSerializer {
	StateSerializer() {
	}
	
	public void serialize(File dir, State state) throws IOException {
		serializeSymbols(dir, state);
		serializeDataTypes(dir, state);
	}
	
	private void serializeSymbols(File dir, State state) throws IOException {
		OutputStream out = openFileWrite(dir, "symbols.csv");
		for (StateSymbol s : state.getSymbols()) {
			out.write(s.address.getBytes());
			out.write(',');
			out.write(s.name.getBytes());
			out.write(',');
			out.write(s.labelType);
			out.write(',');
			out.write(s.type.getBytes());
			out.write('\n');
		}
		out.close();
	}
	
	private void serializeDataTypes(File dir, State state) throws IOException {
		OutputStream out = openFileWrite(dir, "data.csv");
		for (StateDataType dt : state.getDataTypes()) {
			out.write(dt.address.getBytes());
			out.write(',');
			out.write(dt.type.getBytes());
			out.write('\n');
		}
		out.close();
	}
	
	private OutputStream openFileWrite(File dir, String filename) throws IOException {
		return Files.newOutputStream(Paths.get(dir.toString(), filename));
	}
}
