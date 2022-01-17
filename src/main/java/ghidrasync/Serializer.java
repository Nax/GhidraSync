package ghidrasync;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.stream.Stream;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import ghidrasync.state.*;


public class Serializer {
	@FunctionalInterface
	private static interface RunFunction {
		<T> void run(File dir, Class<T> klass, ArrayList<T> list) throws IOException;
	}

	public static void serialize(File dir, State state) throws IOException {
		runList(dir, state, Serializer::serializeList);
	}

	private static void runList(File dir, State state, RunFunction func) throws IOException {
		func.run(dir, RawFunction.class, state.funcs);
		func.run(dir, RawData.class, state.data);
		func.run(dir, RawComment.class, state.comments);
		func.run(dir, RawStruct.class, state.structs);
		func.run(dir, RawStructField.class, state.structsFields);
		func.run(dir, RawEnum.class, state.enums);
		func.run(dir, RawEnumValue.class, state.enumsValues);
		func.run(dir, RawTypedef.class, state.typedefs);
	}

	private static <T> void serializeList(File dir, Class<T> klass, ArrayList<T> list) throws IOException {
		Serializable ann = klass.getAnnotation(Serializable.class);
		CSVPrinter printer = createPrinter(dir, ann.name() + ".csv");
		Field[] fields = klass.getDeclaredFields();
		Arrays.sort(fields, Comparator.comparingInt(Serializer::fieldIndex));
		printer.printRecord(Stream.of(fields).map(Field::getName).toArray());
		for (T elem : list) {
			ArrayList<Object> objs = new ArrayList<>();
			for (Field f : fields) {
				objs.add(serializeObject(f, elem));
			}
			printer.printRecord(objs);
		}
		printer.close();
	}

	private static CSVPrinter createPrinter(File dir, String filename) throws IOException {
		var writer = Files.newBufferedWriter(Path.of(dir.toString(), filename), StandardCharsets.UTF_8);
		return new CSVPrinter(writer, CSVFormat.RFC4180);
	}

	private static int fieldIndex(Field f) {
		return f.getAnnotation(SerializableField.class).index();
	}

	private static Object serializeObject(Field f, Object elem) {
		try {
			Object o = f.get(elem);
			if (o instanceof Boolean) {
				o = ((Boolean)o).booleanValue() ? 't' : 'f';
			}
			return o;
		} catch (IllegalAccessException e) {
			System.err.println(e);
			return null;
		}
	}
}
