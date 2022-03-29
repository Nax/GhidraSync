package ghidrasync;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;
import java.util.UUID;
import java.util.stream.Stream;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;

import ghidrasync.state.*;


public class Serializer {
	@FunctionalInterface
	private static interface RunFunction {
		<T> void run(Path dir, Class<T> klass, ArrayList<T> list) throws IOException, ReflectiveOperationException;
	}

	public static void serialize(Path dir, State state) throws IOException, ReflectiveOperationException {
		runList(dir, state, Serializer::serializeList);
	}

	public static State deserialize(Path dir) throws IOException, ReflectiveOperationException {
		State state = new State();
		runList(dir, state, Serializer::deserializeList);
		return state;
	}

	private static void runList(Path dir, State state, RunFunction func) throws IOException, ReflectiveOperationException {
		func.run(dir, RawMemoryBlock.class, state.memory);
		func.run(dir, RawFunction.class, state.funcs);
		func.run(dir, RawData.class, state.data);
		func.run(dir, RawComment.class, state.comments);
		func.run(dir, RawStruct.class, state.structs);
		func.run(dir, RawStructField.class, state.structsFields);
		func.run(dir, RawEnum.class, state.enums);
		func.run(dir, RawEnumValue.class, state.enumsValues);
		func.run(dir, RawTypedef.class, state.typedefs);
		func.run(dir, RawFunctionType.class, state.functypes);
	}

	private static <T> void serializeList(Path dir, Class<T> klass, ArrayList<T> list) throws IOException, ReflectiveOperationException {
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

	private static <T> void deserializeList(Path dir, Class<T> klass, ArrayList<T> list) throws IOException, ReflectiveOperationException {
		Serializable ann = klass.getAnnotation(Serializable.class);
		CSVParser parser = createParser(dir, ann.name() + ".csv");
		Field[] fields = klass.getDeclaredFields();
		Arrays.sort(fields, Comparator.comparingInt(Serializer::fieldIndex));
		Iterator<CSVRecord> iter = parser.iterator();
		while (iter.hasNext()) {
			CSVRecord record = iter.next();
			T instance = klass.getConstructor().newInstance();
			for (Field f : fields) {
				String value = record.get(f.getName());
				deserializeObject(f, instance, value);
			}
			list.add(instance);
		}
		parser.close();
	}

	private static CSVPrinter createPrinter(Path dir, String filename) throws IOException {
		var writer = Files.newBufferedWriter(Path.of(dir.toString(), filename), StandardCharsets.UTF_8);
		return new CSVPrinter(writer, CSVFormat.RFC4180);
	}

	private static CSVParser createParser(Path dir, String filename) throws IOException {
		var formatBuilder = CSVFormat.Builder.create(CSVFormat.RFC4180);
		formatBuilder.setHeader();
		var format = formatBuilder.build();
		var reader = Files.newBufferedReader(Path.of(dir.toString(), filename), StandardCharsets.UTF_8);
		var parser = new CSVParser(reader, format);
		return parser;
	}

	private static int fieldIndex(Field f) {
		return f.getAnnotation(SerializableField.class).index();
	}

	private static Object serializeObject(Field f, Object elem) throws ReflectiveOperationException {
		Object o = f.get(elem);
		if (o instanceof Boolean) {
			o = ((Boolean)o).booleanValue() ? 't' : 'f';
		}
		return o;
	}

	private static void deserializeObject(Field f, Object elem, String value) throws ReflectiveOperationException {
		Object o;
		Class<?> klass = f.getType();

		/*
		 * This is probably very far from ideal.
		 * An actual Java dev should review this.
		 */
		if (klass == String.class) {
			o = value;
		} else if (klass == UUID.class) {
			o = UUID.fromString(value);
		} else if (klass == boolean.class) {
			o = value.equals("t");
		} else if (klass == long.class) {
			o = Long.parseLong(value);
		} else if (klass == int.class) {
			o = Integer.parseInt(value);
		} else if (klass == char.class) {
			o = value.charAt(0);
		} else {
			throw new ReflectiveOperationException("Deserialization error for type " + klass.getName());
		}

		f.set(elem, o);
	}
}
