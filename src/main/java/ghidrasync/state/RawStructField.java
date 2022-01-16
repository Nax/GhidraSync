package ghidrasync.state;

public class RawStructField implements ISerializable {
	public String 	struct;
	public String 	name;
	public int 		offset;
	public String 	type;

	public final Object[] toRecord() {
		return new Object[]{struct, name, offset, type};
	}
}

