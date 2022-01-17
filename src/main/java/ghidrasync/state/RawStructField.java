package ghidrasync.state;

import java.util.UUID;

public class RawStructField implements ISerializable {
	public UUID 	uuid;
	public String 	name;
	public int 		offset;
	public String 	type;

	public final Object[] toRecord() {
		return new Object[]{uuid, name, offset, type};
	}
}

