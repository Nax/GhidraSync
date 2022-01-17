package ghidrasync.state;

import java.util.UUID;

@Serializable(name = "enums_values")
public class RawEnumValue {
	@SerializableField(index = 0) public UUID   uuid;
	@SerializableField(index = 1) public String name;
	@SerializableField(index = 2) public long 	value;
}
