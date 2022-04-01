package ghidrasync.state;

import java.util.UUID;

@Serializable(name = "structs_fields")
public class RawStructField {
	@SerializableField(index = 0) public UUID 	uuid;
	@SerializableField(index = 1) public String	name;
	@SerializableField(index = 2) public int	offset;
	@SerializableField(index = 3) public int	length;
	@SerializableField(index = 4) public String	type;
}
