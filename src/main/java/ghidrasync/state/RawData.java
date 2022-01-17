package ghidrasync.state;

@Serializable(name = "data")
public class RawData {
	@SerializableField(index = 0) public String addr;
	@SerializableField(index = 1) public String name;
	@SerializableField(index = 2) public String type;
}
