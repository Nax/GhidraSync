package ghidrasync.state;

@Serializable(name = "enums")
public class RawEnum extends RawType {
    @SerializableField(index = 2) public int    size;
    @SerializableField(index = 3) public String comment;
}
