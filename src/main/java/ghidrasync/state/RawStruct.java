package ghidrasync.state;

@Serializable(name = "structs")
public class RawStruct extends RawType {
    @SerializableField(index = 2) public int        size;
    @SerializableField(index = 3) public boolean    union;
    @SerializableField(index = 4) public String     comment;
}
