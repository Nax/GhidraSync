package ghidrasync.state;

@Serializable(name = "typedefs")
public class RawTypedef extends RawType {
    @SerializableField(index = 2) public String typedef;
    @SerializableField(index = 3) public String comment;
}
