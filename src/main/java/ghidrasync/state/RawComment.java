package ghidrasync.state;

@Serializable(name = "comments")
public class RawComment {
    @SerializableField(index = 0) public String addr;
    @SerializableField(index = 1) public char   type;
    @SerializableField(index = 2) public String comment;
}
