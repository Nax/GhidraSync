package ghidrasync.state;

@Serializable(name = "functions")
public class RawFunction {
    @SerializableField(index = 0) public String addr;
    @SerializableField(index = 1) public String prototype;
}
