package ghidrasync.state;

@Serializable(name = "functions_params")
public class RawFunctionParam {
    @SerializableField(index = 0) public String addr;
    @SerializableField(index = 1) public int ord;
    @SerializableField(index = 2) public String name;
    @SerializableField(index = 3) public String type;
}
