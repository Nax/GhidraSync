package ghidrasync.state;

@Serializable(name = "functions")
public class RawFunction {
    @SerializableField(index = 0) public String addr;
    @SerializableField(index = 1) public String name;
    @SerializableField(index = 2) public String cc;
    @SerializableField(index = 3) public String returnType;
}
