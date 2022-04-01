package ghidrasync.state;

@Serializable(name = "functypes")
public class RawFunctionType extends RawType {
    @SerializableField(index = 2) public String     cc;
    @SerializableField(index = 3) public String     returnType;
    @SerializableField(index = 4) public int        argCount;
    @SerializableField(index = 5) public boolean    variadic;
}
