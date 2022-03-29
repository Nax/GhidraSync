package ghidrasync.state;

import java.util.UUID;

@Serializable(name = "functypes_params")
public class RawFunctionTypeParam {
    @SerializableField(index = 0) public UUID uuid;
    @SerializableField(index = 1) public int ord;
    @SerializableField(index = 2) public String name;
    @SerializableField(index = 3) public String type;
}
