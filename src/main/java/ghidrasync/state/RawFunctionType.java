package ghidrasync.state;

import java.util.UUID;

@Serializable(name = "functypes")
public class RawFunctionType {
    @SerializableField(index = 0) public UUID   uuid;
    @SerializableField(index = 1) public String name;
    @SerializableField(index = 2) public String cc;
    @SerializableField(index = 3) public String returnType;
}
