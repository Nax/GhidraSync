package ghidrasync.state;

import java.util.UUID;

@Serializable(name = "enums")
public class RawEnum {
    @SerializableField(index = 0) public UUID     uuid;
    @SerializableField(index = 1) public String   name;
}
