package ghidrasync.state;

import java.util.UUID;

@Serializable(name = "structs")
public class RawStruct {
    @SerializableField(index = 0) public UUID     uuid;
    @SerializableField(index = 1) public String   name;
    @SerializableField(index = 2) public int      size;
    @SerializableField(index = 3) public boolean  union;
}
