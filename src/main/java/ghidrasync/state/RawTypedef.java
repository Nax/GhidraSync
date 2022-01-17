package ghidrasync.state;

import java.util.UUID;

@Serializable(name = "typedefs")
public class RawTypedef {
    @SerializableField(index = 0) public UUID   uuid;
    @SerializableField(index = 1) public String name;
    @SerializableField(index = 2) public String typedef;
}
