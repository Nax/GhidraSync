package ghidrasync.state;

import java.util.UUID;

/* Base class for types */
public abstract class RawType {
    @SerializableField(index = 0) public UUID     uuid;
    @SerializableField(index = 1) public String   name;
}
