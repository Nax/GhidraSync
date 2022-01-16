package ghidrasync.state;

import java.util.UUID;

public class RawType implements ISerializable {
    public UUID     uuid;
    public String   name;
    
    public final Object[] toRecord() {
        return new Object[]{uuid, name};
    }
}
