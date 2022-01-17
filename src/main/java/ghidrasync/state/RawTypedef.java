package ghidrasync.state;

import java.util.UUID;

public class RawTypedef implements ISerializable {
    public UUID     uuid;
    public String   name;
    public String   typedef;
    
    public final Object[] toRecord() {
        return new Object[]{uuid, name, typedef};
    }
}
