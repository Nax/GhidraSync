package ghidrasync.state;

import java.util.UUID;

public class RawStruct implements ISerializable {
    public UUID     uuid;
    public String   name;
    public int      size;
    public boolean  union;
    
    public final Object[] toRecord() {
        return new Object[]{uuid, name, size, union ? 't' : 'f'};
    }
}
