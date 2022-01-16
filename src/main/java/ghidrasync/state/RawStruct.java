package ghidrasync.state;

public class RawStruct implements ISerializable {
    public String   name;
    public int      size;
    public boolean  union;

    public final Object[] toRecord() {
        return new Object[]{name, size, union};
    }
}
