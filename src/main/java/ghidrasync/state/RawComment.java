package ghidrasync.state;

public class RawComment implements ISerializable {
    public String addr;
    public char type;
    public String comment;

    public final Object[] toRecord() {
        return new Object[]{addr, type, comment};
    }
}
