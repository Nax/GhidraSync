package ghidrasync.state;

public class RawFunction implements ISerializable {
    public String addr;
    public String prototype;

    public final Object[] toRecord() {
        return new Object[]{addr, prototype};
    }
}
