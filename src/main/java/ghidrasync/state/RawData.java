package ghidrasync.state;

public class RawData implements ISerializable {
	public String addr;
	public String name;
	public String type;

	public final Object[] toRecord() {
        return new Object[]{addr, name, type};
    }
}
