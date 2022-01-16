package ghidrasync.state;

public class RawData {
	public String addr;
	public String name;
	public String type;

	public Object[] toRecord() {
        return new Object[]{addr, name, type};
    }
}
