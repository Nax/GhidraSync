package ghidrasync.state;

public class RawFunction {
    public String addr;
    public String prototype;

    public Object[] toRecord() {
        return new Object[]{addr, prototype};
    }
}
