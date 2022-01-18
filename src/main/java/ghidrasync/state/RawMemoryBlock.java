package ghidrasync.state;

@Serializable(name = "memory")
public class RawMemoryBlock {
    @SerializableField(index = 0)  public String     addr;
    @SerializableField(index = 1)  public String     name;
    @SerializableField(index = 2)  public long       size;
    @SerializableField(index = 3)  public char       type;
    @SerializableField(index = 4)  public String     file;
    @SerializableField(index = 5)  public long       fileOffset;
    @SerializableField(index = 6)  public boolean    r;
    @SerializableField(index = 7)  public boolean    w;
    @SerializableField(index = 8)  public boolean    x;
    @SerializableField(index = 9)  public boolean    v;
    @SerializableField(index = 9)  public boolean    o;
}
