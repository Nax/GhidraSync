package ghidrasync;

import java.util.ArrayList;
import ghidrasync.state.*;

public class State {
	public ArrayList<RawFunction> funcs = new ArrayList<RawFunction>();
	public ArrayList<RawData> data = new ArrayList<RawData>();
	public ArrayList<RawStructUnion> structs = new ArrayList<RawStructUnion>();
	public ArrayList<RawStructUnion> unions = new ArrayList<RawStructUnion>();
	public ArrayList<RawComment> comments = new ArrayList<RawComment>();
}
