package ghidrasync.state;

import java.util.ArrayList;

public class RawStructUnion {
	static public class Field {
		public String name;
		public String type;
	}

	public String name;
	public ArrayList<Field>	fields = new ArrayList<Field>();
}
