package ghidrasync;

import java.util.ArrayList;
import ghidrasync.state.*;

public class State {
	public ArrayList<RawMemoryBlock>	memory = new ArrayList<>();
	public ArrayList<RawFunction> 		funcs = new ArrayList<>();
	public ArrayList<RawData> 			data = new ArrayList<>();
	public ArrayList<RawComment> 		comments = new ArrayList<>();
	public ArrayList<RawStruct> 		structs = new ArrayList<>();
	public ArrayList<RawStructField> 	structsFields = new ArrayList<>();
	public ArrayList<RawEnum> 			enums = new ArrayList<>();
	public ArrayList<RawEnumValue> 		enumsValues = new ArrayList<>();
	public ArrayList<RawTypedef> 		typedefs = new ArrayList<>();
}
