package ghidrasync;

import java.util.Iterator;
import java.util.UUID;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import ghidrasync.state.RawComment;
import ghidrasync.state.RawData;
import ghidrasync.state.RawEnum;
import ghidrasync.state.RawEnumValue;
import ghidrasync.state.RawFunction;
import ghidrasync.state.RawStruct;
import ghidrasync.state.RawStructField;
import ghidrasync.state.RawTypedef;

public class Manager {
	private TaskMonitor monitor;
	private Program program;
	private FlatProgramAPI api;

	public Manager(TaskMonitor aMonitor, Program aProgram) {
		monitor = aMonitor;
		program = aProgram;
		api = new FlatProgramAPI(aProgram, aMonitor);
	}
	
	public State export() {
		State s = new State();

		exportFunctions(s);
		exportData(s);
		exportComments(s);
		exportTypes(s);
		
		return s;
	}
	
	/*
	private void exportSymbols(State state) {
		SymbolTable symTable = program.getSymbolTable();
		SymbolIterator it = symTable.getAllSymbols(false);
		
		for (Symbol s : it) {
			if (s.getSource() != SourceType.USER_DEFINED)
				continue;
			if (s.getSymbolType() == SymbolType.FUNCTION) {
				Function func = api.getFunctionAt(s.getAddress());
				if (func != null) {
					RawFunction f = new RawFunction();
					f.addr = s.getAddress().toString();
					f.prototype = func.getSignature().getPrototypeString(true);
					state.funcs.add(f);
				}
			}
			else if (s.getSymbolType() != SymbolType.LABEL) {

			}

		}
	}

	private void exportData(State state) {
		SymbolTable symTable = api.getCurrentProgram().getSymbolTable();
		SymbolIterator it = symTable.getAllSymbols(false);
		
		for (Symbol s : it) {
			if (s.getSymbolType() != SymbolType.LABEL)
				continue;
			if (s.getSource() != SourceType.USER_DEFINED)
				continue;
			Data data = api.getDataAt(s.getAddress());
			if (data != null) {
				RawData d = new RawData();
				d.addr = s.getAddress().toString();
				d.name = s.getName();
				d.type = data.getDataType().getPathName();
				state.data.add(d);
			}
		}
	}
	*/

	private void exportFunctions(State state) {
		Listing listing = program.getListing();
		FunctionIterator iter = listing.getFunctions(true);

		monitor.setIndeterminate(true);
		monitor.setProgress(0);
		monitor.setMessage("Exporting functions");
	
		for (Function f : iter) {
			if (monitor.isCancelled())
				return;
			monitor.incrementProgress(1);
			Symbol s = f.getSymbol();
			if (s == null || s.getSource() != SourceType.USER_DEFINED)
				continue;
			RawFunction rf = new RawFunction();
			rf.addr = f.getEntryPoint().toString();
			rf.prototype = f.getSignature().getPrototypeString(true);
			state.funcs.add(rf);
		}
	}

	private void exportData(State state) {
		Listing listing = program.getListing();
		DataIterator iter = listing.getDefinedData(true);

		monitor.setIndeterminate(true);
		monitor.setProgress(0);
		monitor.setMessage("Exporting data");

		for (Data d : iter) {
			if (monitor.isCancelled())
				return;
			monitor.incrementProgress(1);
			Symbol[] s = d.getSymbols();
			if (s.length == 0 || s[0].getSource() != SourceType.USER_DEFINED)
				continue;
			RawData rd = new RawData();
			rd.addr = d.getAddress().toString();
			rd.name = s[0].getName();
			rd.type = d.getDataType().getPathName();
			state.data.add(rd);
		}
	}
	
	private void exportComments(State state) {
		Listing listing = program.getListing();
		AddressIterator iter = listing.getCommentAddressIterator(program.getMemory(), true);

		monitor.setIndeterminate(true);
		monitor.setProgress(0);
		monitor.setMessage("Exporting comments");

		for (Address a : iter) {
			if (monitor.isCancelled())
				return;
			monitor.incrementProgress(1);
	
			exportCommentType(state, a, 'e', api.getEOLComment(a));
			exportCommentType(state, a, 'b', api.getPreComment(a));
			exportCommentType(state, a, 'a', api.getPostComment(a));
			exportCommentType(state, a, 'r', api.getRepeatableComment(a));
			exportCommentType(state, a, 'p', api.getPlateComment(a));
		}
	}

	private void exportTypes(State state) {
		int t = program.getProgramUserData().startTransaction();

		TypeMapper typeMapper = new TypeMapper(program);
		ProgramBasedDataTypeManager typeManager = program.getDataTypeManager();

	/*
		Iterator<Composite> iterStruct = typeManager.getAllComposites();
		while (iterStruct.hasNext()) {
			Composite c = iterStruct.next();
			if (c.getUniversalID() == null)
				continue;
			UUID uuid = typeMapper.getUUID(c);
			RawStruct rs = new RawStruct();
			rs.uuid = uuid;
			rs.name = c.getPathName();
			rs.size = c.getLength();
			rs.union = !!(c instanceof Union);
			state.structs.add(rs);
		}
*/
		Iterator<DataType> iter = typeManager.getAllDataTypes();
		while (iter.hasNext()) {
			DataType dt = iter.next();
			if (dt.getUniversalID() == null)
				continue;
			UUID uuid = typeMapper.getUUID(dt);
			
			if (dt instanceof Composite) {
				RawStruct rs = new RawStruct();
				rs.uuid = uuid;
				rs.name = dt.getPathName();
				rs.size = dt.getLength();
				rs.union = !!(dt instanceof Union);
				state.structs.add(rs);
				exportStructFields(state, uuid, (Composite)dt);
			} else if (dt instanceof Enum) {
				Enum e = (Enum)dt;
				RawEnum re = new RawEnum();
				re.uuid = uuid;
				re.name = e.getPathName();
				state.enums.add(re);
				exportEnumValues(state, uuid, (Enum)dt);
			} else if (dt instanceof TypeDef) {
				TypeDef tdt = (TypeDef)dt;
				RawTypedef rt = new RawTypedef();
				rt.uuid = uuid;
				rt.name = tdt.getPathName();
				rt.typedef = tdt.getBaseDataType().getPathName();
				state.typedefs.add(rt);
			}
		}

		typeMapper.save();
		program.getProgramUserData().endTransaction(t);
	}

	private void exportStructFields(State state, UUID uuid, Composite dt) {
		for (var c : dt.getComponents()) {
			if (Undefined.isUndefined(c.getDataType()))
				continue;
			RawStructField rsf = new RawStructField();
			rsf.uuid = uuid;
			rsf.name = c.getFieldName();
			rsf.offset = c.getOffset();
			rsf.type = c.getDataType().getPathName();
			state.structsFields.add(rsf);
		}
	}

	private void exportEnumValues(State state, UUID uuid, Enum e) {
		for (String name : e.getNames()) {
			RawEnumValue rev = new RawEnumValue();
			rev.uuid = uuid;
			rev.name = name;
			rev.value = e.getValue(name);
			state.enumsValues.add(rev);
		}
	}

	private void exportCommentType(State state, Address a, char type, String comment) {
		if (comment != null) {
			RawComment rc = new RawComment();
			rc.addr = a.toString();
			rc.type = type;
			rc.comment = comment;
			state.comments.add(rc);
		}
	}
}
