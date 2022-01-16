package ghidrasync;

import java.util.Iterator;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
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
import ghidrasync.state.RawFunction;
import ghidrasync.state.RawType;

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
		Iterator<DataType> iter = typeManager.getAllDataTypes();
		while (iter.hasNext()) {
			DataType dt = iter.next();
			if (dt.getUniversalID() == null)
				continue;
			RawType rt = new RawType();
			rt.uuid = typeMapper.getTypeUUID(dt);
			rt.name = dt.getPathName();
			state.types.add(rt);
		}

		typeMapper.save();
		program.getProgramUserData().endTransaction(t);
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
