package ghidrasync;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidrasync.state.RawData;
import ghidrasync.state.RawFunction;

public class Manager {
	private FlatProgramAPI api;

	Manager(Program program) {
		api = new FlatProgramAPI(program);
	}
	
	public State export() {
		State s = new State();
		
		exportFunctions(s);
		exportData(s);
		//exportDataTypes(s);
		
		return s;
	}
	
	private void exportFunctions(State state) {
		SymbolTable symTable = api.getCurrentProgram().getSymbolTable();
		SymbolIterator it = symTable.getAllSymbols(false);
		
		for (Symbol s : it) {
			if (s.getSymbolType() != SymbolType.FUNCTION)
				continue;
			if (s.getSource() != SourceType.USER_DEFINED)
				continue;
			Function func = api.getFunctionAt(s.getAddress());
			if (func != null) {
				RawFunction f = new RawFunction();
				f.addr = s.getAddress().toString();
				f.prototype = func.getSignature().getPrototypeString(true);
				state.funcs.add(f);
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

	/*
	private void exportDataTypes(State state) {
		Data d = api.getFirstData();
		
		while (d != null)
		{
			DataType dt = d.getDataType();
			if (dt != null && d.isDefined())
			{
				DataType sdt = new DataType();
				sdt.address = d.getAddress().toString();
				sdt.type = dt.getPathName();
				state.addDataType(sdt);
			}
			d = api.getDataAfter(d);
		}
	}
	*/
}
