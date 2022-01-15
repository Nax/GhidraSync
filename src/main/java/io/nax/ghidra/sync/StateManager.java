package io.nax.ghidra.sync;

import ghidra.dbg.gadp.protocol.Gadp.DataType.DtCase;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

public class StateManager {
	private FlatProgramAPI api;

	StateManager(Program program) {
		api = new FlatProgramAPI(program);
	}
	
	public State export() {
		State s = new State();
		
		exportSymbols(s);
		//exportDataTypes(s);
		
		return s;
	}
	
	private void exportSymbols(State state) {
		SymbolTable symTable = api.getCurrentProgram().getSymbolTable();
		SymbolIterator it = symTable.getAllSymbols(false);
		
		for (Symbol s : it) {
			exportSymbol(state, s);
		}
	}
	
	private void exportSymbol(State state, Symbol sym) {
		if (sym.getSource() != SourceType.USER_DEFINED) {
			return;
		}
		
		StateSymbol r = new StateSymbol();
		r.type = "";
		if (sym.getSymbolType() == SymbolType.FUNCTION) {
			r.labelType = 'f';
			Function f = api.getFunctionAt(sym.getAddress());
			if (f != null) {
				r.type = f.getSignature().getPrototypeString(true);
				f.updateFunction(null, null, null, false, null, null);
			}
		} else if (sym.getSymbolType() == SymbolType.LABEL) {
			r.labelType = 'l';
			Data data = api.getDataAt(sym.getAddress());
			if (data != null) {
				r.type = data.getDataType().getPathName();
			}

		} else {
			return;
		}
	
		r.address = sym.getAddress().toString();
		r.name = sym.getName();

		state.addSymbol(r);
	}
	
	private void exportDataTypes(State state) {
		Data d = api.getFirstData();
		
		while (d != null)
		{
			DataType dt = d.getDataType();
			if (dt != null && d.isDefined())
			{
				StateDataType sdt = new StateDataType();
				sdt.address = d.getAddress().toString();
				sdt.type = dt.getPathName();
				state.addDataType(sdt);
			}
			d = api.getDataAfter(d);
		}
	}
}
