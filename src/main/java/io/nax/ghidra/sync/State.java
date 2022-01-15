package io.nax.ghidra.sync;

import java.util.ArrayList;

public class State {
	private ArrayList<StateSymbol> 		symbols;
	private ArrayList<StateDataType> 	dataTypes;
	
	State() {
		symbols = new ArrayList<StateSymbol>();
		dataTypes = new ArrayList<StateDataType>();
	}
	
	public Iterable<StateSymbol> getSymbols() {
		return symbols;
	}
	
	public Iterable<StateDataType> getDataTypes() {
		return dataTypes;
	}
	
	public void addSymbol(StateSymbol sym) {
		symbols.add(sym);
	}
	
	public void addDataType(StateDataType dt) {
		dataTypes.add(dt);
	}
}
