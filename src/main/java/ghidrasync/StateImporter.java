package ghidrasync;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidrasync.state.RawFunction;

public class StateImporter {
	private TaskMonitor     monitor;
	private Program         program;
	private FlatProgramAPI  api;

	public StateImporter(TaskMonitor aMonitor, Program aProgram) {
		monitor = aMonitor;
		program = aProgram;
		api = new FlatProgramAPI(aProgram, aMonitor);
	}

    public void run(State state) {
        int transaction = program.startTransaction("SyncPlugin Import");
        for (RawFunction rf : state.funcs) {
            importFunction(rf);
        }
        program.endTransaction(transaction, true);
    }

    private void importFunction(RawFunction func) {
        Address addr = program.getAddressFactory().getAddress(func.addr);

        DisassembleCommand cmdDisasm = new DisassembleCommand(addr, null, true);
        cmdDisasm.applyTo(program, monitor);

        CreateFunctionCmd cmdCreateFunc = new CreateFunctionCmd(addr, false);
        cmdCreateFunc.applyTo(program, monitor);
    
        Function f = program.getFunctionManager().getFunctionAt(addr);
        if (f == null) {
            Msg.showError(this, null, "Error ..?", "Could not create function " + func.name);
        } else {
            try {
                f.setName(func.name, SourceType.USER_DEFINED);
            } catch (DuplicateNameException e) {
            } catch (InvalidInputException e) {
            }
        }
    }
}
