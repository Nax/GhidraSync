package ghidrasync;

import java.nio.file.Path;
import java.util.ArrayList;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.memory.AddFileBytesMemoryBlockCmd;
import ghidra.app.cmd.memory.AddInitializedMemoryBlockCmd;
import ghidra.app.cmd.memory.AddUninitializedMemoryBlockCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidrasync.exception.ImportException;
import ghidrasync.exception.SyncException;
import ghidrasync.state.*;
public class StateImporter {
    private TaskMonitor     monitor;
    private Program         program;
    private TypeMapper      typeMapper;

    private static interface DataTypeFunction {
        public DataType run(CategoryPath path, String name, RawType data);
    }

	public StateImporter(PluginTool aTool, Program aProgram, TaskMonitor aMonitor) {
		program = aProgram;
		monitor = aMonitor;
        typeMapper = null;
	}

    public void run(State state) throws SyncException, LockException {
        int transaction = program.startTransaction("SyncPlugin Import");
        int transaction2 = program.getProgramUserData().startTransaction();
        typeMapper = new TypeMapper(program);
        /*
         * The order here is extremely important.
         * First we load the memory map, because it has no dependency.
         * Then we load enums and their values (no dependencies).
         * Then we load structs.
         * Then we load typedefs.
         */
        for (RawMemoryBlock rmb : state.memory)
            importMemory(rmb);
        makeTypes(state);
        for (RawEnum re : state.enums)
            importEnum(re);
        //for (RawFunction rf : state.funcs)
        //    importFunction(rf);
        typeMapper.save();
        program.getProgramUserData().endTransaction(transaction2);
        program.endTransaction(transaction, true);
    }

    private void makeTypes(State state) throws SyncException {
        makeType(state.enums, (path, name, t) -> new EnumDataType(path, name, ((RawEnum)t).size));
        makeType(state.structs, (path, name, t) -> new StructureDataType(path, name, ((RawStruct)t).size));
    }

    private void makeType(ArrayList<? extends RawType> data, DataTypeFunction factory) throws SyncException {
        ProgramBasedDataTypeManager types = program.getDataTypeManager();
    
        for (RawType t : data) {
            DataType dt = typeMapper.getType(t.uuid);
            CategoryPath path = new CategoryPath(t.name);
            if (dt == null)
            {
                dt = types.getDataType(path.getParent(), path.getName());
                if (dt == null) {
                    dt = factory.run(path.getParent(), path.getName(), t);
                    types.addDataType(dt, null);
                }
                typeMapper.update(dt, t.uuid);
            } else {
                try {
                    dt.setCategoryPath(path);
                } catch (DuplicateNameException e) {
                    throw new SyncException("Duplicate type: " + t.name);
                }
            }
        }
    }

    private void importMemory(RawMemoryBlock rmb) throws SyncException, LockException {
        /*
         * Multiple heuristics could be used here.
         * Right now we assume that same addr = same block.
         */
        Address addr = program.getAddressFactory().getAddress(rmb.addr);
        MemoryBlock block = program.getMemory().getBlock(addr);
        Command cmdAddmemoryBlock;

        if (block == null) {
            if (rmb.file != "") {
                FileBytes fb = null;
                for (var f : program.getMemory().getAllFileBytes()) {
                    if (f.getFilename() == rmb.file) {
                        fb = f;
                        break;
                    }
                }
                if (fb == null)
                    throw new ImportException("Could not find file " + rmb.file);
                cmdAddmemoryBlock = new AddFileBytesMemoryBlockCmd(rmb.name, "", "GhidraSync", addr, rmb.size, rmb.r, rmb.w, rmb.x, rmb.v, fb, rmb.fileOffset, rmb.o);
            } else {
                switch (rmb.type)
                {
                case 'u':
                    cmdAddmemoryBlock = new AddUninitializedMemoryBlockCmd(rmb.name, "", "GhidraSync", addr, rmb.size, rmb.r, rmb.w, rmb.x, rmb.v, rmb.o);
                    break;
                case 'i':
                    cmdAddmemoryBlock = new AddInitializedMemoryBlockCmd(rmb.name, "", "GhidraSync", addr, rmb.size, rmb.r, rmb.w, rmb.x, rmb.v, (byte)0, rmb.o);
                    break;
                default:
                    throw new ImportException("Unknown memory block type: " + rmb.type);
                }
            }
            cmdAddmemoryBlock.applyTo(program);
            block = program.getMemory().getBlock(addr);
            if (block == null)
                throw new ImportException("Could not create memory block " + rmb.name);
        } else {
            block.setName(rmb.name);
            block.setRead(rmb.r);
            block.setWrite(rmb.w);
            block.setExecute(rmb.x);
            block.setVolatile(rmb.v);
        }
    }

    private void importEnum(RawEnum re) {
        //DataType dt = typeMapper.getType(re.uuid);
        //if (dt == null) {
        //    EnumDataType e = new EnumDataType(re.name, re.size);
        //    program.getDataTypeManager().addDataType(e, null);
        //    typeMapper.update(e, re.uuid);
        //    dt = e;
        //}
    }

    private void importFunction(RawFunction func) {
        Address addr = program.getAddressFactory().getAddress(func.addr);

        DisassembleCommand cmdDisasm = new DisassembleCommand(addr, null, true);
        cmdDisasm.applyTo(program, monitor);

        CreateFunctionCmd cmdCreateFunc = new CreateFunctionCmd(addr, false);
        cmdCreateFunc.applyTo(program, monitor);
    
        Function f = program.getFunctionManager().getFunctionAt(addr);
        if (f == null) {
            Msg.showError(this, null, "Error", "Could not create function " + func.name);
        } else {
            try {
                f.setName(func.name, SourceType.USER_DEFINED);
            } catch (DuplicateNameException e) {
            } catch (InvalidInputException e) {
            }
        }
    }
}
