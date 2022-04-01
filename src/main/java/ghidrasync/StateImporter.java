package ghidrasync;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.NoSuchElementException;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.memory.AddFileBytesMemoryBlockCmd;
import ghidra.app.cmd.memory.AddInitializedMemoryBlockCmd;
import ghidra.app.cmd.memory.AddUninitializedMemoryBlockCmd;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidrasync.exception.ImportException;
import ghidrasync.exception.SyncException;
import ghidrasync.state.*;
public class StateImporter {
    private TaskMonitor             monitor;
    private Program                 program;
    private TypeMapper              typeMapper;
    private DataTypeManagerService  dtms;

    private static interface DataTypeFunction {
        public DataType run(CategoryPath path, String name, RawType data) throws SyncException;
    }

	public StateImporter(PluginTool aTool, Program aProgram, TaskMonitor aMonitor) {
		program = aProgram;
		monitor = aMonitor;
        typeMapper = null;
        dtms = aTool.getService(DataTypeManagerService.class);
	}

    public void run(State state) throws SyncException, LockException {
        int transaction = program.startTransaction("SyncPlugin Import");
        int transaction2 = program.getProgramUserData().startTransaction();
        typeMapper = new TypeMapper(program);

        try {
            /*
            * The order here is extremely important.
            * First we load the memory map, because it has no dependency.
            * Then we load enums and their values (no dependencies).
            * Then we load structs.
            * Then we load typedefs.
            */
            for (RawMemoryBlock rmb : state.memory)
                importMemory(rmb);
            
            /* Build the different types (so refs exists later) */
            /* TODO: Check that the resolved types are of the right class (Enum, Struct, Union...) */
            /* TODO: There is probably a better way to do that in java, refactor it */
            makeTypes(state.enums, (path, name, t) -> new EnumDataType(path, name, ((RawEnum)t).size));
            makeTypes(state.structs, (path, name, t) -> ((RawStruct)t).union ? new UnionDataType(path, name) : new StructureDataType(path, name, ((RawStruct)t).size));
            makeTypes(state.functypes, (path, name, t) -> new FunctionDefinitionDataType(path, name));
            makeTypes(state.typedefs, (path, name, t) -> new TypedefDataType(path, name, parseType(((RawTypedef)t).typedef)));
            typeMapper.save();
            
            for (RawEnum x : state.enums)
                importEnum(x);
            for (RawEnumValue x : state.enumsValues)
                importEnumValue(x);
            for (RawFunctionType x : state.functypes)
                importFunctionType(x);
            for (RawFunctionTypeParam x : state.functypesParams)
                importFunctionTypeParam(x);
            for (RawStruct x : state.structs)
                importStruct(x);
            for (RawStructField x : state.structsFields)
                importStructField(x);
            /* Typedefs are already imported */

            for (RawData x : state.data)
                importData(x);
            
            //for (RawFunction rf : state.funcs)
            //    importFunction(rf);
        } catch(Exception e) {
            program.getProgramUserData().endTransaction(transaction2);
            program.endTransaction(transaction, false);
            throw e;
        }

        program.getProgramUserData().endTransaction(transaction2);
        program.endTransaction(transaction, true);
    }

    private void makeTypes(ArrayList<? extends RawType> data, DataTypeFunction factory) throws SyncException {
        ProgramBasedDataTypeManager types = program.getDataTypeManager();
    
        for (RawType t : data) {
            DataType dt = typeMapper.getType(t.uuid);
            CategoryPath path = new CategoryPath(t.name);
            if (dt == null)
            {
                dt = types.getDataType(path.getParent(), path.getName());
                if (dt == null) {
                    dt = factory.run(path.getParent(), path.getName(), t);
                    dt = types.addDataType(dt, null);
                }
                typeMapper.update(dt, t.uuid);
            } else {
                if (!(new CategoryPath(dt.getPathName()).equals(path))) {
                    try {
                        dt.setNameAndCategory(path.getParent(), path.getName());
                    } catch (DuplicateNameException e) {
                        throw new SyncException("Duplicate name: " + t.name + " :: " + dt.getPathName() + "(" + path.getName() + ", " + path.getParent().toString() + ")");
                    } catch (InvalidNameException e) {
                        throw new SyncException("Invalid name: " + t.name);
                    }
                }
            }
        }
    }

    private DataType parseType(String str) throws SyncException {
        str = str.replaceAll(" ", "");
        int[] indices = new int[]{str.indexOf('*'), str.indexOf('['), str.length()};
        int idx = Arrays.stream(indices).filter(i -> i >= 0).min().getAsInt();
        String type = str.substring(0, idx);
        str = str.substring(idx, str.length());

        DataTypeManager[] managers = dtms.getDataTypeManagers();
        DataType dt = null;
        
        for (DataTypeManager dtm : managers) {
            dt = dtm.getDataType(type);
            if (dt != null)
                break;
        }
        if (dt == null) {
            throw new SyncException("Could not find type " + str);
        }

        /* Handle pointers and arrays */
        while (!str.isEmpty()) {
            char c = str.charAt(0);
            switch (c) {
            case '[':
                int i = str.indexOf(']');
                String num = str.substring(1, i);
                str = str.substring(i + 1, str.length());
                dt = new ArrayDataType(dt, Integer.parseInt(num), dt.getLength());
                break;
            case '*':
                dt = new PointerDataType(dt);
                str = str.substring(1, str.length());
                break;
            default:
                throw new SyncException("Unknown char in type: " + c);
            }
        }

        return dt;
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
        Enum en = (Enum)typeMapper.getType(re.uuid);
        if (en.getLength() != re.size) {
            CategoryPath path = new CategoryPath(re.name);
            en.replaceWith(new EnumDataType(path.getParent(), path.getName(), re.size));
        }
        if (!re.comment.isEmpty() && !en.getDescription().equals(re.comment)) {
            en.setDescription(re.comment);
        }
    }

    private void importEnumValue(RawEnumValue val) {
        Enum en = (Enum)typeMapper.getType(val.uuid);
        try {
            long old = en.getValue(val.name);
            if (old != val.value || (!val.comment.isEmpty() && !val.comment.equals(en.getComment(val.name)))) {
                en.remove(val.name);
                en.add(val.name, val.value, val.comment);
            }
        } catch (NoSuchElementException e) {
            en.add(val.name, val.value, val.comment);
        }
    }

    private void importStruct(RawStruct raw) {
        Composite c = (Composite)typeMapper.getType(raw.uuid);
        if (!raw.union) {
            Structure s = (Structure)c;
            if (raw.size > s.getLength()) {
                s.growStructure(s.getLength() - raw.size);
            }
            while (raw.size < s.getLength()) {
                s.deleteAtOffset(raw.size);
            }
        }
        if (!raw.comment.isEmpty() && !c.getDescription().equals(raw.comment)) {
            c.setDescription(raw.comment);
        }
    }

    private void importStructField(RawStructField raw) throws SyncException {
        Composite c = (Composite)typeMapper.getType(raw.uuid);
        DataType t = parseType(raw.type);
        if (c instanceof Structure) {
            Structure s = (Structure)c;
            DataTypeComponent comp = s.getComponentContaining(raw.offset);
            /* Check for incompatible component */
            if (comp == null || comp.getOffset() != raw.offset || !comp.getDataType().getPathName().equals(t.getPathName())) {
                /* The component is not compatible, make space and replace */
                int length = t.getLength();
                if (length <= 0) {
                    length = raw.length;
                }
                int offset = (comp == null) ? raw.offset : raw.offset + comp.getLength();
                for (;;)
                {
                    DataTypeComponent oldComponent = s.getDefinedComponentAtOrAfterOffset(offset);
                    if (oldComponent == null || oldComponent.getOffset() >= raw.offset + length)
                        break;
                    s.deleteAtOffset(oldComponent.getOffset());
                }
                s.replaceAtOffset(raw.offset, t, raw.length, raw.name, raw.comment);
            } else {
                if (!comp.getFieldName().equals(raw.name)) {
                    try
                    {
                        comp.setFieldName(raw.name);
                    } catch (DuplicateNameException e) {
                        throw new SyncException("Duplicate struct field name: " + s.getName() + "." + raw.name);
                    }
                }
                if (!raw.comment.isEmpty() && !raw.comment.equals(comp.getComment())) {
                    comp.setComment(raw.comment);
                }
            }
        }
    }

    private void importFunctionType(RawFunctionType raw) throws SyncException {
        FunctionDefinition def = (FunctionDefinition)typeMapper.getType(raw.uuid);
        DataType returnType = parseType(raw.returnType);
        GenericCallingConvention cc = GenericCallingConvention.getGenericCallingConvention(raw.cc);

        /* Properties */
        if (!def.getReturnType().getPathName().equals(returnType.getPathName())) {
            def.setReturnType(returnType);
        }
        if (!def.getGenericCallingConvention().equals(cc)) {
            def.setGenericCallingConvention(cc);
        }
        if (def.hasVarArgs() != raw.variadic) {
            def.setVarArgs(raw.variadic);
        }

        /* Args */
        ParameterDefinition[] params = def.getArguments();
        if (params.length != raw.argCount) {
            ParameterDefinition[] newParams = new ParameterDefinitionImpl[raw.argCount];
            if (newParams.length < params.length) {
                /* Less args */
                for (int i = 0; i < newParams.length; ++i)
                    newParams[i] = params[i];
            } else {
                /* More args */
                for (int i = 0; i < params.length; ++i)
                    newParams[i] = params[i];
                for (int i = params.length; i < newParams.length; ++i)
                    newParams[i] = new ParameterDefinitionImpl("_tmpArg" + Integer.toString(i), Undefined.getUndefinedDataType(1), "");
            }
            def.setArguments(newParams);
        }

        /* Comment */
        if (!raw.comment.isEmpty() && !raw.comment.equals(def.getDescription())) {
            def.setDescription(raw.comment);
        }
    }

    private void importFunctionTypeParam(RawFunctionTypeParam raw) throws SyncException {
        FunctionDefinition def = (FunctionDefinition)typeMapper.getType(raw.uuid);
        ParameterDefinition[] params = def.getArguments();
        ParameterDefinition d = params[raw.ord];
        DataType t = parseType(raw.type);

        if (!d.getName().equals(raw.name)) {
            d.setName(raw.name);
        }
        if (!d.getDataType().getPathName().equals(t.getPathName())) {
            d.setDataType(t);
        }
    }

    private void importData(RawData raw) throws SyncException {
        Address addr = program.getAddressFactory().getAddress(raw.addr);
        Data d = DataUtilities.getDataAtAddress(program, addr);
        DataType t = parseType(raw.type);
        if (d == null || !d.getDataType().getPathName().equals(t.getPathName())) {
            try {
                d = DataUtilities.createData(program, addr, t, raw.size, false, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            } catch (CodeUnitInsertionException e) {
                throw new SyncException("Code conflict when applying data at " + raw.addr);
            }
        }

        if (d.getNames().length == 0 || !d.getNames()[0].equals(raw.name)) {
            SymbolTable st = program.getSymbolTable();
            if (st.hasSymbol(addr)) {
                Symbol s = st.getSymbols(addr)[0];
                try {
                    s.setName(raw.name, SourceType.USER_DEFINED);
                } catch (Exception e) {
                    throw new SyncException("Error renaming symbol " + s.getName() + " to " + raw.name);
                }
            } else {
                try {
                    st.createLabel(addr, raw.name, SourceType.USER_DEFINED);
                } catch (InvalidInputException e) {
                    throw new SyncException("Error creating symbol " + raw.name);
                }
            }
        }
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
