package ghidrasync;

import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.mem.FileBytes;
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
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import ghidrasync.exception.NotSupportedException;
import ghidrasync.exception.SyncException;
import ghidrasync.state.*;

public class StateExporter {
	private TaskMonitor monitor;
	private Program program;
	private FlatProgramAPI api;

	public StateExporter(PluginTool aTool, Program aProgram, TaskMonitor aMonitor) {
		monitor = aMonitor;
		program = aProgram;
		api = new FlatProgramAPI(aProgram, aMonitor);
	}
	
	public State run() throws SyncException {
		State s = new State();

		exportMemory(s);
		exportFunctions(s);
		exportData(s);
		exportComments(s);
		exportTypes(s);
		
		return s;
	}

	private void exportMemory(State state) throws SyncException {
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			if (b.isMapped())
				throw new NotSupportedException("Memory Block " + b.getName() + " is mapped.");

			RawMemoryBlock rmb = new RawMemoryBlock();
			rmb.addr = b.getStart().toString();
			rmb.name = b.getName();
			rmb.size = b.getSize();
			rmb.r = b.isRead();
			rmb.w = b.isWrite();
			rmb.x = b.isExecute();
			rmb.v = b.isVolatile();
			rmb.o = b.isOverlay();
			rmb.type = b.isInitialized() ? 'i' : 'u';

			List<MemoryBlockSourceInfo> sources = b.getSourceInfos();
			if (sources.size() > 1)
				throw new NotSupportedException("Memory Block " + b.getName() + " has more than one source.");
			if (sources.size() == 0)
				throw new NotSupportedException("Memory Block " + b.getName() + " has more no source.");
	
			MemoryBlockSourceInfo source = sources.get(0);
			Optional<FileBytes> ofb = source.getFileBytes();
			if (!ofb.isPresent()) {
				rmb.file = "";
				rmb.fileOffset = 0;
			} else {
				FileBytes fb = ofb.get();
				rmb.file = fb.getFilename();
				rmb.fileOffset = source.getFileBytesOffset();
			}

			state.memory.add(rmb);
		}
	}

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
			rf.name = f.getName();
			rf.cc = f.getCallingConventionName();
			rf.returnType = f.getReturnType().getPathName();
			rf.argCount = f.getParameterCount();
			rf.variadic = f.hasVarArgs();
			rf.noreturn = f.hasNoReturn();
			state.funcs.add(rf);
			exportFunctionParams(state, f);
		}
	}

	private void exportFunctionParams(State state, Function f) {
		for (int i = 0; i < f.getParameterCount(); ++i) {
			Parameter param = f.getParameter(i);
			if (param.isAutoParameter() || param.getSource() != SourceType.USER_DEFINED)
				continue;
			RawFunctionParam p = new RawFunctionParam();
			p.addr = f.getEntryPoint().toString();
			p.ord = i;
			p.type = param.getDataType().getPathName();
			p.name = param.getName();
			state.funcsParams.add(p);
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
			rd.size = d.getLength();
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

		try {
			ProgramBasedDataTypeManager typeManager = program.getDataTypeManager();

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
					rs.comment = dt.getDescription();
					state.structs.add(rs);
					exportStructFields(state, uuid, (Composite)dt);
				} else if (dt instanceof Enum) {
					Enum e = (Enum)dt;
					RawEnum re = new RawEnum();
					re.uuid = uuid;
					re.name = e.getPathName();
					re.size = e.getLength();
					re.comment = e.getDescription();
					state.enums.add(re);
					exportEnumValues(state, uuid, (Enum)dt);
				} else if (dt instanceof TypeDef) {
					TypeDef tdt = (TypeDef)dt;
					RawTypedef rt = new RawTypedef();
					rt.uuid = uuid;
					rt.name = tdt.getPathName();
					rt.typedef = tdt.getBaseDataType().getPathName();
					rt.comment = tdt.getDescription();
					state.typedefs.add(rt);
				} else if (dt instanceof FunctionDefinition) {
					FunctionDefinition fd = (FunctionDefinition)dt;
					RawFunctionType rft = new RawFunctionType();
					rft.uuid = uuid;
					rft.name = fd.getPathName();
					rft.cc = fd.getGenericCallingConvention().name();
					rft.returnType = fd.getReturnType().getPathName();
					rft.argCount = fd.getArguments().length;
					rft.variadic = fd.hasVarArgs();
					rft.comment = fd.getDescription();
					state.functypes.add(rft);
					exportFunctionTypeParams(state, uuid, fd);
				}
			}
			typeMapper.save();
		} finally {
			program.getProgramUserData().endTransaction(t);
		}
	}

	private void exportFunctionTypeParams(State state, UUID uuid, FunctionDefinition f) {
		ParameterDefinition[] params = f.getArguments();
		for (int i = 0; i < params.length; ++i) {
			ParameterDefinition param = params[i];
			RawFunctionTypeParam p = new RawFunctionTypeParam();
			p.uuid = uuid;
			p.ord = i;
			p.type = param.getDataType().getPathName();
			p.name = param.getName();
			state.functypesParams.add(p);
		}
	}

	private void exportStructFields(State state, UUID uuid, Composite dt) {
		for (var c : dt.getComponents()) {
			if (Undefined.isUndefined(c.getDataType()))
				continue;
			RawStructField rsf = new RawStructField();
			rsf.uuid = uuid;
			rsf.name = Utils.strNoNull(c.getFieldName());
			rsf.offset = c.getOffset();
			rsf.length = c.getLength();
			rsf.type = c.getDataType().getPathName();
			rsf.comment = c.getComment();
			state.structsFields.add(rsf);
		}
	}

	private void exportEnumValues(State state, UUID uuid, Enum e) {
		for (String name : e.getNames()) {
			RawEnumValue rev = new RawEnumValue();
			rev.uuid = uuid;
			rev.name = name;
			rev.value = e.getValue(name);
			rev.comment = e.getComment(name);
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
