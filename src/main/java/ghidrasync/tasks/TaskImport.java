package ghidrasync.tasks;

import java.nio.file.Path;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidrasync.Serializer;
import ghidrasync.State;
import ghidrasync.StateImporter;

public class TaskImport extends Task {
    private PluginTool tool;
    private Program program;
    private Path dir;

    public TaskImport(PluginTool aTool, Program aProgram, Path aDir) {
        super("SyncPlugin - Import");
        tool = aTool;
        program = aProgram;
        dir = aDir;
    }

    @Override
    public final void run(TaskMonitor mon) {
		try {
            mon.initialize(0);
			State state = Serializer.deserialize(dir);
            StateImporter importer = new StateImporter(tool, program, mon);
            importer.run(state);
		} catch (Exception e) {
            Msg.showError(this, null, "Error", e.getMessage(), e);
		}
    }
}
