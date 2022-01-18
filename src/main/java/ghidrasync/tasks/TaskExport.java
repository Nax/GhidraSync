package ghidrasync.tasks;

import java.nio.file.Path;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidrasync.StateExporter;
import ghidrasync.Serializer;
import ghidrasync.State;

public class TaskExport extends Task {
    private PluginTool tool;
    private Program program;
    private Path dir;

    public TaskExport(PluginTool aTool, Program aProgram, Path aDir) {
        super("SyncPlugin - Export");
        tool = aTool;
        program = aProgram;
        dir = aDir;
    }

    @Override
    public final void run(TaskMonitor mon) {
		try {
            mon.initialize(0);
            StateExporter exporter = new StateExporter(tool, program, mon);
            State s = exporter.run();
			Serializer.serialize(dir, s);
		} catch (Exception e) {
			Msg.showError(this, null, "Error", e.getMessage(), e);
		}
    }
}
