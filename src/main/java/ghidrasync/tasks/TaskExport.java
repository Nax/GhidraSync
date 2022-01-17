package ghidrasync.tasks;

import java.nio.file.Path;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidrasync.StateExporter;
import ghidrasync.Serializer;
import ghidrasync.State;

public class TaskExport extends Task {
    private Program program;
    private Path dir;

    public TaskExport(Program aProgram, Path aDir) {
        super("SyncPlugin - Export");
        program = aProgram;
        dir = aDir;
    }

    @Override
    public final void run(TaskMonitor mon) {
		try {
            mon.initialize(0);
            StateExporter exporter = new StateExporter(mon, program);
            State s = exporter.run();
			Serializer.serialize(dir, s);
		} catch (Exception e) {
			Msg.showError(this, null, "Error", e.getMessage(), e);
		}
    }
}
