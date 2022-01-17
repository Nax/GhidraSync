package ghidrasync.tasks;

import java.nio.file.Path;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidrasync.Serializer;
import ghidrasync.State;
import ghidrasync.StateImporter;

public class TaskImport extends Task {
    private Program program;
    private Path dir;

    public TaskImport(Program aProgram, Path aDir) {
        super("SyncPlugin - Import");
        program = aProgram;
        dir = aDir;
    }

    @Override
    public final void run(TaskMonitor mon) {
		try {
            mon.initialize(0);
			State state = Serializer.deserialize(dir);
            StateImporter importer = new StateImporter(mon, program);
            importer.run(state);
		} catch (Exception e) {
            Msg.showError(this, null, "Error", e.getMessage(), e);
		}
    }
}
