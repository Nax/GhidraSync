package ghidrasync.tasks;

import java.io.File;
import java.io.IOException;

import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidrasync.Manager;
import ghidrasync.Serializer;
import ghidrasync.State;

public class TaskExport extends Task {
    private Program program;
    private File dir;

    public TaskExport(Program aProgram, File aDir) {
        super("SyncPlugin - Export");
        program = aProgram;
        dir = aDir;
    }

    public final void run(TaskMonitor mon) {
        mon.initialize(0);
		Manager manager = new Manager(mon, program);
		Serializer serializer = new Serializer();

		State s = manager.export();
		try {
			serializer.serialize(dir, s);
		} catch (IOException e) {
			System.err.println(e);
		}
    }
}
