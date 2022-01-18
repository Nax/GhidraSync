/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidrasync;

import java.io.File;
import java.nio.file.Path;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidrasync.tasks.TaskExport;
import ghidrasync.tasks.TaskImport;

@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Import/Export commands to synchronize a ghidra project over source control",
	description = "Import/Export commands to synchronize a ghidra project over source control"
)
public class SyncPlugin extends ProgramPlugin {
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public SyncPlugin(PluginTool tool) {
		super(tool, true, true);
	}

	@Override
	public void init() {
		super.init();
		
		createActions();
	}
	
	private void createActions() {
		DockingAction actionExport = new DockingAction("Export", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Path dir = askFile("Sync Export");
				if (dir == null)
					return;
				tool.execute(new TaskExport(tool, currentProgram, dir));
			}
		};
		actionExport.setMenuBarData(new MenuData(new String[] { "Sync", "Export..." }, null, "group1", MenuData.NO_MNEMONIC, "1"));
		actionExport.setDescription("Export the current project in text format");
		actionExport.setEnabled(true);
		tool.addAction(actionExport);

		DockingAction actionImport = new DockingAction("Import", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {		
				Path dir = askFile("Sync Import");
				if (dir == null)
					return;
				tool.execute(new TaskImport(tool, currentProgram, dir));
			}
		};
		actionImport.setMenuBarData(new MenuData(new String[] { "Sync", "Import..." }, null, "group1", MenuData.NO_MNEMONIC, "1"));
		actionImport.setDescription("Import a previously exported project");
		actionImport.setEnabled(true);
		tool.addAction(actionImport);
	}
	
	/**
	 * Method to ask for a file.
	 * @param title popup window title
	 * @return the file chosen, or null
	 */
	private Path askFile(final String title) {
		final GhidraFileChooser chooser = new GhidraFileChooser(tool.getActiveWindow());
		chooser.setApproveButtonText("Ok");
		chooser.setTitle(title);
		chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
		File f = chooser.getSelectedFile();
		if (f == null)
			return null;
		return f.toPath();
	}
}
