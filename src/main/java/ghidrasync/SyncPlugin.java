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
import java.io.IOException;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Import/Export commands to synchronize a ghidra project over source control",
	description = "Import/Export commands to synchronize a ghidra project over source control"
)
//@formatter:on
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
		DockingAction action;

		action = new DockingAction("Export", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				File dir = askFile("Sync Export");
				if (dir == null)
					return;
				syncExport(dir);
			}
		};
		action.setMenuBarData(new MenuData(new String[] { "Sync", "Export..." }, null, "group1", MenuData.NO_MNEMONIC, "1"));
		action.setDescription("Export the current project in text format");
		action.setEnabled(true);
		tool.addAction(action);
	}
	
	private void syncExport(File dir) {
		Manager manager = new Manager(getCurrentProgram());
		Serializer serializer = new Serializer();

		State s = manager.export();

		try {
			serializer.serialize(dir, s);
		} catch (IOException e) {
			System.err.println(e);
		}
	}
	
	/**
	 * Method to ask for a file.
	 * @param title popup window title
	 * @return the file chosen, or null
	 */
	private File askFile(final String title) {
		final GhidraFileChooser chooser = new GhidraFileChooser(tool.getActiveWindow());
		chooser.setApproveButtonText("Ok");
		chooser.setTitle(title);
		chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
		return chooser.getSelectedFile();
	}
}
