/*
 * Created on Feb 25, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.io.File;

import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JMenuBar;
import javax.swing.KeyStroke;

/**
 * @author srosset
 *
 * A Swing GUI tool to display graphs based on information
 * collected from a running society.
 */
public class NetTool extends JFrame {

	private JMenuBar         m_menu;
	private GraphFileHandler m_graphFileHandler;
	private GraphRenderer    m_graphRenderer;
	private SocietyModel     m_societyModel;
	
	private static final String MENU_FILE = "File";
	private static final String MENU_ITEM_OPEN = "Open";
	private static final String MENU_ITEM_CLOSE = "Close";
	private static final String MENU_ITEM_DISPLAY_NODE_NAME = "Display Node Name";
	
	private static final String MENU_COMMAND = "Commands";
	private static final String MENU_ITEM_DISPLAY_SELECTED_NODE_NAMES = "Display names of selected agents";
	private static final String MENU_ITEM_HIGHLIGHT_SELECTED_NODES = "Highlight selected agents";
	private static final String MENU_ITEM_DISPLAY_ALL_NODES = "Display all agents";
	private static final String MENU_ITEM_REMOVE_SELECTED_NODES = "Remove selected nodes";

	private static final String MENU_ITEM_DISPLAY_NODE_RELATIONSHIPS = "Display relationships of selected agent";

	private static final String MENU_ITEM_HIGHLIGHT_SELECTED_TYPES = "Highlight selected message types";
	private static final String MENU_ITEM_DISPLAY_ALL_TYPES = "Display all message types";
	private static final String MENU_ITEM_REMOVE_SELECTED_TYPES = "Remove selected message types";

	public NetTool() {
		m_graphFileHandler = new GraphFileHandler();
		m_societyModel = new SocietyModelImpl();
		initUiComponents();
	}

	/**
	 * Initialize UI components
	 */
	private void initUiComponents() {
		addWindowListener(new java.awt.event.WindowAdapter() {
			public void windowClosing(java.awt.event.WindowEvent evt) {
				exitForm(evt);
			}
		});
		
		m_graphRenderer = new GraphRenderer(this, m_societyModel);
		getContentPane().add(m_graphRenderer);

		m_menu = new JMenuBar();
		JMenu fileMenu = new JMenu(MENU_FILE);
		fileMenu.setMnemonic(KeyEvent.VK_F);
		m_menu.add(fileMenu);
		
		addMenuItem(MENU_ITEM_OPEN, KeyEvent.VK_O, ActionEvent.ALT_MASK, fileMenu,
				new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JMenuItem source = (JMenuItem)(e.getSource());
				if (source.getText().equals(MENU_ITEM_OPEN)) {
					openAndDisplayGraph();
				}			
			}
		});
		
		addMenuItem(MENU_ITEM_CLOSE, KeyEvent.VK_F4, ActionEvent.CTRL_MASK, fileMenu,
				new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JMenuItem source = (JMenuItem)(e.getSource());
				if (source.getText().equals(MENU_ITEM_CLOSE)) {
					m_graphRenderer.closeGraph();
					pack();
				}			
			}
		});
		addMenuItem(MENU_ITEM_DISPLAY_NODE_NAME, 0, 0, fileMenu,
				new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JMenuItem source = (JMenuItem)(e.getSource());
				if (source.getText().equals(MENU_ITEM_DISPLAY_NODE_NAME)) {
					m_graphRenderer.switchDisplayNodeName();
					pack();
				}			
			}
		});

		// Command menu
		// node display
		JMenu commandMenu = new JMenu(MENU_COMMAND);
		commandMenu.setMnemonic(KeyEvent.VK_C);
		m_menu.add(commandMenu);
		addMenuItem(MENU_ITEM_DISPLAY_SELECTED_NODE_NAMES, 0, 0, commandMenu,
				new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JMenuItem source = (JMenuItem)(e.getSource());
				if (source.getText().equals(MENU_ITEM_DISPLAY_SELECTED_NODE_NAMES)) {
					m_graphRenderer.displaySelectedNodeNames();
				}			
			}
		});
		addMenuItem(MENU_ITEM_HIGHLIGHT_SELECTED_NODES, 0, 0, commandMenu,
				new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JMenuItem source = (JMenuItem)(e.getSource());
				if (source.getText().equals(MENU_ITEM_HIGHLIGHT_SELECTED_NODES)) {
					m_graphRenderer.highlightSelectedNodes();
				}			
			}
		});
		
		
		addMenuItem(MENU_ITEM_DISPLAY_ALL_NODES, 0, 0, commandMenu,
				new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JMenuItem source = (JMenuItem)(e.getSource());
				if (source.getText().equals(MENU_ITEM_DISPLAY_ALL_NODES)) {
					m_graphRenderer.displayAllNodes();
				}			
			}
		});
		
		addMenuItem(MENU_ITEM_REMOVE_SELECTED_NODES, 0, 0, commandMenu,
				new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JMenuItem source = (JMenuItem)(e.getSource());
				if (source.getText().equals(MENU_ITEM_REMOVE_SELECTED_NODES)) {
					m_graphRenderer.removeSelectedNodes();
				}			
			}
		});
		commandMenu.addSeparator();
		
		addMenuItem(MENU_ITEM_HIGHLIGHT_SELECTED_TYPES, 0, 0, commandMenu,
				new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JMenuItem source = (JMenuItem)(e.getSource());
				if (source.getText().equals(MENU_ITEM_HIGHLIGHT_SELECTED_TYPES)) {
					m_graphRenderer.highlightSelectedTypes();
				}			
			}
		});
		addMenuItem(MENU_ITEM_DISPLAY_ALL_TYPES, 0, 0, commandMenu,
				new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JMenuItem source = (JMenuItem)(e.getSource());
				if (source.getText().equals(MENU_ITEM_DISPLAY_ALL_TYPES)) {
					m_graphRenderer.displayAllTypes();
				}			
			}
		});
			
		addMenuItem(MENU_ITEM_REMOVE_SELECTED_TYPES, 0, 0, commandMenu,
				new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JMenuItem source = (JMenuItem)(e.getSource());
				if (source.getText().equals(MENU_ITEM_REMOVE_SELECTED_TYPES)) {
					m_graphRenderer.removeSelectedTypes();
				}			
			}
		});
		
		commandMenu.addSeparator();
		addMenuItem(MENU_ITEM_DISPLAY_NODE_RELATIONSHIPS, 0, 0, commandMenu,
				new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JMenuItem source = (JMenuItem)(e.getSource());
				if (source.getText().equals(MENU_ITEM_DISPLAY_NODE_RELATIONSHIPS)) {
					m_graphRenderer.displayNodeRelationships();
				}			
			}
		});
		
		setJMenuBar(m_menu);
		pack();
		
		//Display the window.
		//setSize(450, 260);
		setVisible(true);
		
	}

	/** Exit the Application */
	private void exitForm(java.awt.event.WindowEvent evt) {
		System.exit(0);
	}

	private void addMenuItem(String menuText, int shortcut, int mask, JMenu menu, ActionListener listener) {
		JMenuItem item = new JMenuItem(menuText, shortcut);
		item.setAccelerator(KeyStroke.getKeyStroke(
				shortcut, mask));
		item.addActionListener(listener);
		menu.add(item);
	}
	
	private void openAndDisplayGraph() {
		File theGraphFile = null;
		
		//Create a file chooser
		JFileChooser fc = new JFileChooser();
		fc.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
		int returnVal = fc.showOpenDialog(this);
		if (returnVal == JFileChooser.APPROVE_OPTION) {
			theGraphFile = fc.getSelectedFile();
		}
		openAndDisplayGraph(theGraphFile);
	}

	public void openAndDisplayGraph(File theGraphFile) {
		if (theGraphFile != null && theGraphFile.exists()) {
			m_graphFileHandler.openGraphFile(theGraphFile, m_societyModel);
			m_graphRenderer.displayPanel();
			pack();
		}
	}
	
	public static void main(String[] args) {
		new NetTool().show();
	}
}
