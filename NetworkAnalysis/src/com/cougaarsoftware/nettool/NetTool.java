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

import edu.uci.ics.jung.graph.Graph;

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

	private static final String MENU_ITEM_OPEN = "Open";
	private static final String MENU_ITEM_CLOSE = "Close";
	private static final String MENU_ITEM_DISPLAY_NODE_NAME = "Display Node Name";
	private static final String MENU_FILE = "File";
	
	public NetTool() {
		m_graphFileHandler = new GraphFileHandler();
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
		
		m_graphRenderer = new GraphRenderer(this);
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
			Graph g = m_graphFileHandler.openGraphFile(theGraphFile);
			m_graphRenderer.displayGraph(g);
			pack();
		}
	}
	
	public static void main(String[] args) {
		new NetTool().show();
	}
}
