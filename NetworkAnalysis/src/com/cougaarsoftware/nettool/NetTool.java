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
import javax.swing.JPanel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JMenuBar;
import javax.swing.KeyStroke;

import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.GraphDraw;

/**
 * @author srosset
 *
 * A Swing GUI tool to display graphs based on information
 * collected from a running society.
 */
public class NetTool extends JFrame {

	private JPanel           m_graph;
	private JMenuBar         m_menu;
	private GraphFileHandler m_graphFileHandler;

	private static final String MENU_ITEM_OPEN = "Open";
	private static final String MENU_ITEM_CLOSE = "Close";
	private static final String MENU_FILE = "File";
	
	public NetTool() {
		initUiComponents();
		m_graphFileHandler = new GraphFileHandler();
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
		
		m_graph = new javax.swing.JPanel();
		getContentPane().add(m_graph, java.awt.BorderLayout.SOUTH);

		m_menu = new JMenuBar();
		JMenu fileMenu = new JMenu(MENU_FILE);
		fileMenu.setMnemonic(KeyEvent.VK_F);
		m_menu.add(fileMenu);
		JMenuItem fileOpen = new JMenuItem(MENU_ITEM_OPEN, KeyEvent.VK_O);
		fileOpen.setAccelerator(KeyStroke.getKeyStroke(
					KeyEvent.VK_O, ActionEvent.ALT_MASK));
		fileOpen.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JMenuItem source = (JMenuItem)(e.getSource());
				if (source.getText().equals(MENU_ITEM_OPEN)) {
					openAndDisplayGraph();
				}			
			}
		});
		fileMenu.add(fileOpen);
		
		JMenuItem fileClose = new JMenuItem(MENU_ITEM_CLOSE, KeyEvent.VK_F4);
		fileClose.setAccelerator(KeyStroke.getKeyStroke(
				KeyEvent.VK_F4, ActionEvent.CTRL_MASK));
		fileClose.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JMenuItem source = (JMenuItem)(e.getSource());
				if (source.getText().equals(MENU_ITEM_CLOSE)) {
					closeGraph(m_graph);
				}			
			}
		});
		fileMenu.add(fileClose);
		
		setJMenuBar(m_menu);
		pack();
		
		//Display the window.
		setSize(450, 260);
		setVisible(true);
		
	}

	/** Exit the Application */
	private void exitForm(java.awt.event.WindowEvent evt) {
		System.exit(0);
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
		if (theGraphFile != null && theGraphFile.exists()) {
			Graph g = m_graphFileHandler.openGraphFile(theGraphFile);
			displayGraph(g, m_graph);
			pack();
		}
	}

	private void displayGraph(Graph g, JPanel jp) {
		if (g == null) {
			return;
		}
		GraphDraw gd = new GraphDraw(g);
		jp.removeAll();
		jp.add(gd);
	}

	private void closeGraph(JPanel jp) {
		jp.removeAll();
		pack();
	}
	
	public static void main(String[] args) {
		new NetTool().show();
	}
}
