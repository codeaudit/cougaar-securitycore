/*
 * Created on Feb 25, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComboBox;
import javax.swing.JPanel;

import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.FRLayout;
import edu.uci.ics.jung.visualization.GraphDraw;
import edu.uci.ics.jung.visualization.ISOMLayout;
import edu.uci.ics.jung.visualization.Layout;
import edu.uci.ics.jung.visualization.SpringLayout;
import edu.uci.ics.jung.visualization.contrib.CircleLayout;
import edu.uci.ics.jung.visualization.contrib.KKLayout;

/**
 * @author srosset
 *
 * Display graphs in a JPanel
 */
public class GraphRenderer extends JPanel {

	private JPanel m_graphPanel;
	private JPanel m_commandPanel;
	
	private Graph     m_graph;
	private GraphDraw m_graphDraw;
	private Layout    m_layout;
	
	static final Class[] constructorArgsWanted = { Graph.class };
	
	public GraphRenderer() {
		super();
		initGuiComponents();
	}
	
	private void initGuiComponents() {
		GridBagLayout gridBag = new GridBagLayout();
		setLayout(gridBag);
		GridBagConstraints c = new GridBagConstraints();
		
		c.fill = GridBagConstraints.NORTH;
		m_commandPanel = new JPanel();
		gridBag.setConstraints(m_commandPanel, c);
		add(m_commandPanel);

		c.fill = GridBagConstraints.SOUTH;
		m_graphPanel = new JPanel();
		gridBag.setConstraints(m_graphPanel, c);
		add(m_graphPanel);
		
		Class[] combos = getCombos();
		final JComboBox jcb = new JComboBox(combos);
		jcb.setSelectedItem(SpringLayout.class);
		jcb.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent arg0) {
				Object[] constructorArgs = { m_graph };
				Class layoutC = (Class) jcb.getSelectedItem();
				System.out.println("Setting to " + layoutC);
				Class lay = layoutC;
				try {
					Constructor constructor =
						lay.getConstructor(constructorArgsWanted);
					Object o = constructor.newInstance(constructorArgs);
					m_layout = (Layout) o;
					setGraphLayout();
				} catch (Exception e) {
					System.out.println("Can't handle " + lay);
				}
				
			}
		});
		m_commandPanel.add(jcb);
	}
	
	private void setGraphLayout() {
		if (m_graphDraw != null && m_layout != null) {
			m_graphDraw.setGraphLayout(m_layout);
			m_graphDraw.restartLayout();
		}
	}

	/**
	 * Display a graph in a JPanel
	 * @param g
	 * @param jp
	 */
	public void displayGraph(Graph g) {
		m_graph = g;
		if (m_graph == null) {
			return;
		}
		m_graphDraw = new GraphDraw(m_graph);
		setGraphLayout();
		m_graphPanel.removeAll();
		m_graphPanel.add(m_graphDraw);
	}

	/**
	 * Remove the graph from a JPanel
	 * @param jp
	 */
	public void closeGraph() {
		removeAll();
	}
	
	private static Class[] getCombos() {
		List layouts = new ArrayList();
		layouts.add( KKLayout.class );
		layouts.add( FRLayout.class );
		layouts.add( CircleLayout.class );
		layouts.add( SpringLayout.class );
		layouts.add( ISOMLayout.class) ;
		return (Class[]) layouts.toArray( new Class[0] );
	}
	
}
