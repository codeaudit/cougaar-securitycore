/*
 * Created on Feb 25, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import com.cougaarsoftware.nettool.parsers.LogGenerator;

import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.decorators.StringLabeller;
import edu.uci.ics.jung.visualization.FRLayout;
import edu.uci.ics.jung.visualization.GraphDraw;
import edu.uci.ics.jung.visualization.ISOMLayout;
import edu.uci.ics.jung.visualization.Layout;
import edu.uci.ics.jung.visualization.Renderer;
import edu.uci.ics.jung.visualization.SpringLayout;
import edu.uci.ics.jung.visualization.contrib.CircleLayout;
import edu.uci.ics.jung.visualization.contrib.KKLayout;
import edu.uci.ics.jung.visualization.graphdraw.SettableRenderer;

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
	private NetTool   m_frame;
	private Renderer  m_cougaarRenderer;
	private Renderer  m_settableRenderer;
	
	static final Class[] constructorArgsWanted = { Graph.class };
	
	public GraphRenderer(NetTool nt) {
		super();
		initGuiComponents();
		m_frame = nt;
	}
	
	private void initGuiComponents() {
		GridBagLayout gridBag = new GridBagLayout();
		setLayout(gridBag);
		GridBagConstraints c = new GridBagConstraints();
		
		c.fill = GridBagConstraints.BOTH;
		c.weightx = 1.0;
		c.gridwidth = GridBagConstraints.REMAINDER;
		m_commandPanel = new JPanel();
		gridBag.setConstraints(m_commandPanel, c);
		add(m_commandPanel);

		c.fill = GridBagConstraints.SOUTH;
		m_graphPanel = new JPanel();
		m_graphPanel.setBorder(BorderFactory.createLineBorder(Color.black));
		gridBag.setConstraints(m_graphPanel, c);
		JScrollPane scroller = new JScrollPane(m_graphPanel);
		//scroller.setPreferredSize(new Dimension(400, 400));
		add(scroller);
		
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
		
		JButton b1 = new JButton("Random");
		m_commandPanel.add(b1);
		b1.setActionCommand("Random");
		b1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
        if ("Random".equals(e.getActionCommand())) {
        	// Generate random graph
        	Random r = new Random();
        	int nodes = r.nextInt(500);
        	int edges = r.nextInt(10000);
        	System.out.println("Nodes: " + nodes + " edges: " + edges);
        	LogGenerator lg = new LogGenerator();
        	String fileName = "random.log";
        	lg.generateLogFile(nodes, edges, fileName);
        	m_frame.openAndDisplayGraph(new File(fileName));
        }
			}
		});
	}
	
	private void setGraphLayout() {
		if (m_graphDraw != null && m_layout != null) {
			m_graphDraw.setGraphLayout(m_layout);
			m_graphDraw.restartLayout();
			m_layout.resize( m_graphPanel.getSize() );
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
		m_graphDraw.showStatus();
		StringLabeller sl = StringLabeller.getLabeller(m_graph);
		if (m_cougaarRenderer == null) {
			m_cougaarRenderer = new CougaarRenderer(sl);
		}
		if (m_settableRenderer == null) {
			m_settableRenderer = new SettableRenderer(sl);
		}
		m_graphDraw.setRenderer(m_cougaarRenderer);
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

	private boolean node_label_on = true;
	
	/**
	 * 
	 */
	public void switchDisplayNodeName() {
		if (node_label_on) {
			node_label_on = false;
			m_graphDraw.setRenderer(m_settableRenderer);
		}
		else {
			node_label_on = true;
			m_graphDraw.setRenderer(m_cougaarRenderer);
		}
		setGraphLayout();
	}
}
