/*
 * Created on Feb 25, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.io.File;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Set;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextField;

import com.cougaarsoftware.nettool.parsers.LogGenerator;

import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.Vertex;
import edu.uci.ics.jung.graph.decorators.StringLabeller;
import edu.uci.ics.jung.graph.filters.Filter;
import edu.uci.ics.jung.graph.filters.UnassembledGraph;
import edu.uci.ics.jung.visualization.FRLayout;
import edu.uci.ics.jung.visualization.GraphDraw;
import edu.uci.ics.jung.visualization.GraphMouseListener;
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

	private JPanel           m_graphPanel;
	private JPanel           m_commandPanel;
	private NodeControlPane   m_nodeControlPane;
  private JSplitPane       m_splitPane;
  
	private GraphDraw         m_graphDraw;
	private Layout            m_layout;
	private NetTool           m_frame;
	private CougaarRenderer   m_cougaarRenderer;
	private Renderer          m_settableRenderer;
	private SocietyModel      m_societyModel;
	private JTextField        m_agentName;
	private NodeRelationships m_relationships;
	
	static final Class[] constructorArgsWanted = { Graph.class };
	
	public GraphRenderer(NetTool nt, SocietyModel sm) {
		super();
		m_frame = nt;
		m_nodeControlPane = new NodeControlPane();
		m_societyModel = sm;
		initGuiComponents();
	}
	
	private void initGuiComponents() {
		m_relationships = new NodeRelationships();

		//GridBagLayout gridBag = new GridBagLayout();
		//setLayout(gridBag);
		//GridBagConstraints c = new GridBagConstraints();

		setLayout(new BorderLayout());
		
		//c.fill = GridBagConstraints.BOTH;
		//c.weightx = 1.0;
		//c.gridwidth = GridBagConstraints.REMAINDER;
		m_commandPanel = new JPanel();
		m_commandPanel.setPreferredSize(new Dimension(450, 40));
		//gridBag.setConstraints(m_commandPanel, c);
		add(m_commandPanel, BorderLayout.NORTH);

    
		m_graphPanel = new JPanel();
		m_graphPanel.setBorder(BorderFactory.createLineBorder(Color.black));
		JScrollPane scroller = new JScrollPane(m_graphPanel);
		scroller.setPreferredSize(new Dimension(450, 450));
		//scroller.setMaximumSize(new Dimension(400, 400));

		//c.gridwidth = GridBagConstraints.RELATIVE;
		//gridBag.setConstraints(scroller, c);
    //Create a split pane with the two scroll panes in it.
    m_splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                               scroller, m_nodeControlPane);
    m_splitPane.setOneTouchExpandable(true);
    m_splitPane.setDividerLocation(400);

    add(m_splitPane, BorderLayout.CENTER);
		//add(scroller);
		
		//c.gridwidth = GridBagConstraints.REMAINDER;
		//gridBag.setConstraints(m_nodeControlPane, c);
		//add(m_nodeControlPane);
		
		Class[] combos = getCombos();
		final JComboBox jcb = new JComboBox(combos);
		jcb.setSelectedItem(SpringLayout.class);
		jcb.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent arg0) {
				Object[] constructorArgs = { m_societyModel.getGraph() };
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
		
		m_agentName = new JTextField();
		m_agentName.setColumns(30);
		m_commandPanel.add(m_agentName);
	}
	
	private void setGraphLayout() {
		if (m_graphDraw != null && m_layout != null) {
			m_graphDraw.setGraphLayout(m_layout);
			m_graphDraw.restartLayout();
			m_layout.resize( m_graphPanel.getSize() );
		}
	}

  public void displayPanel() {
  	displayGraph();
		m_nodeControlPane.updateDisplay(m_societyModel);
  }
  
	/**
	 * Display a graph in a JPanel
	 * @param g
	 * @param jp
	 */
	private void displayGraph() {
		Graph g = m_societyModel.getGraph();
		if (m_societyModel.getGraph() == null) {
			return;
		}
		m_graphDraw = new GraphDraw(g);
		m_graphDraw.showStatus();
		m_graphDraw.addGraphMouseListener(new MyGraphMouseListener());
		StringLabeller sl = StringLabeller.getLabeller(g);
		if (m_cougaarRenderer == null) {
			m_cougaarRenderer = new CougaarRenderer(sl);
		}
		if (m_settableRenderer == null) {
			m_settableRenderer = new SettableRenderer(sl);
		}
		m_graphDraw.setRenderer(m_cougaarRenderer);
		FRLayout frlayout = new FRLayout(g);
		frlayout.setMaxIterations(70);
		m_graphDraw.setGraphLayout(frlayout);
		setGraphLayout();
		m_graphPanel.removeAll();
		m_graphPanel.add(m_graphDraw);
		m_graphPanel.repaint();
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

	/**
	 * 
	 */
	public void highlightSelectedNodes() {
		Set s = m_nodeControlPane.getSelectedNodes();
		m_cougaarRenderer.highlightNodes(s);
		m_graphDraw.restartLayout();
	}

	/**
	 * 
	 */
	public void displaySelectedNodeNames() {
		Set s = m_nodeControlPane.getSelectedNodes();
		m_graphDraw.repaint();
	}

	/**
	 * 
	 */
	public void displayAllNodes() {
		m_societyModel.setSubGraph(null);
		displayGraph();
	}

	/**
	 * 
	 */
	public void removeSelectedNodes() {
		Set s = m_nodeControlPane.getSelectedNodes();
		Filter nrf = new NodeRemoverFilter(s);
		Graph g = nrf.filter(m_societyModel.getGraph()).assemble();
		m_societyModel.setSubGraph(g);	
		displayGraph();
	}

	/**
	 * 
	 */
	public void highlightSelectedTypes() {
		Set s = m_nodeControlPane.getSelectedTypes();
		m_cougaarRenderer.highlightMessageTypes(s);
		m_graphDraw.repaint();
	}

	/**
	 * 
	 */
	public void removeSelectedTypes() {
		Set s = m_nodeControlPane.getSelectedTypes();
		Filter nrf = new EdgeRemoverFilter(s);
		Graph g = nrf.filter(m_societyModel.getGraph()).assemble();
		m_societyModel.setSubGraph(g);	
		displayGraph();
		
	}

	/**
	 * 
	 */
	public void displayAllTypes() {
		// TODO Auto-generated method stub
		
	}
	
	private class MyGraphMouseListener implements GraphMouseListener {

		/* (non-Javadoc)
		 * @see edu.uci.ics.jung.visualization.GraphMouseListener#graphClicked(edu.uci.ics.jung.graph.Vertex, java.awt.event.MouseEvent)
		 */
		public void graphClicked(Vertex v, MouseEvent me) {
			String name = (String) v.getUserDatum(SocietyModel.KEY_AGENT_NAME);
			System.out.println(name);
			m_agentName.setText(name);
		}

		/* (non-Javadoc)
		 * @see edu.uci.ics.jung.visualization.GraphMouseListener#graphPressed(edu.uci.ics.jung.graph.Vertex, java.awt.event.MouseEvent)
		 */
		public void graphPressed(Vertex v, MouseEvent me) {
		}

		/* (non-Javadoc)
		 * @see edu.uci.ics.jung.visualization.GraphMouseListener#graphReleased(edu.uci.ics.jung.graph.Vertex, java.awt.event.MouseEvent)
		 */
		public void graphReleased(Vertex v, MouseEvent me) {
		}
		
	}

	/**
	 * 
	 */
	public void displayNodeRelationships() {
		if (m_agentName == null) {
			return;
		}
		//System.out.println(m_agentName.getText());
		m_relationships.displayRelationships(m_agentName.getText(), m_societyModel.getGraph());
		m_relationships.setVisible(true);
	}


}
