/*
 * Created on Feb 25, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package com.cougaarsoftware.nettool;

import javax.swing.JComboBox;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.GraphDraw;

/**
 * @author srosset
 *
 * Allows to change the graph layout
 */
public class LayoutChooser {

	private final JComboBox m_jcb;
	private final Graph     m_g;
	private final GraphDraw m_gd;
	
	public LayoutChooser(JComboBox jcb, Graph g, GraphDraw gd) {
		m_jcb = jcb;
		m_g = g;
		m_gd = gd;
	}
	
}
