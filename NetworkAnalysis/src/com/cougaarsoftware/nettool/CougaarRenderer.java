/*
 * Created on Feb 26, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.awt.Graphics;
import java.awt.Color;

import edu.uci.ics.jung.graph.Edge;
import edu.uci.ics.jung.graph.Vertex;
import edu.uci.ics.jung.graph.decorators.StringLabeller;
import edu.uci.ics.jung.visualization.graphdraw.SettableRenderer;

/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class CougaarRenderer extends SettableRenderer {

	/**
	 * @param arg0
	 */
	public CougaarRenderer(StringLabeller arg0) {
		super(arg0);
	}
	/**
	 * @see edu.uci.ics.jung.visualization.Renderer#paintVertex(java.awt.Graphics, edu.uci.ics.jung.graph.Vertex, int, int)
	 */
	public void paintVertex(Graphics g, Vertex v, int x, int y) {
		g.setColor( Color.BLUE );
		g.fillOval(x-3, y-3, 6, 6);
	}

	/**
	 * @see edu.uci.ics.jung.visualization.Renderer#paintEdge(java.awt.Graphics, edu.uci.ics.jung.graph.Edge, int, int, int, int)
	 */
	public void paintEdge(Graphics g, Edge e, int x1, int y1, int x2, int y2) {
		g.setColor( Color.GRAY );
		g.drawLine(x1, y1, x2, y2);
	}

}
