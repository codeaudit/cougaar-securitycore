/*
 * Created on Feb 26, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.awt.Graphics;
import java.awt.Color;
import java.util.Iterator;
import java.util.Set;

import edu.uci.ics.jung.graph.Edge;
import edu.uci.ics.jung.graph.Vertex;
import edu.uci.ics.jung.graph.decorators.StringLabeller;
import edu.uci.ics.jung.visualization.graphdraw.EdgeColorFunction;
import edu.uci.ics.jung.visualization.graphdraw.SettableRenderer;
import edu.uci.ics.jung.visualization.graphdraw.VertexColorFunction;

/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class CougaarRenderer extends SettableRenderer {

	private boolean                   m_highlightType;
	private MessageTypeColorFunction  m_edgeColorFunction;
	private NodeColorFunction         m_nodeColorFunction;
	
	/**
	 * @param arg0
	 */
	public CougaarRenderer(StringLabeller arg0) {
		super(arg0);
		m_edgeColorFunction = new MessageTypeColorFunction();
		m_nodeColorFunction = new NodeColorFunction();
	}
	
	/**
	 * @see edu.uci.ics.jung.visualization.Renderer#paintVertex(java.awt.Graphics, edu.uci.ics.jung.graph.Vertex, int, int)
	 */
	public void paintVertex(Graphics g, Vertex v, int x, int y) {
		//g.setColor( Color.BLUE );
		g.setColor(m_nodeColorFunction.getVertexColor(v));
		g.fillOval(x-3, y-3, 6, 6);
	}

	/**
	 * @see edu.uci.ics.jung.visualization.Renderer#paintEdge(java.awt.Graphics, edu.uci.ics.jung.graph.Edge, int, int, int, int)
	 */
	public void paintEdge(Graphics g, Edge e, int x1, int y1, int x2, int y2) {
		//g.setColor( Color.GRAY );
		g.setColor(m_edgeColorFunction.getEdgeColor(e));
		g.drawLine(x1, y1, x2, y2);
	}

	public void highlightMessageTypes(Set messageType) {
		m_edgeColorFunction.setHighlightedType(messageType);
	}

	public void highlightNodes(Set nodeNames) {
		m_nodeColorFunction.setHighlightedNode(nodeNames);
	}
		
	private class MessageTypeColorFunction {
		private Set m_highlightedMessageTypes;
		
		/* (non-Javadoc)
		 * @see edu.uci.ics.jung.visualization.graphdraw.EdgeColorFunction#getEdgeColor(edu.uci.ics.jung.graph.Edge)
		 */
		public Color getEdgeColor(Edge edge) {
			if (m_highlightedMessageTypes != null) {
				Set types = (Set) edge.getUserDatum(SocietyModel.KEY_MSG_TYPE);
				Iterator it = types.iterator();
				while (it.hasNext()) {
					if (m_highlightedMessageTypes.contains(it.next())) {
						return Color.GREEN;
					}
				}
				return Color.GRAY;
			}
			else {
				return Color.GRAY;
			}
		}

		/**
		 * @param messageType
		 */
		public void setHighlightedType(Set messageTypes) {
			m_highlightedMessageTypes = messageTypes;
		}
	}
	
	private class NodeColorFunction {
		private Set m_highlightedNodeNames;
		
		/**
		 * @param nodeNames
		 */
		public void setHighlightedNode(Set nodeNames) {
			m_highlightedNodeNames = nodeNames;
		}

		/* (non-Javadoc)
		 * @see edu.uci.ics.jung.visualization.graphdraw.VertexColorFunction#getForeColor(edu.uci.ics.jung.graph.Vertex)
		 */
		public Color getVertexColor(Vertex vertex) {
			if (m_highlightedNodeNames != null) {
				String node = (String) vertex.getUserDatum(SocietyModel.KEY_AGENT_NAME);
				if (m_highlightedNodeNames.contains(node)) {
					return Color.YELLOW;
				}
				return Color.BLUE;
			}
			else {
				return Color.BLUE;
			}
		}
		
	}
}
