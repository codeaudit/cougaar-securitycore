/*
 * Created on Mar 1, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.util.Iterator;
import java.util.Set;

import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.Vertex;
import edu.uci.ics.jung.graph.filters.EfficientFilter;
import edu.uci.ics.jung.graph.filters.Filter;
import edu.uci.ics.jung.graph.filters.GeneralVertexAcceptFilter;
import edu.uci.ics.jung.graph.filters.UnassembledGraph;

/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class NodeRemoverFilter extends GeneralVertexAcceptFilter implements EfficientFilter {

	private Set m_removedNodes;

	public NodeRemoverFilter(Set nodes) {
		m_removedNodes = nodes;
	}

	/* (non-Javadoc)
	 * @see edu.uci.ics.jung.graph.filters.GeneralVertexAcceptFilter#acceptVertex(edu.uci.ics.jung.graph.Vertex)
	 */
	public boolean acceptVertex(Vertex v) {
		String theAgent = (String) v.getUserDatum(SocietyModel.KEY_AGENT_NAME);
		Iterator it = m_removedNodes.iterator();
		while (it.hasNext()) {
			String name = (String) it.next();
			System.out.println(name + " " + theAgent);
			if (name.equals(theAgent)) {
				return false;
			}
		}
		return true;
	}

	/* (non-Javadoc)
	 * @see edu.uci.ics.jung.graph.filters.Filter#getName()
	 */
	public String getName() {
		Iterator it = m_removedNodes.iterator();
		String filterName = "Node Remover: ";
		while (it.hasNext()) {
			filterName = filterName + " " + (String) it.next() ;
		}
		return filterName;
	}

	
}
