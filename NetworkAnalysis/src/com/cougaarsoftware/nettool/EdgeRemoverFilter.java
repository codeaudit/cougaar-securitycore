/*
 * Created on Mar 1, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.util.Iterator;
import java.util.Set;

import edu.uci.ics.jung.graph.Edge;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.Vertex;
import edu.uci.ics.jung.graph.filters.EfficientFilter;
import edu.uci.ics.jung.graph.filters.Filter;
import edu.uci.ics.jung.graph.filters.GeneralVertexAcceptFilter;
import edu.uci.ics.jung.graph.filters.GeneralEdgeAcceptFilter;
import edu.uci.ics.jung.graph.filters.UnassembledGraph;

/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class EdgeRemoverFilter extends GeneralEdgeAcceptFilter implements EfficientFilter {

	private Set m_removedTypes;

	public EdgeRemoverFilter(Set types) {
		m_removedTypes = types;
	}

	/* (non-Javadoc)
	 * @see edu.uci.ics.jung.graph.filters.Filter#getName()
	 */
	public String getName() {
		Iterator it = m_removedTypes.iterator();
		String filterName = "Type Remover: ";
		while (it.hasNext()) {
			filterName = filterName + " " + (String) it.next() ;
		}
		return filterName;
	}

	/* (non-Javadoc)
	 * @see edu.uci.ics.jung.graph.filters.GeneralEdgeAcceptFilter#acceptEdge(edu.uci.ics.jung.graph.Edge)
	 */
	public boolean acceptEdge(Edge e) {
		Set edgeTypes = (Set) e.getUserDatum(SocietyModel.KEY_MSG_TYPE);
		Iterator it = m_removedTypes.iterator();
		while (it.hasNext()) {
			String removedType = (String) it.next();
			Iterator it2 = edgeTypes.iterator();
			int numberOfTypes = edgeTypes.size();
			int numberOfMatch = 0;
			while (it2.hasNext()) {
				String edgeType = (String) it2.next();
				if (removedType.equals(edgeType)) {
					numberOfMatch++;
				}
			}
			if (numberOfMatch == numberOfTypes) {
				return false;
			}
		}
		return true;
	}

	
}

