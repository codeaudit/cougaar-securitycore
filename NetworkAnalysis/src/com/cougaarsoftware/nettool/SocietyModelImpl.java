/*
 * Created on Mar 1, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Iterator;
import java.util.HashMap;
import java.util.Map;

import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.Edge;
import edu.uci.ics.jung.graph.impl.DirectedSparseEdge;
import edu.uci.ics.jung.graph.impl.DirectedSparseGraph;
import edu.uci.ics.jung.graph.decorators.StringLabeller;
import edu.uci.ics.jung.graph.decorators.StringLabeller.UniqueLabelException;
import edu.uci.ics.jung.graph.Vertex;
import edu.uci.ics.jung.graph.impl.SparseVertex;
import edu.uci.ics.jung.utils.UserDataContainer;

/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class SocietyModelImpl implements SocietyModel {

	/**
	 * A list of CougaarEdge representing a communication channel between two agents)
	 */
	private List m_edges;
	
	/**
	 * A Map of AgentPair to GraphEdges.
	 */
	private Map  m_graphEdges;
	
	/**
	 * A Set of agents. Each agent appears only once.
	 */
	private Set  m_agentNames;
	
	/**
	 * A Set of message types
	 */
	private Set  m_types;
	
	/**
	 * The resulting graph after parsing the log files.
	 */
	private Graph m_graph;
	
	/**
	 * A graph that has been filtered.
	 */
	private Graph m_subGraph;
	
	public SocietyModelImpl() {
		m_edges = new ArrayList();
		m_agentNames = new HashSet();
		m_types = new HashSet();
		m_graphEdges = new HashMap();
	}

	public Graph getGraph() {
		if (m_graph == null) {
			generateGraph();
		}
		if (m_subGraph != null) {
			return m_subGraph;
		}
		else {
			return m_graph;
		}
	}

	/* (non-Javadoc)
	 * @see com.cougaarsoftware.nettool.SocietyModel#setGraph()
	 */
	public void setGraph(Graph graph) {
		m_graph = graph;
		m_subGraph = null;
	}

	private void generateGraph() {
		m_graph = new DirectedSparseGraph();
		StringLabeller sl = StringLabeller.getLabeller(m_graph);
		
		// The Map maps Agent names to its corresponding vertex.
		Map vertexList = new HashMap(); 
		Collection c = m_graphEdges.values();
		Iterator it = c.iterator();
		while (it.hasNext()) {
			GraphEdge ce = (GraphEdge) it.next();
			Vertex srcV = (Vertex) vertexList.get(ce.getSourceAgent());
			if (srcV == null) {
				srcV = addVertex(ce.getSourceAgent(), vertexList, sl);
			}

			Vertex dstV = (Vertex) vertexList.get(ce.getDestinationAgent());
			if (dstV == null) {
				dstV = addVertex(ce.getDestinationAgent(), vertexList, sl);
			}
			// Create an edge.
			// The library does not support parallel edges
			try {
				Edge e = new DirectedSparseEdge(srcV, dstV);
				e.addUserDatum(KEY_MSG_TYPE, ce.getTypes(), new UserDataContainer.CopyAction.Shared());
				m_graph.addEdge(e);
			}
			catch (IllegalArgumentException e) {
				
			}
		}
	}
	
	private Vertex addVertex(String name, Map vertexList, StringLabeller sl) {
		//System.out.println("Creating vertex " + name);
		Vertex v = new SparseVertex();
		v.addUserDatum(KEY_AGENT_NAME, name, new UserDataContainer.CopyAction.Shared());
		vertexList.put(name, v);
		m_graph.addVertex(v);
		try {
			sl.setLabel(v, name);
		} catch (UniqueLabelException e1) {
		}
		return v;
	}

	/* (non-Javadoc)
	 * @see com.cougaarsoftware.nettool.SocietyModel#addAgentName(java.lang.String)
	 */
	public void addAgentName(String agentName) {
		m_agentNames.add(agentName);
	}

	/* (non-Javadoc)
	 * @see com.cougaarsoftware.nettool.SocietyModel#addEdge(java.lang.String, java.lang.String)
	 */
	public void addEdge(CougaarEdge edge) {
		m_edges.add(edge);
		AgentPair ap = new AgentPair(edge.getSourceAgent(), edge.getDestinationAgent());
		GraphEdge ge = (GraphEdge) m_graphEdges.get(ap);
		if (ge == null) {
			ge = new GraphEdge(ap);
			m_graphEdges.put(ap, ge);
		}
		ge.addType(edge.getMessageType());
		// Add type to global list of types.
		m_types.add(edge.getMessageType());
	}

	/* (non-Javadoc)
	 * @see com.cougaarsoftware.nettool.SocietyModel#getAgentNames()
	 */
	public Set getAgentNames() {
		return m_agentNames;
	}

	/* (non-Javadoc)
	 * @see com.cougaarsoftware.nettool.SocietyModel#getEdges()
	 */
	public List getEdges() {
		return m_edges;
	}

	/* (non-Javadoc)
	 * @see com.cougaarsoftware.nettool.SocietyModel#resetGraph()
	 */
	public void resetGraph() {
		m_edges.clear();
		m_agentNames.clear();
		m_graph = null;
		m_graphEdges.clear();
	}

	/**
	 * @return Returns the m_graphEdges.
	 */
	public Map getGraphEdges() {
		return m_graphEdges;
	}
	/**
	 * @return Returns the m_types.
	 */
	public Set getTypes() {
		return m_types;
	}

	/* (non-Javadoc)
	 * @see com.cougaarsoftware.nettool.SocietyModel#setSubGraph(edu.uci.ics.jung.graph.Graph)
	 */
	public void setSubGraph(Graph graph) {
		m_subGraph = graph;
	}
}
