/*
 * Created on Mar 1, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.util.Set;
import java.util.HashSet;

/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class GraphEdge {
	private AgentPair m_agentPair;
	private Set       m_types;
	
	public GraphEdge(AgentPair ap) {
		m_agentPair = ap;
		m_types = new HashSet();
	}	

	/**
	 * @return Returns the m_types.
	 */
	public Set getTypes() {
		return m_types;
	}
	
	public void addType(String type) {
		m_types.add(type);
	}

	/**
	 * @return Returns the m_destinationAgent.
	 */
	public String getDestinationAgent() {
		return m_agentPair.getDestinationAgent();
	}
	/**
	 * @return Returns the m_sourceAgent.
	 */
	public String getSourceAgent() {
		return m_agentPair.getSourceAgent();
	}
	
}
