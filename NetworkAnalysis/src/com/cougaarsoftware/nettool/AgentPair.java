/*
 * Created on Mar 1, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package com.cougaarsoftware.nettool;

/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class AgentPair {
	private String  m_sourceAgent;
	private String  m_destinationAgent;

	public AgentPair(String src, String dst) {
		m_sourceAgent = src;
		m_destinationAgent = dst;
	}
	/**
	 * @return Returns the m_destinationAgent.
	 */
	public String getDestinationAgent() {
		return m_destinationAgent;
	}
	/**
	 * @return Returns the m_sourceAgent.
	 */
	public String getSourceAgent() {
		return m_sourceAgent;
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (! (obj instanceof AgentPair)) {
			return false;
		}
		AgentPair ge = (AgentPair) obj;
		return (m_sourceAgent.equals(ge.getSourceAgent())
				&& m_destinationAgent.equals(ge.getDestinationAgent()));
	}

}
