/*
 * Created on Feb 25, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.util.Date;

/**
 * @author srosset
 *
 * Represents a pair of agents communicating with each other.
 */
public class CougaarEdge {

	private Date    m_initialTime;
	private String  m_sourceAgent;
	private String  m_destinationAgent;
	private String  m_messageType;
	
	public CougaarEdge(Date initialTime, String sourceAgent, String destinationAgent, String type) {
		m_initialTime = initialTime;
		m_sourceAgent = sourceAgent;
		m_destinationAgent = destinationAgent;
		m_messageType = type;
	}

	public Date getInitialTime() {
		return m_initialTime
	}
}
