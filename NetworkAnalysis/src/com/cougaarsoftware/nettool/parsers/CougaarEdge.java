/*
 * Created on Feb 25, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package com.cougaarsoftware.nettool.parsers;

import java.text.DateFormat;
import java.text.ParseException;
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
	static private DateFormat df = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM);
	
	static {
		df.setLenient(true);
	}
	
	public CougaarEdge(String initialTime, String sourceAgent, String destinationAgent, String type) throws ParseException {
		System.out.println(df.format(new Date()));
		m_initialTime = df.parse(initialTime);
		m_sourceAgent = sourceAgent;
		m_destinationAgent = destinationAgent;
		m_messageType = type;
	}

	public Date getInitialTime() {
		return m_initialTime;
	}
	
	public String getSourceAgent() {
		return m_sourceAgent;
	}
	
	public String getDestinationAgent() {
		return m_destinationAgent;
	}
	
	public String getMessageType() {
		return m_messageType;
	}
}
