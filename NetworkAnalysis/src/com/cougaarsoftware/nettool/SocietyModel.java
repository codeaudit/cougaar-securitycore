/*
 * Created on Mar 1, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.util.List;
import java.util.Map;
import java.util.Set;

import edu.uci.ics.jung.graph.Graph;

/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public interface SocietyModel {
	public static final String KEY_AGENT_NAME = "AgentName";
	public static final String KEY_MSG_TYPE   = "MessageType";

	public Graph getGraph();
	public void setGraph(Graph graph);
	
	public void addAgentName(String agentName);
	
	public void addEdge(CougaarEdge edge);
	
	public Set getAgentNames();
	public List getEdges();
	public Map getGraphEdges();
	public Set getTypes();

	public void resetGraph();
	public void setSubGraph(Graph graph);
}
