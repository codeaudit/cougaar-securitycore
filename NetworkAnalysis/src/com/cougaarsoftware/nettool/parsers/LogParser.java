/*
 * Created on Feb 25, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package com.cougaarsoftware.nettool.parsers;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


import edu.uci.ics.jung.graph.Edge;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.Vertex;
import edu.uci.ics.jung.graph.decorators.StringLabeller;
import edu.uci.ics.jung.graph.decorators.StringLabeller.UniqueLabelException;
import edu.uci.ics.jung.graph.impl.DirectedSparseEdge;
import edu.uci.ics.jung.graph.impl.DirectedSparseGraph;
import edu.uci.ics.jung.graph.impl.SparseVertex;
import edu.uci.ics.jung.utils.UserDataContainer;

/**
 * @author srosset
 *
 * Converts Cougaar network log files into Pajek or GraphML format.
 */
public class LogParser {

	public static final String KEY_AGENT_NAME = "Agent";
	public static final String KEY_MSG_TYPE   = "Type";
	
	/**
	 * Record parse errors as we parse files.
	 * A List of Exception.
	 */
	private List m_parseErrors;
	
	/**
	 * A list of CougaarEdge representing a communication channel between two agents)
	 */
	private List m_edges;
	
	/**
	 * A list of agents. Each agent appears only once.
	 */
	private Set  m_agentNames;
	
	/**
	 * The resulting graph after parsing the log files.
	 */
	private Graph m_graph;
	
	public LogParser() {
		m_parseErrors = new ArrayList();
		m_edges = new ArrayList();
		m_agentNames = new HashSet();
	}
		
	public Graph getGraph() {
		return m_graph;
	}
	
	private void generateGraph() {
		m_graph = new DirectedSparseGraph();
		StringLabeller sl = StringLabeller.getLabeller(m_graph);
		
		// The Map maps Agent names to its corresponding vertex.
		Map vertexList = new HashMap(); 
		Iterator it = m_edges.iterator();
		while (it.hasNext()) {
			CougaarEdge ce = (CougaarEdge) it.next();
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
				e.addUserDatum(KEY_MSG_TYPE, ce.getMessageType(), new UserDataContainer.CopyAction.Shared());
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
	
	public void parseCougaarLogFiles(String []files) {
		for (int i = 0 ; i < files.length ; i++) {
			File f = new File(files[i]);
			parseFile(f);
		}
		generateGraph();
	}

	/**
	 * @param f
	 */
	private void parseFile(File f) {
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(f));
		} catch (FileNotFoundException e) {
			m_parseErrors.add(e);
		}
		if (br == null) {
			return;
		}
		
		String line = null;
		Pattern p = Pattern.compile("(.+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)");
		try {
			while ( (line = br.readLine()) != null) {
				Matcher m = p.matcher(line);
				if (m.matches()) {
					String time =     m.group(1);
					String srcAgent = m.group(2);
					String dstAgent = m.group(3);
					String type =     m.group(4);
					CougaarEdge ce = new CougaarEdge(time, srcAgent, dstAgent, type);
					m_agentNames.add(srcAgent);
					m_agentNames.add(dstAgent);
					m_edges.add(ce);
				}
				else {
					m_parseErrors.add(new Exception("Unable to find match against pattern: " + line));
				}
			}
		} catch (IOException e1) {
			m_parseErrors.add(e1);
		} catch (ParseException e) {
			m_parseErrors.add(e);
		}
	}
}
