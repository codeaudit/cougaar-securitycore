/*
 * Created on Mar 1, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package com.cougaarsoftware.nettool;

import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.DefaultListModel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;

import edu.uci.ics.jung.graph.Edge;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.Vertex;
import edu.uci.ics.jung.utils.Pair;

import java.awt.Dimension;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class NodeRelationships extends JFrame {
	private JList            m_nodeList;
	private DefaultListModel m_nodeListModel;

	public void displayRelationships(String agentName, Graph g) {
		Set vertices = g.getVertices();
		
		Iterator it = vertices.iterator();
		Vertex agentVertex = null;
		while (it.hasNext()) {
			Vertex v = (Vertex)it.next();
			String name = (String) v.getUserDatum(SocietyModel.KEY_AGENT_NAME);
			v.getUserDatum(SocietyModel.KEY_MSG_TYPE);
			if (name.equals(agentName)) {
				agentVertex = v;
				break;
			}
		}
	
		if (agentVertex == null) {
			return;
		}
		m_nodeListModel = new DefaultListModel();
		buildLabels(agentVertex.getInEdges(), agentVertex, agentName);
		buildLabels(agentVertex.getOutEdges(), agentVertex, agentName);
		
		m_nodeList = new JList(m_nodeListModel);
		m_nodeList
				.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		m_nodeList.setSelectedIndex(0);
		
		JScrollPane listScrollPane = new JScrollPane(m_nodeList);
		listScrollPane.setPreferredSize(new Dimension(300,400));
		getContentPane().removeAll();
		setSize(320, 420);
		getContentPane().add(listScrollPane);
	}
	
	private void buildLabels(Set edges, Vertex agentVertex, String agentName) {
		Iterator it = edges.iterator(); 
		while (it.hasNext()) {
			Edge e = (Edge) it.next();
			Vertex remote = e.getOpposite(agentVertex);
			String remoteAgent = (String) remote.getUserDatum(SocietyModel.KEY_AGENT_NAME);
			String label = agentName + " -> " + remoteAgent + "(";
			Set types = (Set) e.getUserDatum(SocietyModel.KEY_MSG_TYPE);
			Iterator it2 = types.iterator();
			while (it2.hasNext()) {
				label = label + " " + (String) it2.next();
			}
			label = label + ")";
			m_nodeListModel.addElement(label);
		}
		
	}
}
