/*
 * Created on Mar 1, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JList;
import javax.swing.DefaultListModel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class NodeControlPane extends JPanel {
	private JList            m_nodeList;
	private DefaultListModel m_nodeListModel;

	private JList            m_typeList;
	private DefaultListModel m_typeListModel;
	
	public NodeControlPane() {
		super();
		setBorder(BorderFactory.createLineBorder(Color.black));
		//setPreferredSize(new Dimension(100,300));
	}
	
	public void updateDisplay(SocietyModel sm) {
		setLayout(new BorderLayout());

	  //  Add list of nodes
		m_nodeListModel = new DefaultListModel();
		List s = new ArrayList(sm.getAgentNames());
		Collections.sort(s);
		if (s != null) {
			Iterator it = s.iterator();
			while (it.hasNext()) {
				m_nodeListModel.addElement(it.next());
			}
		}
		
		m_nodeList = new JList(m_nodeListModel);
		m_nodeList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		m_nodeList.setSelectedIndex(0);
		m_nodeList.addListSelectionListener(new ListSelectionListener() {
			public void valueChanged(ListSelectionEvent e) {
        if (e.getValueIsAdjusting() == false) {
          if (m_nodeList.getSelectedIndex() == -1) {
          	//No selection
          } else {
          	//Selection, enable the fire button.
          }
        }
			}
		});
		m_nodeList.setVisibleRowCount(15);
		JScrollPane nodeListScrollPane = new JScrollPane(m_nodeList);
		nodeListScrollPane.setPreferredSize(new Dimension(150,320));
		
		// Add list of types
		m_typeListModel = new DefaultListModel();
		s = new ArrayList(sm.getTypes());
		Collections.sort(s);
		if (s != null) {
			Iterator it = s.iterator();
			while (it.hasNext()) {
				m_typeListModel.addElement(it.next());
			}
		}
		
		m_typeList = new JList(m_typeListModel);
		m_typeList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		m_typeList.setSelectedIndex(0);
		m_typeList.addListSelectionListener(new ListSelectionListener() {
			public void valueChanged(ListSelectionEvent e) {
        if (e.getValueIsAdjusting() == false) {
          if (m_nodeList.getSelectedIndex() == -1) {
          	//No selection
          } else {
          	//Selection, enable the fire button.
          }
        }
			}
		});
		m_typeList.setVisibleRowCount(15);
		JScrollPane typeListScrollPane = new JScrollPane(m_typeList);
		typeListScrollPane.setPreferredSize(new Dimension(150,320));

    JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
    		nodeListScrollPane, typeListScrollPane);
    splitPane.setOneTouchExpandable(true);
    splitPane.setDividerLocation(400);

    add(splitPane, BorderLayout.CENTER);
	}
	
	public Set getSelectedNodes() {
		Object o[] = m_nodeList.getSelectedValues();
		Set s = new HashSet();
		for (int i = 0 ; i < o.length ; i++) {
			s.add(o[i]);
		}
		return s;
	}
	
	public Set getSelectedTypes() {
		Object o[] = m_typeList.getSelectedValues();
		Set s = new HashSet();
		for (int i = 0 ; i < o.length ; i++) {
			s.add(o[i]);
		}
		return s;
	}
}
