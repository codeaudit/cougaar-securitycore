/*
 * Created on Feb 25, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package com.cougaarsoftware.nettool;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;

import com.cougaarsoftware.nettool.parsers.*;

import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.io.GraphMLFile;
import edu.uci.ics.jung.io.PajekNetFile;

/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
public class GraphFileHandler {

	private SocietyModel m_societyModel;
	
	/**
	 * @param theGraphFile
	 */
	public void openGraphFile(File theGraphFile, SocietyModel sm) {
		m_societyModel = sm;
		String fileName = theGraphFile.getPath();
		Graph theGraph = null;	
		
		if (fileName.endsWith(".net")) {
			// A Pajek file
			try {
				BufferedReader br =
					new BufferedReader(new FileReader(theGraphFile));
				PajekNetFile pnf = new PajekNetFile();
				m_societyModel.setGraph(pnf.load(br));
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			}
		}
		else if (fileName.endsWith(".xml")) {
			// A GraphXML file
			GraphMLFile gmf = new GraphMLFile();
			try {
				m_societyModel.setGraph(gmf.load(new FileInputStream(theGraphFile)));
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			}
		}
		else if (fileName.endsWith(".log")) {
			// Parse log files and save as Graph.
			LogParser lp = new LogParser(m_societyModel);
			String names[] = { fileName };
			lp.parseCougaarLogFiles(names);
		}
	}
	
}
