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

import com.cougaarsoftware.nettools.parsers.*;

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


	/**
	 * @param theGraphFile
	 */
	public Graph openGraphFile(File theGraphFile) {
		String fileName = theGraphFile.getPath();
		Graph theGraph = null;	
		
		if (fileName.endsWith(".net")) {
			// A Pajek file
			try {
				BufferedReader br =
					new BufferedReader(new FileReader(theGraphFile));
				PajekNetFile pnf = new PajekNetFile();
				theGraph = pnf.load(br);
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			}
		}
		else if (fileName.endsWith(".xml")) {
			// A GraphXML file
			GraphMLFile gmf = new GraphMLFile();
			try {
				theGraph = gmf.load(new FileInputStream(theGraphFile));
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			}
		}
		else if (fileName.endsWith(".log")) {
			// Parse log files and save as Graph.
			LogParser lp = new LogParser();
			String names[] = { fileName };
			lp.parseCougaarLogFiles(names);
			theGraph = lp.getGraph();
		}
		return theGraph;
	}
	
}
