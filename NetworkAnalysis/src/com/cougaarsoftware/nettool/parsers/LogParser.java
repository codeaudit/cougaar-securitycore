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
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.cougaarsoftware.nettool.*;

/**
 * @author srosset
 *
 * Converts Cougaar network log files into Pajek or GraphML format.
 */
public class LogParser {
	
	/**
	 * Record parse errors as we parse files.
	 * A List of Exception.
	 */
	private List m_parseErrors;
	
	private SocietyModel m_societyModel;
	
	public LogParser(SocietyModel sm) {
		m_parseErrors = new ArrayList();
		m_societyModel = sm;
	}
	
	public void parseCougaarLogFiles(String []files) {
		for (int i = 0 ; i < files.length ; i++) {
			File f = new File(files[i]);
			parseFile(f);
		}
	}

	/**
	 * @param f
	 */
	private void parseFile(File f) {
		m_societyModel.resetGraph();
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
					m_societyModel.addAgentName(srcAgent);
					m_societyModel.addAgentName(dstAgent);
					m_societyModel.addEdge(ce);
				}
				else {
					m_parseErrors.add(new Exception("Unable to find match against pattern: " + line));
				}
			}
		} catch (IOException e1) {
			m_parseErrors.add(e1);
		}
	}
}
