/*
 * Created on Feb 26, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package com.cougaarsoftware.nettool.parsers;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class LogGenerator {
	static private DateFormat df = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM);
	
	public void generateLogFile(int numberOfNodes, int numberOfLines, String fileName) {
		File f = new File(fileName);
		try {
			FileOutputStream fos = new FileOutputStream(f);
			PrintWriter pw = new PrintWriter(fos);
			StringBuffer sb = new StringBuffer();
			generateNodes(numberOfNodes);
			Random r = new Random();
			for (int i = 0 ; i < numberOfLines ; i++) {
				sb.setLength(0);
				sb.append(df.format(new Date()));
				sb.append(" ");
				sb.append(nodes.get(r.nextInt(numberOfNodes)));
				sb.append(" ");
				sb.append(nodes.get(r.nextInt(numberOfNodes)));
				sb.append(" ");
				sb.append("SC");
				pw.println(sb.toString());
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	private List nodes;
	
	private void generateNodes(int numberOfNodes) {
		nodes = new ArrayList();
		for (int i = 0 ; i < numberOfNodes ; i++) {
			nodes.add("Agent-" + i);
		}
	}
}
