/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */

package com.nai.security.tools;

import java.io.*;
import java.util.*;
import java.io.*;

public class PolicyGenerator
{
  private String filename = null;
  private String outputfileprefix = null;

  private Hashtable communities = null;

  public PolicyGenerator()
  {
    communities = new Hashtable();
  }

  public void setInputFileName(String aFilename)
  {
    filename = aFilename;
  }

  public void setOutputFilePrefix(String aPrefix)
  {
    outputfileprefix = aPrefix;
  }

  public void parseFile()
  {
    FileInputStream in = null;
    try {
      in = new FileInputStream(filename);
    }
    catch (Exception e) {
      e.printStackTrace();
      return;
    }
    Reader r = new BufferedReader(new InputStreamReader(in));
    StreamTokenizer st = new StreamTokenizer(r);

    st.resetSyntax();
    st.eolIsSignificant(true);
    st.wordChars('a', 'z');
    st.wordChars('A', 'Z');
    st.wordChars('!', '@');
    st.wordChars(128 + 32, 255);
    st.whitespaceChars(0, ' ');
    st.commentChar('/');
    st.commentChar('#');
    st.quoteChar('"');
    st.quoteChar('\'');


    int index = 0;
    ArrayList list = null;
    String community = null;

    try {
      while(st.nextToken() != StreamTokenizer.TT_EOF) {
	switch (st.ttype) {
	case StreamTokenizer.TT_EOL:
	  index = 0;
	  //System.out.println("End of line");
	  break;
	case StreamTokenizer.TT_WORD:
	  //System.out.println(st.sval + " - " + index);
	  if (index == 0) {
	    // Read community (enclave) name
	    community = st.sval;
	    list = (ArrayList) communities.get(community);
	    if (list == null) {
	      list = new ArrayList();
	    }
	  }
	  else if (index == 1) {
	    // Read agent name
	    list.add(st.sval);
	    communities.put(community, list);
	  }
	  index++;
	  break;
	case StreamTokenizer.TT_NUMBER:
	  System.out.println("Nb=" + st.nval);
	  break;
	}
      }
    }
    catch (IOException e) {
      e.printStackTrace();
      return;
    }

    Enumeration e = communities.keys();
    while (e.hasMoreElements()) {
      String c = (String) e.nextElement();
      ArrayList l = (ArrayList) communities.get(c);
      System.out.println(c);
      ListIterator it = l.listIterator();
      while (it.hasNext()) {
	System.out.println("\t" + it.next());
      }
    }
  }

  public static void main(String[] args) {
    String filename = args[0];

    PolicyGenerator pg = new PolicyGenerator();
    pg.setInputFileName(filename);
    pg.parseFile();
  }
}
