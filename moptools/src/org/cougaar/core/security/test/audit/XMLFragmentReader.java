/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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


package org.cougaar.core.security.test.audit;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;




/**
 * DOCUMENT ME!
 *
 * @version $Revision: 1.1 $
 * @author $author$
 */
public class XMLFragmentReader extends java.io.Reader {
    boolean rdyflag = false;
    Reader rdr; // current Reader
    Object[] sources;
    int[] lineCounts; // per source
    char eol = '\n';
    String readerID;
    int sourceN; // index of current Reader
    long charsRead; // in current Reader

    // 
    PrintStream log;
    String lastErr;

    /**
     * Creates a new XMLFragmentReader object.
     *
     * @param src DOCUMENT ME!
     * @param ps DOCUMENT ME!
     *
     * @throws IOException DOCUMENT ME!
     */
    public XMLFragmentReader(Object[] src, PrintStream ps)
        throws IOException {
        sources = src;
        lineCounts = new int[sources.length];
        if (ps != null) {
            log = ps;
        } else {
            log = System.out;
        }

        log.println("Created XMLfragmentReader with " + sources.length
            + " sources.");
        createReader(0);
    }

    private void createReader(int n) throws IOException {
        Object src = sources[n];
        charsRead = 0;
        log.println("Creating reader for: " + src);
        if (src instanceof String) {
            rdr = new StringReader((String) src);
            rdyflag = true;
            readerID = "InputString " + n;
        }

        if (src instanceof File) {
            rdr = new BufferedReader(new FileReader((File) src));
            rdyflag = true;
            readerID = ((File) src).getAbsolutePath();
        }

        // expand here with more source types
    }


    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws IOException DOCUMENT ME!
     */
    public boolean ready() throws IOException {
        return rdr.ready();
    }


    /**
     * DOCUMENT ME!
     *
     * @throws IOException DOCUMENT ME!
     */
    public void close() throws IOException {
        rdr.close();
        rdyflag = false;
    }


    // Return a single character or -1 if all reader sources
    // are exhausted. 
    public int read() throws IOException {
        int ch = rdr.read();
        charsRead++;
        if (ch == -1) {
            if (nextReader()) {
                ch = rdr.read();
            }
             // if no next reader return -1
        }

        if (ch == eol) {
            lineCounts[sourceN]++;
        }

        return ch;
    }


    /**
     * DOCUMENT ME!
     *
     * @param cbuf DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws IOException DOCUMENT ME!
     */
    public int read(char[] cbuf) throws IOException {
        return read(cbuf, 0, cbuf.length);
    }


    /**
     * DOCUMENT ME!
     *
     * @param cbuf DOCUMENT ME!
     * @param off DOCUMENT ME!
     * @param len DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws IOException DOCUMENT ME!
     */
    public int read(char[] cbuf, int off, int len)
        throws IOException {
        int ct = rdr.read(cbuf, off, len);
        if (ct == -1) {
            if (nextReader()) {
                ct = rdr.read(cbuf, off, len);
            }
             // if no next reader return -1
        }

        if (ct > 0) {
            countLines(cbuf, off, ct);
        }

        charsRead += ct;
        return ct;
    }


    /**
     * DOCUMENT ME!
     *
     * @param n DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws IOException DOCUMENT ME!
     */
    public long skip(long n) throws IOException {
        return rdr.skip(n);
    }


    //return true if next reader created ok
    private boolean nextReader() throws IOException {
        close(); // sets rdyflag = false ;
        if (++sourceN >= sources.length) {
            return false;
        }

        createReader(sourceN);
        return rdyflag;
    }


    // note that len is the number actually read
    private void countLines(char[] cbuf, int off, int len) {
        for (int i = 0; i < len; i++) {
            if (cbuf[off++] == eol) {
                lineCounts[sourceN]++;
            }
        }
    }


    //Method to convert a absolute line number as reported in
    //a SAXException to a source and relative line number
    public String reportRelativeLine(int absN) {
        int runningLines = 0;
        for (int i = 0; i < sources.length; i++) {
            runningLines += lineCounts[i];
            if (absN <= runningLines) {
                int startN = runningLines - lineCounts[i];
                return "Source number: " + i + " line: " + (absN - startN);
            }
        }

        return "Unable to locate line# " + absN;
    }
    
	// returns null if no error, else a String with details
	public String parse( DefaultHandler handler ){
	 SAXParser parser ;
	 try {
		 InputSource input = new InputSource( this );
		 SAXParserFactory fac = SAXParserFactory.newInstance();
		 fac.setValidating(false);
		 fac.setNamespaceAware(false);
		 parser = fac.newSAXParser() ; // default
		 parser.parse( input, handler );
		 
	 }catch(SAXParseException spe){
		 StringBuffer sb = new StringBuffer( spe.toString() );
		 sb.append("\nAbsolute Line number: " + 
				 spe.getLineNumber());
		 sb.append("\nColumn number: " + 
				 spe.getColumnNumber() );
		 sb.append("\n");
		 sb.append( reportRelativeLine( spe.getLineNumber() ));
		 lastErr = sb.toString(); 
	 }catch(Exception e){
				StringWriter sw = new StringWriter();
				e.printStackTrace( new PrintWriter( sw ) ); 
				lastErr = sw.toString();
	 }
		 return lastErr ;
	} 

	public Document build( ){
		 DocumentBuilder builder = null ;
		 Document doc = null ;
		 try {
			 InputSource input = new InputSource( this );
			 DocumentBuilderFactory fac = 
					 DocumentBuilderFactory.newInstance();
			 builder = fac.newDocumentBuilder(); // default
			 doc = builder.parse( input );
			 return doc ;
		 }catch(SAXParseException spe){
			 StringBuffer sb = new StringBuffer( spe.toString() );
			 sb.append("\nAbsolute Line number: " +
					 spe.getLineNumber());
			 sb.append("\nColumn number: " + 
					 spe.getColumnNumber() );
			 sb.append("\n");
			 sb.append( reportRelativeLine(spe.getLineNumber()));
			 lastErr = sb.toString(); 
		 }catch(Exception e){
			 StringWriter sw = new StringWriter();
			 e.printStackTrace( new PrintWriter( sw ) ); 
			 lastErr = sw.toString();
		 }
		 return null ;
	 } 
	

}
