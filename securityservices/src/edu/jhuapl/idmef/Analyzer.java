/* The following passage applies to all software and text files in this distribution, 
including this one:

Copyright (c) 2001, Submarine Technology Department, The Johns Hopkins University 
Applied Physics Laboratory.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

    -> Redistributions of source code must retain the above copyright notice, 
       this list of conditions and the following disclaimer.

    -> Redistributions in binary form must reproduce the above copyright notice, 
       this list of conditions and the following disclaimer in the documentation 
       and/or other materials provided with the distribution.

    -> Neither the name of the Johns Hopkins University Applied Physics Laboratory
       nor the names of its contributors may be used to endorse or promote products 
       derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
OF SUCH DAMAGE.
*/

package edu.jhuapl.idmef;

import java.util.*;
import java.text.*;
import java.io.*;

import org.w3c.dom.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.apache.xml.serialize.*;
import java.math.*;
/** This class represents the sensor that detected this alert.
    See Section 5.2.4.1 of the IDMEF internet-draft for more info.
*/
public class Analyzer implements XMLSerializable{


    protected IDMEF_Node node;

    protected IDMEF_Process process;


    //attributes

    protected String analyzerid;

    //getters and setters

    public IDMEF_Node getNode(){
	return node;
    }
    public void setNode(IDMEF_Node inNode){
	node = inNode;
    }

    public IDMEF_Process getProcess(){
	return process;
    }
    public void setProcess(IDMEF_Process inProcess){
	process = inProcess;
    }

    public String getAnalyzerid(){
	return analyzerid;
    }
    public void setAnalyzerid(String inAnalyzerid){
	analyzerid = inAnalyzerid;
    }
    /**Copies arguments into corresponding fields.
      */
    public Analyzer(IDMEF_Node inNode, IDMEF_Process inProcess, 
		    String inAnalyzerid){
	node = inNode;
	process = inProcess;
	analyzerid = inAnalyzerid;
    }
    /**Creates an object with all fields null.
     */
    public Analyzer (){
	this(null, null, null);

    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public Analyzer (Node inNode){
	Node nodeNode =  XMLUtils.GetNodeForName(inNode, "Node");
	if (nodeNode == null) node = null;
	else node = new IDMEF_Node (nodeNode);


	Node processNode =  XMLUtils.GetNodeForName(inNode, "Process");
	if (processNode == null) process = null;
	else process = new IDMEF_Process (processNode);

	NamedNodeMap nnm = inNode.getAttributes();

	Node analyzeridNode = nnm.getNamedItem("analyzerid");
	if(analyzeridNode == null) analyzerid=null;
	else analyzerid = analyzeridNode.getNodeValue();


    }



    public Node convertToXML(Document parent){
	Element analyzerNode = parent.createElement("Analyzer");
	if(analyzerid != null)
	    analyzerNode.setAttribute("analyzerid", analyzerid);

	if(node != null){
	    Node nodeNode = node.convertToXML(parent);
	    analyzerNode.appendChild(nodeNode);
	    
	}

	if(process != null){
	    Node processNode = process.convertToXML(parent);
	    analyzerNode.appendChild(processNode);
	    
	}

	return analyzerNode;
    }

    /** Method used to test this object...probably should not be called otherwise.
     */
    public static void main (String args[]){

	//make a node
	Address address_list[] = {new Address("1.1.1.1", null, null, null, null, null),
	                          new Address("0x0987beaf", null, null, Address.IPV4_ADDR_HEX, null, null)};
	IDMEF_Node testNode = new IDMEF_Node("Test Location", 
					      "Test Name", address_list, 
					      "Test_Ident", 
					      IDMEF_Node.DNS);


	//make a Process
	String arg_list[] = {"-r", "-b", "12.3.4.5"};
	String env_list[] = {"HOME=/home/mccubb/", "PATH=/usr/sbin"};
	IDMEF_Process testProcess = new IDMEF_Process("Test_Name", new Integer(1002), "/usr/sbin/ping",
					       arg_list, env_list, "Test_Ident");

	//make a analyzer

	Analyzer analyzer = new Analyzer(testNode, testProcess, "test_id");

	try{
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    Document document = builder.newDocument(); 
	    Element root = (Element) document.createElement("Test_IDMEF_Message"); 
	    document.appendChild (root);
	    Node tNode = analyzer.convertToXML(document);
	    root.appendChild(tNode);

	    StringWriter buf=new StringWriter();

	    XMLSerializer sezr = new XMLSerializer (buf ,new OutputFormat(document, "UTF-8", true));
	    sezr.serialize(document);
	    System.out.println(buf.getBuffer());
	      

	    Analyzer new_i = new Analyzer(tNode);


	} catch (Exception e) {e.printStackTrace();}
    }




}
