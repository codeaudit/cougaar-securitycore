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

import java.net.*;
import java.util.*;
import java.text.*;
import java.io.*;

import org.w3c.dom.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.apache.xml.serialize.*;
import java.math.*;

/** This class represents a Heartbeat Message 
    See Section 5.2.3 of the IDMEF internet-draft for more info.
*/

public class Heartbeat extends IDMEF_Message {

    protected Analyzer analyzer;

    protected CreateTime createTime;

    protected AnalyzerTime analyzerTime;

    protected AdditionalData additionalData[];

    //attributes

    protected String ident;

    //getters and setters

    public Analyzer getAnalyzer(){
	return analyzer;
    }
    public void setAnalyzer(Analyzer inAnalyzer){
	analyzer = inAnalyzer;
    }

    public CreateTime getCreateTime(){
	return createTime;
    }
    public void setCreateTime(CreateTime inCreateTime){
	createTime = inCreateTime;
    }


    public AnalyzerTime getAnalyzerTime(){
	return analyzerTime;
    }
    public void setAnalyzerTime(AnalyzerTime inAnalyzerTime){
	analyzerTime = inAnalyzerTime;
    }


    public AdditionalData[] getAdditionalData(){
	return additionalData;
    }
    public void setAdditionalData(AdditionalData[] inAdditionalData){
	additionalData = inAdditionalData;
    }


    public String getIdent(){
	return ident;
    }
    public void setIdent(String inIdent){
	ident = inIdent;
    }

    /**Copies arguments into corresponding fields.
      */
    public Heartbeat(Analyzer inAnalyzer, CreateTime ct, 
		     AnalyzerTime at, 
		     AdditionalData[] ad, String inIdent){

	analyzer = inAnalyzer;
	createTime = ct;
	analyzerTime = at;
	additionalData = ad;
	ident = inIdent;
    }
    /**Creates an object with all fields null.
     */
    public Heartbeat(){
	
	this(null, null, null, null, null);
    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public Heartbeat(Node inNode){

	//read in the arrays of aggregate classes

	Node analyzerNode =  XMLUtils.GetNodeForName(inNode, "Analyzer");
	if (analyzerNode == null) analyzer = null;
	else analyzer = new Analyzer (analyzerNode);

	Node createTimeNode =  XMLUtils.GetNodeForName(inNode, "CreateTime");
	if (createTimeNode == null) createTime = null;
	else createTime = new CreateTime (createTimeNode);

	Node analyzerTimeNode =  XMLUtils.GetNodeForName(inNode, "AnalyzerTime");
	if (analyzerTimeNode == null) analyzerTime = null;
	else analyzerTime = new AnalyzerTime (analyzerTimeNode);

	NodeList children = inNode.getChildNodes();
	ArrayList additionalDataNodes = new ArrayList();

	for (int i=0; i<children.getLength(); i++){
	    Node finger = children.item(i);

	    if (finger.getNodeName().equals("AdditionalData")){
		AdditionalData newAdditionalData = new AdditionalData(finger);
		additionalDataNodes.add(newAdditionalData);
	    }


	}


	additionalData = new AdditionalData[additionalDataNodes.size()];
	for (int i=0; i< additionalDataNodes.size(); i++){
	    additionalData[i] = (AdditionalData) additionalDataNodes.get(i);
	}



	NamedNodeMap nnm = inNode.getAttributes();

	Node identNode = nnm.getNamedItem("ident");
	if(identNode == null) ident=null;
	else ident = identNode.getNodeValue();



	    
    }
    public Node convertToXML(Document parent){

	Element heartbeatNode = parent.createElement("Heartbeat");
	if(ident != null)
	    heartbeatNode.setAttribute("ident", ident);


	if(analyzer != null){
	    Node analyzerNode = analyzer.convertToXML(parent);
	    heartbeatNode.appendChild(analyzerNode);
	    
	}

	if(createTime != null){
	    Node createTimeNode = createTime.convertToXML(parent);
	    heartbeatNode.appendChild(createTimeNode);
	    
	}


	if(analyzerTime != null){
	    Node analyzerTimeNode = analyzerTime.convertToXML(parent);
	    heartbeatNode.appendChild(analyzerTimeNode);
	    
	}


	if (additionalData != null){
	    for (int i=0; i<additionalData.length; i++){
		Node currentNode = additionalData[i].convertToXML(parent);
		if (currentNode != null) heartbeatNode.appendChild(currentNode);
	    }
	}



	return heartbeatNode;
    }

    /** Method used to test this object...probably should not be called otherwise.
     */
     /*

    public static void main (String args[]){
	try{
	    //make a node
	    Address address_list[] = {new Address("1.1.1.1", null, null, null, null, null),
				      new Address("0x0987beaf", null, null, Address.IPV4_ADDR_HEX, null, null)};
	    IDMEF_Node testNode = new IDMEF_Node("Test Location", 
						 "Test Name", address_list, 
						 "Test_Ident", 
						 IDMEF_Node.DNS);
	    //make a user
	    UserId userId_list[] = {new UserId("Test_Name", new Integer (100), "Test_Ident", UserId.CURRENT_USER)};
	    
	    User testUser = new User(userId_list, "Test_Ident", User.APPLICATION);
	    
	    
	    //make a Process
	    String arg_list[] = {"-r", "-b", "12.3.4.5"};
	    String env_list[] = {"HOME=/home/mccubb/", "PATH=/usr/sbin"};
	    IDMEF_Process testProcess = new IDMEF_Process("Test_Name", new Integer(1002), "/usr/sbin/ping",
							  arg_list, env_list, "Test_Ident");
	    
	    //make a service
	    Service testService = new Service("Test_Name", new Integer(23), 
					      "26, 8, 100-1098", "telnet", "test_ident");
	    
	    

	    


	    //make an analyzer
	    
	    Analyzer testAnalyzer = new Analyzer(testNode, testProcess, "test_id");
	    
	    //make a createTime

	    //make a AnalyzerTime
	    

	    CreateTime c = new CreateTime();
	    AnalyzerTime a = new AnalyzerTime();

	
	    //make an additionalData list
	    AdditionalData ad[] = {new AdditionalData (AdditionalData.INTEGER, 
						"Chris' Age", "24")};


	    Heartbeat testHeartbeat = new Heartbeat(testAnalyzer, c, a, ad, 
					"test_ident");

	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    Document document = builder.newDocument(); 
	    Element root = (Element) document.createElement("Test_IDMEF_Message"); 
	    document.appendChild (root);
	    Node tNode = testHeartbeat.convertToXML(document);
	    root.appendChild(tNode);

	    StringWriter buf=new StringWriter();

	    XMLSerializer sezr = new XMLSerializer (buf ,new OutputFormat(document, "UTF-8", true));
	    sezr.serialize(document);
	    System.out.println(buf.getBuffer());
	      

	    Heartbeat new_i = new Heartbeat(tNode);


	} catch (Exception e) {e.printStackTrace();}
    }
    */
}
