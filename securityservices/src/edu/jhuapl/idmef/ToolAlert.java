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


/** This class represents an alert caused by the attack of some malicious tool. 
    See Section 5.2.2.1 of the IDMEF internet-draft for more info.
*/

public class ToolAlert extends Alert implements XMLSerializable {


    protected String name;

    protected String command;

    protected Alertident alertidents[];


    //getters and setters

    public String getName () {
	return name;
    }
    public void setName(String inName){
	name = inName;
    }

    public String getCommand(){
	return command;
    }
    public void setCommand(String inCommand){
	command = inCommand;
    }

    public Alertident[] getAlertidents(){
	return alertidents;
    }

    public void setAlertidents(Alertident[] inAlertidents){
	alertidents = inAlertidents;
    }
    /**Copies arguments into corresponding fields.
      */
    public ToolAlert(Analyzer inAnalyzer, CreateTime ct, 
		     DetectTime dt, AnalyzerTime at, Source[] inSources, 
		     Target[] inTargets, Classification[] inClassifications, 
		     Assessment inAssessment, AdditionalData[] ad, String inIdent,
		     String inName, String inCommand, 
		     Alertident[] inAlertidents){

	super(inAnalyzer, ct, dt, at, inSources, inTargets, inClassifications, 
	      inAssessment, ad, inIdent );
	name = inName;
	command = inCommand;
	alertidents = inAlertidents;

    }
    /**Creates an object with all fields null.
     */
    public ToolAlert(){

	this(null, null, null, null, null, null, null, null, null, null,
	     null, null, null);
    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public ToolAlert(Node inNode){
	super(inNode);
	
	Node taNode = XMLUtils.GetNodeForName(inNode, "ToolAlert");

	Node nameNode =  XMLUtils.GetNodeForName(taNode, "name");
	if (nameNode == null) name = null;
	else name = XMLUtils.getAssociatedString(nameNode);

	Node commandNode =  XMLUtils.GetNodeForName(taNode, "command");
	if (commandNode == null) command = null;
	else command = XMLUtils.getAssociatedString(commandNode);



	NodeList children = taNode.getChildNodes();
	ArrayList alertidentNodes = new ArrayList();

	for (int i=0; i<children.getLength(); i++){
	    Node finger = children.item(i);
	    if (finger.getNodeName().equals("alertident")){
		Alertident newAlertident = new Alertident(finger);
		alertidentNodes.add(newAlertident);
	    }

	}

	alertidents = new Alertident[alertidentNodes.size()];
	for (int i=0; i< alertidentNodes.size(); i++){
	    alertidents[i] = (Alertident) alertidentNodes.get(i);
	}
    }

    public Node convertToXML(Document parent){

	Element toolAlertNode = parent.createElement("Alert");
	if(ident != null)
	    toolAlertNode.setAttribute("ident", ident);

	if(analyzer != null){
	    Node analyzerNode = analyzer.convertToXML(parent);
	    toolAlertNode.appendChild(analyzerNode);
	    
	}

	if(createTime != null){
	    Node createTimeNode = createTime.convertToXML(parent);
	    toolAlertNode.appendChild(createTimeNode);
	    
	}

	if(detectTime != null){
	    Node detectTimeNode = detectTime.convertToXML(parent);
	    toolAlertNode.appendChild(detectTimeNode);
	    
	}

	if(analyzerTime != null){
	    Node analyzerTimeNode = analyzerTime.convertToXML(parent);
	    toolAlertNode.appendChild(analyzerTimeNode);
	    
	}

	if (sources != null){
	    for (int i=0; i<sources.length; i++){
		Node currentNode = sources[i].convertToXML(parent);
		if (currentNode != null) toolAlertNode.appendChild(currentNode);
	    }
	}

	if (targets != null){
	    for (int i=0; i<targets.length; i++){
		Node currentNode = targets[i].convertToXML(parent);
		if (currentNode != null) toolAlertNode.appendChild(currentNode);
	    }
	}

	if (classifications != null){
	    for (int i=0; i<classifications.length; i++){    
		Node currentNode = classifications[i].convertToXML(parent);
		if (currentNode != null) toolAlertNode.appendChild(currentNode);
	    }
	}
	if (additionalData != null){
	    for (int i=0; i<additionalData.length; i++){
		Node currentNode = additionalData[i].convertToXML(parent);
		if (currentNode != null) toolAlertNode.appendChild(currentNode);
	    }
	}

	//toolalert-specific
	Node toolAlertSpecificNode = parent.createElement("ToolAlert");
	toolAlertNode.appendChild(toolAlertSpecificNode);

	if(name != null){
	    Node nameNode = parent.createElement("name");
	    nameNode.appendChild(parent.createTextNode(name));
	    toolAlertSpecificNode.appendChild(nameNode);
	    
	}

	if(command != null){
	    Node commandNode = parent.createElement("command");
	    commandNode.appendChild(parent.createTextNode(command));
	    toolAlertSpecificNode.appendChild(commandNode);
	    
	}
	if (alertidents != null){
	    for (int i=0; i<alertidents.length; i++){
		Node currentNode = alertidents[i].convertToXML(parent);
		if (currentNode != null) toolAlertSpecificNode.appendChild(currentNode);
	    }
	}
	return toolAlertNode;
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
	    //make a detectTime
	    //make a AnalyzerTime
	    
	    DetectTime d = new DetectTime ();
	    CreateTime c = new CreateTime();
	    AnalyzerTime a = new AnalyzerTime();

	    //make a target list

	    Target target[] = {new Target(testNode, testUser, testProcess, testService, "test_ident", 
					  Target.YES, "/dev/eth0")};

	    //make a source list
	
	    Source source[] = {new Source(testNode, testUser, testProcess, testService, "test_ident", 
				      Source.YES, "/dev/eth0")};

	    //make a Classification list
	    Classification testClassification[] = {new Classification("Test_Name", 
							  "http://www.yahoo.com", Classification.CVE)};
 		//make an Assessment					  
		Impact impact = new Impact( Impact.HIGH,
		                            Impact.SUCCEEDED,
		                            Impact.OTHER,
		                            "test_impact" );
		Action actions[] = { new Action( Action.OTHER, "test_action" ) };
		Confidence confidence = new Confidence( Confidence.NUMERIC, 0.5f );					  
	    Assessment testAssessment = new Assessment( impact, actions, confidence );

	    //make an additionalData list
	    AdditionalData ad[] = {new AdditionalData (AdditionalData.INTEGER, 
						"Chris' Age", "24")};

	    //toolalert specific: make Alertident list
	    
	    Alertident alertidents[] = {new Alertident("Test_Ident", "Test_id")};


	    ToolAlert testAlert = new ToolAlert(testAnalyzer, c, d, a, source, target, 
					    testClassification, testAssessment, ad, 
					    "test_ident", "Test_Name", "/usr/bin/emacs",
					    alertidents
					    );

	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    Document document = builder.newDocument(); 
	    Element root = (Element) document.createElement("Test_IDMEF_Message"); 
	    document.appendChild (root);
	    Node tNode = testAlert.convertToXML(document);
	    root.appendChild(tNode);

	    StringWriter buf=new StringWriter();

	    XMLSerializer sezr = new XMLSerializer (buf ,new OutputFormat(document, "UTF-8", true));
	    sezr.serialize(document);
	    System.out.println(buf.getBuffer());
	      

	    ToolAlert new_i = new ToolAlert(tNode);


	} catch (Exception e) {e.printStackTrace();}
    }
    */
}
