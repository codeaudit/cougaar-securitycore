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

/** This class represents an alert caused by a buffer overflow.
    See Section 5.2.2.3 of the IDMEF internet-draft for more info.
*/

public class OverflowAlert extends Alert implements XMLSerializable{

    protected String program;

    protected Integer size;
    
    protected String buffer;

    //getters and setters

    public String getProgram(){
	return program;
    }
    public void setProgram(String inProgram){
	program = inProgram;
    }

    public Integer getSize(){
	return size;
    }
    public void setSize(Integer inSize){
	size = inSize;
    }

    public String getBuffer(){
	return buffer;
    }
    public void setBuffer(String inBuffer){
	buffer = inBuffer;
    }
    /**Copies arguments into corresponding fields.
      */
    public OverflowAlert(Analyzer inAnalyzer, CreateTime ct, 
			 DetectTime dt, AnalyzerTime at, Source[] inSources, 
			 Target[] inTargets, Classification[] inClassifications, 
			 AdditionalData[] ad, String inIdent, String inImpact,

			 String inProgram, Integer inSize, String inBuffer){


	super(inAnalyzer, ct, dt, at, inSources, inTargets, inClassifications, 
	      ad, inIdent, inImpact);
        program = inProgram;
	size = inSize;
	buffer = inBuffer;

    }
    /**Creates an object with all fields null.
     */
    public OverflowAlert(){

	this(null, null, null, null, null, null, null, null, null,
	     null, null, null, null);
    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public OverflowAlert(Node inNode){
	super(inNode);
	Node oaNode = XMLUtils.GetNodeForName(inNode, "OverflowAlert");


	Node programNode =  XMLUtils.GetNodeForName(oaNode, "program");
	if (programNode == null) program = null;
	else program = XMLUtils.getAssociatedString(programNode);

	Node sizeNode =  XMLUtils.GetNodeForName(oaNode, "size");
	if (sizeNode == null) size = null;
	else size = new Integer(XMLUtils.getAssociatedString(sizeNode));

	Node bufferNode =  XMLUtils.GetNodeForName(oaNode, "buffer");
	if (bufferNode == null) buffer = null;
	else buffer = XMLUtils.getAssociatedString(bufferNode);


    }

    public Node convertToXML(Document parent){

	Element overflowalertNode = parent.createElement("Alert");
	if(ident != null)
	    overflowalertNode.setAttribute("ident", ident);
	if(impact != null)
	    overflowalertNode.setAttribute("impact", impact);

	if(analyzer != null){
	    Node analyzerNode = analyzer.convertToXML(parent);
	    overflowalertNode.appendChild(analyzerNode);
	    
	}

	if(createTime != null){
	    Node createTimeNode = createTime.convertToXML(parent);
	    overflowalertNode.appendChild(createTimeNode);
	    
	}

	if(detectTime != null){
	    Node detectTimeNode = detectTime.convertToXML(parent);
	    overflowalertNode.appendChild(detectTimeNode);
	    
	}

	if(analyzerTime != null){
	    Node analyzerTimeNode = analyzerTime.convertToXML(parent);
	    overflowalertNode.appendChild(analyzerTimeNode);
	    
	}

	if (sources != null){
	    for (int i=0; i<sources.length; i++){
		Node currentNode = sources[i].convertToXML(parent);
		if (currentNode != null) overflowalertNode.appendChild(currentNode);
	    }
	}

	if (targets != null){
	    for (int i=0; i<targets.length; i++){
		Node currentNode = targets[i].convertToXML(parent);
		if (currentNode != null) overflowalertNode.appendChild(currentNode);
	    }
	}

	if (classifications != null){
	    for (int i=0; i<classifications.length; i++){    
		Node currentNode = classifications[i].convertToXML(parent);
		if (currentNode != null) overflowalertNode.appendChild(currentNode);
	    }
	}
	if (additionalData != null){
	    for (int i=0; i<additionalData.length; i++){
		Node currentNode = additionalData[i].convertToXML(parent);
		if (currentNode != null) overflowalertNode.appendChild(currentNode);
	    }
	}

	//overflowalert-specific

	Element overflowalertSpecificNode = parent.createElement("OverflowAlert");
	overflowalertNode.appendChild(overflowalertSpecificNode);

	if(program != null){
	    Node programNode = parent.createElement("program");
	    programNode.appendChild(parent.createTextNode(program));
	    overflowalertSpecificNode.appendChild(programNode);
	    
	}

	if(size != null){
	    Node sizeNode = parent.createElement("size");
	    sizeNode.appendChild(parent.createTextNode(size.toString()));
	    overflowalertSpecificNode.appendChild(sizeNode);
	    
	}

	if(buffer != null){
	    Node bufferNode = parent.createElement("buffer");
	    bufferNode.appendChild(parent.createTextNode(buffer));
	    overflowalertSpecificNode.appendChild(bufferNode);
	    
	}

	return overflowalertNode;
    }
    /** Method used to test this object...probably should not be called otherwise.
     */
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
	    //make an additionalData list
	    AdditionalData ad[] = {new AdditionalData (AdditionalData.INTEGER, 
						"Chris' Age", "24")};

	    //overflowalert specific: make Alertident list
	    

	    OverflowAlert testAlert = new OverflowAlert(testAnalyzer, c, d, a, source, target, 
					    testClassification, ad, 
					    "test_ident", Alert.NOT_SUSPICIOUS, 
							"/usr/sbin/emacs", new Integer (109),
							"1308472348907543876473564956925"
					    
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
	      

	    OverflowAlert new_i = new OverflowAlert(tNode);


	} catch (Exception e) {e.printStackTrace();}
    }
}
