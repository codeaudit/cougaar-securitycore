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

/** This class represents an alert message.
    See Section 5.2.2 of the IDMEF internet-draft for more info.
*/


public class Alert extends IDMEF_Message{

    protected Analyzer analyzer;
    
    protected CreateTime createTime;

    protected DetectTime detectTime;

    protected AnalyzerTime analyzerTime;

    protected Source sources[];
    
    protected Target targets[];

    protected Classification classifications[];
    
    protected AdditionalData additionalData[];


    //attributes

    protected String ident;

    protected String impact;

    //constants

    public static final String UNKNOWN = "unknown";
    public static final String BAD_UNKNOWN = "bad-unknown";
    public static final String NOT_SUSPICIOUS = "not-suspicious";
    public static final String ATTEMPTED_ADMIN = "attempted-admin";
    public static final String SUCCESSFUL_ADMIN = "successful-admin";
    public static final String ATTEMPTED_DOS = "attempted-dos";
    public static final String SUCCESSFUL_DOS = "successful-dos";
    public static final String ATTEMPTED_RECON = "attempted-recon";
    public static final String SUCCESSFUL_RECON = "successful-recon";
    public static final String SUCCESSFUL_RECON_LIMITED = "successful-recon-limited";
    public static final String SUCCESSFUL_RECON_LARGESCALE = "successful-recon-largescale";
    public static final String ATTEMPTED_USER = "attempted-user";
    public static final String SUCCESSFUL_USER = "successful-user";

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


    public DetectTime getDetectTime(){
	return detectTime;
    }
    public void setDetectTime(DetectTime inDetectTime){
	detectTime = inDetectTime;
    }


    public AnalyzerTime getAnalyzerTime(){
	return analyzerTime;
    }
    public void setAnalyzerTime(AnalyzerTime inAnalyzerTime){
	analyzerTime = inAnalyzerTime;
    }


    public Source[] getSources(){
	return sources;
    }
     public void setSources(Source[] inSources){
	sources = inSources;
    }

   
    public Target[] getTargets(){
	return targets;
    }
    public void setTargets(Target[] inTargets){
	targets = inTargets;
    }


    public Classification[] getClassifications(){
	return classifications;
    }
     public void setClassifications(Classification[] inClassifications){
	classifications = inClassifications;
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


    public String getImpact(){
	return impact;
    }
    public void setImpact(String inImpact){
	impact = inImpact;
    }


    /**Copies arguments into corresponding fields.
      */
    public Alert(Analyzer inAnalyzer, CreateTime ct, 
		 DetectTime dt, AnalyzerTime at, Source[] inSources, 
		 Target[] inTargets, Classification[] inClassifications, 
		 AdditionalData[] ad, String inIdent, String inImpact){
	analyzer = inAnalyzer;
	createTime = ct;
	detectTime = dt;
	analyzerTime = at;
	sources = inSources;
	targets = inTargets;
	classifications = inClassifications;
	additionalData = ad;
	ident = inIdent;
	impact = inImpact;


    }
    /**Creates an object with all fields null.
     */
    public Alert(){
	
	this(null, null, null, null, null, null, null, null, null, null);
    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public Alert(Node inNode){

	//read in the arrays of aggregate classes

	Node analyzerNode =  XMLUtils.GetNodeForName(inNode, "Analyzer");
	if (analyzerNode == null) analyzer = null;
	else analyzer = new Analyzer (analyzerNode);

	Node createTimeNode =  XMLUtils.GetNodeForName(inNode, "CreateTime");
	if (createTimeNode == null) createTime = null;
	else createTime = new CreateTime (createTimeNode);

	Node detectTimeNode =  XMLUtils.GetNodeForName(inNode, "DetectTime");
	if (detectTimeNode == null) detectTime = null;
	else detectTime = new DetectTime (detectTimeNode);

	Node analyzerTimeNode =  XMLUtils.GetNodeForName(inNode, "AnalyzerTime");
	if (analyzerTimeNode == null) analyzerTime = null;
	else analyzerTime = new AnalyzerTime (analyzerTimeNode);

	NodeList children = inNode.getChildNodes();
	ArrayList sourceNodes = new ArrayList();
	ArrayList targetNodes = new ArrayList();
	ArrayList classificationNodes = new ArrayList();
	ArrayList additionalDataNodes = new ArrayList();

	for (int i=0; i<children.getLength(); i++){
	    Node finger = children.item(i);
	    String nodeName = finger.getNodeName();
	    if (nodeName.equals("Source")){
		Source newSource = new Source(finger);
		sourceNodes.add(newSource);
	    }
	    else if (nodeName.equals("Target")){
		Target newTarget = new Target(finger);
		targetNodes.add(newTarget);
	    }
	    else if (nodeName.equals("Classification")){
		Classification newClassification=null;
		
		newClassification = new Classification(finger);
		classificationNodes.add(newClassification);

		//Old code...no longer valid.
		//} catch (MalformedURLException e){
		//    System.err.println("Warning: bad URL detected in classification");
		//}
		
	    }
	    else if (nodeName.equals("AdditionalData")){
		AdditionalData newAdditionalData = new AdditionalData(finger);
		additionalDataNodes.add(newAdditionalData);
	    }


	}

	sources = new Source[sourceNodes.size()];
	for (int i=0; i< sourceNodes.size(); i++){
	    sources[i] = (Source) sourceNodes.get(i);
	}

	targets = new Target[targetNodes.size()];
	for (int i=0; i< targetNodes.size(); i++){
	    targets[i] = (Target) targetNodes.get(i);
	}
	

	classifications = new Classification[classificationNodes.size()];
	for (int i=0; i< classificationNodes.size(); i++){
	    classifications[i] = (Classification) classificationNodes.get(i);
	}

	additionalData = new AdditionalData[additionalDataNodes.size()];
	for (int i=0; i< additionalDataNodes.size(); i++){
	    additionalData[i] = (AdditionalData) additionalDataNodes.get(i);
	}



	NamedNodeMap nnm = inNode.getAttributes();

	Node identNode = nnm.getNamedItem("ident");
	if(identNode == null) ident=null;
	else ident = identNode.getNodeValue();

	Node impactNode = nnm.getNamedItem("impact");
	if (impactNode == null) impact=null;
	else impact = impactNode.getNodeValue();

	    
    }
    public Node convertToXML(Document parent){

	Element alertNode = parent.createElement("Alert");
	if(ident != null)
	    alertNode.setAttribute("ident", ident);
	if(impact != null)
	    alertNode.setAttribute("impact", impact);

	if(analyzer != null){
	    Node analyzerNode = analyzer.convertToXML(parent);
	    alertNode.appendChild(analyzerNode);
	    
	}

	if(createTime != null){
	    Node createTimeNode = createTime.convertToXML(parent);
	    alertNode.appendChild(createTimeNode);
	    
	}

	if(detectTime != null){
	    Node detectTimeNode = detectTime.convertToXML(parent);
	    alertNode.appendChild(detectTimeNode);
	    
	}

	if(analyzerTime != null){
	    Node analyzerTimeNode = analyzerTime.convertToXML(parent);
	    alertNode.appendChild(analyzerTimeNode);
	    
	}

	if (sources != null){
	    for (int i=0; i<sources.length; i++){
		Node currentNode = sources[i].convertToXML(parent);
		if (currentNode != null) alertNode.appendChild(currentNode);
	    }
	}

	if (targets != null){
	    for (int i=0; i<targets.length; i++){
		Node currentNode = targets[i].convertToXML(parent);
		if (currentNode != null) alertNode.appendChild(currentNode);
	    }
	}

	if (classifications != null){
	    for (int i=0; i<classifications.length; i++){
		Node currentNode = classifications[i].convertToXML(parent);
		if (currentNode != null) alertNode.appendChild(currentNode);
	    }
	}
	if (additionalData != null){
	    for (int i=0; i<additionalData.length; i++){
		Node currentNode = additionalData[i].convertToXML(parent);
		if (currentNode != null) alertNode.appendChild(currentNode);
	    }
	}



	return alertNode;
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


	    Alert testAlert = new Alert(testAnalyzer, c, d, a, source, target, testClassification, ad, 
					"test_ident", Alert.NOT_SUSPICIOUS);

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
	      

	    Alert new_i = new Alert(tNode);


	} catch (Exception e) {e.printStackTrace();}
    }

}
