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

/** This class represents an alert identity.
    See Section 5.2.2.2 of the IDMEF internet-draft for more info.
*/

public class Alertident implements XMLSerializable{
    //attributes

    protected String analyzerid;
    
    //element data

    protected String elementData;

    //getters and setters
    
    public String getAnalyzerid(){
	return analyzerid;
    }

    public String getElementData(){
	return elementData;
    }
    public void setAnalyzerId(String inAnalyzerid){
	analyzerid = inAnalyzerid;
    }
    public void setElementData(String inAlertident){
	elementData = inAlertident;
    }
    /**Copies arguments into corresponding fields.
      */
    public Alertident(String inAnalyzerid, String inAlertident){
	analyzerid = inAnalyzerid;
	elementData = inAlertident;
    }
    /**Creates an object with all fields null.
     */
    public Alertident(){
	this(null, null);
    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public Alertident (Node node){
	elementData = XMLUtils.getAssociatedString(node);
	NamedNodeMap nnm = node.getAttributes();
	Node aidNode = nnm.getNamedItem("analyzerid");
	if (aidNode != null)
	    analyzerid = aidNode.getNodeValue();
	
    }

    public Node convertToXML(Document parent){

	Element alertidentNode = parent.createElement("alertident");
	if (analyzerid != null)
	    alertidentNode.setAttribute("analyzerid", analyzerid);


	alertidentNode.appendChild(parent.createTextNode(elementData));
	return alertidentNode;
    }

    /** Method used to test this object...probably should not be called otherwise.
     */
    public static void main(String args[]){

	Alertident a = new Alertident("test_id", "test_ident");
	try{
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    Document document = builder.newDocument(); 
	    Element root = document.createElement("Test_IDMEF_Message"); 
	    document.appendChild (root);
	    Node tNode = a.convertToXML(document);
	    root.appendChild(tNode);



	    StringWriter buf=new StringWriter();

	    XMLSerializer sezr = new XMLSerializer (buf ,new OutputFormat(document, "UTF-8", true));
	    sezr.serialize(document);
	    //System.out.println(buf.getBuffer());

	} catch (Exception e) {e.printStackTrace();}
    }

}
