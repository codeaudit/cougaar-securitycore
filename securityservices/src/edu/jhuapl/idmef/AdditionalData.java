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

/** This class represents additional uncovered data.
    See Section 5.2.4.5 of the IDMEF internet-draft for more info.

*/


public class AdditionalData implements XMLSerializable{

    //attributes

    protected String type;
    protected String meaning;

    //element data

    protected String additionalData;
    protected XMLSerializable xmlData;

    //constants

    public static final String BYTE = "byte";
    public static final String CHARACTER = "character";
    public static final String DATE_TIME = "date-time";
    public static final String INTEGER = "integer";
    public static final String NTPSTAMP = "ntpstamp";
    public static final String PORTLIST = "portlist";
    public static final String REAL = "real";
    public static final String STRING  = "string";
    public static final String XML = "xml";

    //getters and setters

    public String getType(){
	return type;
    }
    public void setType(String inType){
	type = inType;
    }

    public String getMeaning(){
	return meaning;
    }
    public void setMeaning(String inMeaning){
	meaning = inMeaning;
    }
    public String getAdditionalData(){
	return additionalData;
    }
    public void setAdditionalData(String inAdditionalData){
	additionalData = inAdditionalData;
    }

    public XMLSerializable getXMLData(){
        return xmlData;
    }
    public void setXMLData( XMLSerializable inXMLData ){
        xmlData = inXMLData;
    }
    
    /**Copies arguments into corresponding fields.
      */
    public AdditionalData(String inType, String inMeaning, 
			  String inAdditionalData){
	type = inType;
	meaning = inMeaning;
	additionalData = inAdditionalData;
    }
    
    /**
     * constructor for creating additional xml data
     */
    public AdditionalData( XMLSerializable inXMLData, String inMeaning ){
        type = XML;
        meaning = inMeaning;
        xmlData = inXMLData;
    }
    
    /**Creates an object with all fields null.
     */
    public AdditionalData(){
	this(null, null, null);
    }
    
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public AdditionalData (Node inNode){
	//additionalData = XMLUtils.getAssociatedString(inNode);

	NamedNodeMap nnm = inNode.getAttributes();

	Node typeNode = nnm.getNamedItem("type");
	if (typeNode != null) type = typeNode.getNodeValue();
	else type = null;

	Node meaningNode = nnm.getNamedItem("meaning");
	if (meaningNode != null) meaning = meaningNode.getNodeValue();
	else meaning = null;

    if (type != null && type.equals(this.XML)){
	    //read in xml additional data
	    // extract class name from element name Cougaar:Agent
	    // create instance of that class
    } else {
	    additionalData = XMLUtils.getAssociatedString(inNode);
    }

    }

    public Node convertToXML(Document parent){

    	Element additionalDataNode = parent.createElement("AdditionalData");

	if(type != null)
	    additionalDataNode.setAttribute("type", type);
	
	if(meaning != null)
	    additionalDataNode.setAttribute("meaning", meaning);

    if( type.equals( XML ) && xmlData != null ){
        additionalDataNode.appendChild( xmlData.convertToXML( parent ) );
    }
    else{
	    additionalDataNode.appendChild(parent.createTextNode(additionalData));
    }
	return additionalDataNode;
    }
    /** Method used to test this object...probably should not be called otherwise.
     */
    public static void main (String args[]){

	AdditionalData ad = new AdditionalData (AdditionalData.INTEGER, 
						"Chris' Age", "24");
	
	try{
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    Document document = builder.newDocument(); 
	    Element root = (Element) document.createElement("Test_IDMEF_Message"); 
	    document.appendChild (root);
	    Node tNode = ad.convertToXML(document);
	    root.appendChild(tNode);

	    StringWriter buf=new StringWriter();

	    XMLSerializer sezr = new XMLSerializer (buf ,new OutputFormat(document, "UTF-8", true));
	    sezr.serialize(document);
	    System.out.println(buf.getBuffer());
	      

	    AdditionalData new_i = new AdditionalData(tNode);


	} catch (Exception e) {e.printStackTrace();}
    }
}
