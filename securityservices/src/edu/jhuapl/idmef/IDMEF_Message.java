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
import org.apache.xerces.parsers.*;
import java.math.*;

/** This class represents an abstract IDMEF Message.
 *  It is also used to create messages from XML documents or strings.
 *  See Section 5.2.1 of the IDMEF internet-draft for more info.
 */

public abstract class IDMEF_Message implements XMLSerializable{

    public static String ELEMENT_NAME = "IDMEF-Message";
    public static String ATTRIBUTE_VERSION = "version";
    
    /**The current implemented version of IDMEF*/
    protected static String version = "1.0";

    /**The current location of the idmef DTD File*/
    protected static String dtdFileLocation;


    //initialize the dtd file location.
    static{
	dtdFileLocation = "./idmef-message.dtd";
    }

    //getters and setters
    public static void setVersion (String vers){
	version = vers;
    }

    public static String getVersion (){
	return version;
    }

    public static String getDtdFileLocation(){
	return dtdFileLocation;
    }
    public static void setDtdFileLocation(String inDtdFileLocation){
	dtdFileLocation = inDtdFileLocation ;
    }

    public Node convertToXML(Document parent){
	Element idmefNode = parent.createElement("IDMEF-Message");
	if(version != null)
	    idmefNode.setAttribute("version", version);
	return idmefNode;
    }

    /**This method is used to create messages from input XML Strings. This
       method really only parses the String and calls the createMessage(Document) method.
       @see #createMessage(Document inputXML)
       @param inputXML the String to turn into a message.
       @return the Message that is created from the String.
    */

    public static IDMEF_Message createMessage(String inputXML){
	try{
	    DOMParser parser = new DOMParser();
	    parser.parse(new InputSource(new StringReader(inputXML)));
	    Document newMessage = parser.getDocument();

	    return createMessage(newMessage);
	    
	} catch(Exception e){ e.printStackTrace();
	}
	return null;
    }
    /**This method is used to create messages from input XML Documents.
       @param inputXML the Document to turn into a message.
       @return the Message that is created from the String.
    */

    public static IDMEF_Message createMessage(Document inputXML){
	Element root = inputXML.getDocumentElement();
	//System.out.println(root.getNodeName() + root.getNodeValue());
	
	NodeList children = root.getChildNodes();
	IDMEF_Message returnValue = null;
	for (int i=0; i<children.getLength();i++){
	
	    //System.out.println(children.item(i).getNodeName());
	    if(children.item(i).getNodeName().equals("Alert")){
		boolean isAlertSubclass = false;
		//System.out.println("This is an alert");
		NodeList alertChildren = children.item(i).getChildNodes();
		for (int j=0; j<alertChildren.getLength();j++){
		    if (alertChildren.item(j).getNodeName().equals("CorrelationAlert")){
			//System.out.println("This is a CorrelationAlert");
			returnValue =  new CorrelationAlert(children.item(i));
			isAlertSubclass = true;
		    }
		    if (alertChildren.item(j).getNodeName().equals("ToolAlert")){
			//System.out.println("This is a ToolAlert");
			returnValue =  new ToolAlert(children.item(i));
			isAlertSubclass = true;
		    }
		    if (alertChildren.item(j).getNodeName().equals("OverflowAlert")){
			//System.out.println("This is a OverflowAlert");
			returnValue =  new OverflowAlert(children.item(i));
			isAlertSubclass = true;
		    }
		}
		if (!isAlertSubclass){
		    returnValue =  new Alert(children.item(i));
		}
	    }
	    else if(children.item(i).getNodeName().equals("Heartbeat")){
		//System.out.println("This is a Heartbeat");
		returnValue = new Heartbeat (children.item(i));
		
	    }
	    
	}
	//System.out.println("This is the document I created:");
	
	//if (returnValue != null) System.out.println(returnValue.serialize());
	
	return returnValue;
    }

    /**This method converts this message to a pretty-printed XML string.
     */
    public String toString(){
	try{

	    Document document = toXML();
	    
	    StringWriter buf=new StringWriter();
	    OutputFormat of = new OutputFormat(document, "UTF-8", true);
	    of.setDoctype("-//IETF//DTD RFCxxxx IDMEF v0.3//EN", getDtdFileLocation());
	    
	    //of.getOmitDocumentType();
	    XMLSerializer sezr = new XMLSerializer (buf , of);
	    sezr.serialize(document);
	    
	    return buf.toString();
	}catch (Exception e){
	    return null;
	}
    }

    public Document toXML() throws ParserConfigurationException{
	
	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	// factory.setNamespaceAware( false );
	DocumentBuilder builder = factory.newDocumentBuilder();
	Document document = builder.newDocument(); 
	// Element root = (Element) document.createElementNS("idmef", "IDMEF-Message"); 
	Element root = document.createElement("IDMEF-Message"); 
	document.appendChild (root);
	if(version != null)
	{
        root.setAttribute( "version", version );
	    /* 
	    // TODO: determine if this is necessary!
	    Attr attr = document.createAttributeNS( "idmef", "version" );
	    attr.setValue(version);
	    root.setAttributeNodeNS( attr );
	    */
	}
	
	Node messageNode = this.convertToXML(document);
	root.appendChild(messageNode);
	return document;
    }
}


