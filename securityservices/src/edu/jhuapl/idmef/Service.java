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
/** This class represents network services on sources and targets.
    See Section 5.2.6.4 of the IDMEF internet-draft for more info.
*/
public class Service implements XMLSerializable{


    protected String name;

    protected Integer port;

    protected String portlist;

    protected String protocol;

    //attributes

    protected String ident;

    //constants
    //none

    //getters and setters
    public String getName(){
	return name;
    }
    public void setName(String inName){
	name = inName;
    }

    public Integer getPort(){
	return port;
    }
    public void setPort(Integer inPort){
	port = inPort;
    }

 
    public String getPortlist(){
	return portlist;
    }
    public void setPortlist(String inPortlist){
	portlist = inPortlist;
    }

 
    public String getProtocol(){
	return protocol;
    }
    public void setProtocol(String inProtocol){
	protocol = inProtocol;
    }

 
    public String getIdent(){
	return ident;
    }
    public void setIdent(String inIdent){
	ident = inIdent;
    }

    /**Copies arguments into corresponding fields.
     */

    public Service (String inName, Integer inPort, String inPortlist, 
		    String inProtocol, String inIdent){
	name = inName;
	if (inPort != null) port = new Integer(inPort.intValue());
	else port = null;
	portlist = inPortlist;
	protocol = inProtocol;
	ident = inIdent;

    }
    /**Creates an object with all fields null.
     */
    public Service(){
	this(null, null, null, null, null);

    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public Service (Node node){


	Node nameNode =  XMLUtils.GetNodeForName(node, "name");
	if (nameNode == null) name = null;
	else name = XMLUtils.getAssociatedString(nameNode);

	Node portNode =  XMLUtils.GetNodeForName(node, "port");
	if (portNode == null) port = null;
	else port = new Integer(XMLUtils.getAssociatedString(portNode));

	Node portlistNode =  XMLUtils.GetNodeForName(node, "portlist");
	if (portlistNode == null) portlist = null;
	else portlist = XMLUtils.getAssociatedString(portlistNode);

	Node protocolNode =  XMLUtils.GetNodeForName(node, "protocol");
	if (protocolNode == null) protocol = null;
	else protocol = XMLUtils.getAssociatedString(protocolNode);

	NamedNodeMap nnm = node.getAttributes();

	Node identNode = nnm.getNamedItem("ident");
	if(identNode == null) ident=null;
	else ident = identNode.getNodeValue();

    }

    public Node convertToXML(Document parent){

	Element serviceNode = parent.createElement("Service");
	if(ident != null)
	    serviceNode.setAttribute("ident", ident);

	    
	
	if(name != null){
	    Node nameNode = parent.createElement("name");
	    nameNode.appendChild(parent.createTextNode(name));
	    serviceNode.appendChild(nameNode);
	    
	}
	if(port != null){
	    Node portNode = parent.createElement("port");
	    portNode.appendChild(parent.createTextNode(port.toString()));
	    serviceNode.appendChild(portNode);
	    
	}
	if(portlist != null){
	    Node portlistNode = parent.createElement("portlist");
	    portlistNode.appendChild(parent.createTextNode(portlist));
	    serviceNode.appendChild(portlistNode);
	    
	}
	if(protocol != null){
	    Node protocolNode = parent.createElement("protocol");
	    protocolNode.appendChild(parent.createTextNode(protocol));
	    serviceNode.appendChild(protocolNode);
	    
	}


	return serviceNode;
    }
    /** Method used to test this object...probably should not be called otherwise.
     */
    public static void main (String args[]){

	Service idmefnode = new Service("Test_Name", new Integer(23), 
					"26, 8, 100-1098", "telnet", "test_ident");

	try{
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    Document document = builder.newDocument(); 
	    Element root = (Element) document.createElement("Test_IDMEF_Message"); 
	    document.appendChild (root);
	    Node tNode = idmefnode.convertToXML(document);
	    root.appendChild(tNode);

	    StringWriter buf=new StringWriter();

	    XMLSerializer sezr = new XMLSerializer (buf ,new OutputFormat(document, "UTF-8", true));
	    sezr.serialize(document);
	    System.out.println(buf.getBuffer());
	      

	    Service new_i = new Service(tNode);


	} catch (Exception e) {e.printStackTrace();}
    }

}
