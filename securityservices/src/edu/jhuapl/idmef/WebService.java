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

/** This class represents Services that are related to Web Traffic.
    See section 5.2.6.4.1 of the IDMEF internet-draft for meanings of fields.
*/

public class WebService extends Service implements XMLSerializable{

    protected URL url;

    protected String cgi;

    protected String method;

    protected String args[];


    public URL getUrl(){
	return url;
    }
    public void setUrl(URL inUrl){
	url = inUrl;
    }

    public String getCgi(){
	return cgi;
    }

    public void setCgi(String inCgi){
	cgi = inCgi;
    }

    public String getMethod(){
	return method;
    }

    public void setMethod(String inMethod){
	method = inMethod;
    }

    public String[] getArgs(){
	return args;
    }

    public void setArgs(String[] inArgs){
	args = inArgs;
    }

    /**Creates a new URL from the string provided. Copies other arguments into corresponding fields.
       @param inUrl the string to create the new URL object with
       
     */

    public WebService(String inName, Integer inPort, String inPortlist, 
		      String inProtocol, String inIdent, 

		      String inUrl, String inCgi, String inMethod, 
		      String inArgs[]){


	super(inName, inPort, inPortlist, inProtocol, inIdent);
	URL tempUrl;
	try {
	    tempUrl = new URL(inUrl);
	} catch (MalformedURLException e) {
	    tempUrl = null;
	}
	

	cgi = inCgi;
	method = inMethod;
	args = inArgs;
	
    
    }
    
     /**Copies arguments into corresponding fields.
      */

    public WebService(String inName, Integer inPort, String inPortlist, 
		      String inProtocol, String inIdent, 

		      URL inUrl, String inCgi, String inMethod, 
		      String inArgs[]){
	
	super(inName, inPort, inPortlist, inProtocol, inIdent);

	url = inUrl;
	cgi = inCgi;
	method = inMethod;
	args = inArgs;
    }

    /**Creates an object with all fields null.
     */

    public WebService() {
	this(null, null, null, null, null, (String) null, null, null, null);
    }

    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
       
    */

    public WebService (Node node) {

	super(node);
	
	Node urlNode =  XMLUtils.GetNodeForName(node, "url");
	if (urlNode == null) url = null;
	else {
	    try {
		url = new URL(XMLUtils.getAssociatedString(urlNode));
	    } catch (MalformedURLException e){
		url = null;
	    }
	}

	Node cgiNode =  XMLUtils.GetNodeForName(node, "cgi");
	if (cgiNode == null) cgi = null;
	else cgi = XMLUtils.getAssociatedString(cgiNode);

	Node methodNode =  XMLUtils.GetNodeForName(node, "method");
	if (methodNode == null) method = null;
	else method = XMLUtils.getAssociatedString(methodNode);

	//get args nodes here
	NodeList children = node.getChildNodes();
	ArrayList argNodes = new ArrayList();
	for (int i=0; i<children.getLength(); i++){
	    Node finger = children.item(i);
	    if (finger.getNodeName().equals("arg")){
		String newArg = XMLUtils.getAssociatedString(finger);
		argNodes.add(newArg);
	    }
	}
	args = new String[argNodes.size()];
	for (int i=0; i< argNodes.size(); i++){
	    args[i] = (String) argNodes.get(i);
	}


    }


    public Node convertToXML(Document parent){

	

	Element webserviceNode = parent.createElement("WebService");
	if(ident != null)
	    webserviceNode.setAttribute("ident", ident);

	    
	
	if(name != null){
	    Node nameNode = parent.createElement("name");
	    nameNode.appendChild(parent.createTextNode(name));
	    webserviceNode.appendChild(nameNode);
	    
	}
	if(port != null){
	    Node portNode = parent.createElement("port");
	    portNode.appendChild(parent.createTextNode(port.toString()));
	    webserviceNode.appendChild(portNode);
	    
	}
	if(portlist != null){
	    Node portlistNode = parent.createElement("portlist");
	    portlistNode.appendChild(parent.createTextNode(portlist));
	    webserviceNode.appendChild(portlistNode);
	    
	}
	if(protocol != null){
	    Node protocolNode = parent.createElement("protocol");
	    protocolNode.appendChild(parent.createTextNode(protocol));
	    webserviceNode.appendChild(protocolNode);
	    
	}

	if(url != null){
	    Node urlNode = parent.createElement("url");
	    urlNode.appendChild(parent.createTextNode(url.toString()));
	    webserviceNode.appendChild(urlNode);
	    
	}else {
	    Node urlNode = parent.createElement("url");
	    urlNode.appendChild(parent.createTextNode("Unknown URL"));
	    webserviceNode.appendChild(urlNode);
	}

	if(cgi != null){
	    Node cgiNode = parent.createElement("cgi");
	    cgiNode.appendChild(parent.createTextNode(cgi));
	    webserviceNode.appendChild(cgiNode);
	    
	}

	if(method != null){
	    Node methodNode = parent.createElement("method");
	    methodNode.appendChild(parent.createTextNode(method));
	    webserviceNode.appendChild(methodNode);
	    
	}

	if (args != null){
	    for (int i=0; i<args.length; i++){

		Node argNode = parent.createElement("arg");
		argNode.appendChild(parent.createTextNode(args[i]));

		if (argNode != null) webserviceNode.appendChild(argNode);
	    }
	}


	return webserviceNode;
    }

    /** Method used to test this object...probably should not be called otherwise.
     */

    public static void main (String args[]){
	String arglist[] = {"-b", "-c"};
	

	try{
	    WebService idmefnode = new WebService("Test_Name", new Integer(80), 
					   "26, 8, 100-1098", "http", "test_ident",
					   "http://www.yahoo.com", null, "netscape", 
					   arglist );

	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    Document document = builder.newDocument(); 
	    Element root = document.createElement("Test_IDMEF_Message"); 
	    document.appendChild (root);
	    Node tNode = idmefnode.convertToXML(document);
	    root.appendChild(tNode);

	    StringWriter buf=new StringWriter();

	    XMLSerializer sezr = new XMLSerializer (buf ,new OutputFormat(document, "UTF-8", true));
	    sezr.serialize(document);
	    System.out.println(buf.getBuffer());


	} catch (Exception e) {e.printStackTrace();}
    }
}
