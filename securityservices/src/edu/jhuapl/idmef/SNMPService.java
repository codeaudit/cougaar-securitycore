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
/** This class represents a service having to do with SNMP. 
    See Section 5.2.6.4.2 of the IDMEF internet-draft for more info.
*/
public class SNMPService extends Service implements XMLSerializable{

    protected String oid;

    protected String community;

    protected String command;

    //getters and setters 
    public String getOid(){
	return oid;
    }
    public void setOid(String inOid){
	oid = inOid;
    }


    public String getcommunity(){
	return community;
    }
    public void setCommunity(String inCommunity){
	community = inCommunity;
    }

    public String getcommand(){
	return command;
    }
    public void setCommand(String inCommand){
	command = inCommand;
    }
    /**Copies arguments into corresponding fields.
      */
    public SNMPService(String inName, Integer inPort, String inPortlist, 
		      String inProtocol, String inIdent, 

		      String inOid, String inCommunity, String inCommand){
	
	super(inName, inPort, inPortlist, inProtocol, inIdent);

	oid = inOid;
	community = inCommunity;
	command = inCommand;
    }
    /**Creates an object with all fields null.
     */
    public SNMPService(){
	this(null, null, null, null, null, null, null, null);
    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public SNMPService (Node node){

	super(node);
	


	Node oidNode =  XMLUtils.GetNodeForName(node, "oid");
	if (oidNode == null) oid = null;
	else oid = XMLUtils.getAssociatedString(oidNode);

	Node communityNode =  XMLUtils.GetNodeForName(node, "community");
	if (communityNode == null) community = null;
	else community = XMLUtils.getAssociatedString(communityNode);

	Node commandNode =  XMLUtils.GetNodeForName(node, "command");
	if (commandNode == null) command = null;
	else command = XMLUtils.getAssociatedString(commandNode);


    }

    public Node convertToXML(Document parent){

	

	Element snmpserviceNode = parent.createElement("WebService");
	if(ident != null)
	    snmpserviceNode.setAttribute("ident", ident);

	    
	
	if(name != null){
	    Node nameNode = parent.createElement("name");
	    nameNode.appendChild(parent.createTextNode(name));
	    snmpserviceNode.appendChild(nameNode);
	    
	}
	if(port != null){
	    Node portNode = parent.createElement("port");
	    portNode.appendChild(parent.createTextNode(port.toString()));
	    snmpserviceNode.appendChild(portNode);
	    
	}
	if(portlist != null){
	    Node portlistNode = parent.createElement("portlist");
	    portlistNode.appendChild(parent.createTextNode(portlist));
	    snmpserviceNode.appendChild(portlistNode);
	    
	}
	if(protocol != null){
	    Node protocolNode = parent.createElement("protocol");
	    protocolNode.appendChild(parent.createTextNode(protocol));
	    snmpserviceNode.appendChild(protocolNode);
	    
	}

	if(oid != null){
	    Node oidNode = parent.createElement("oid");
	    oidNode.appendChild(parent.createTextNode(oid));
	    snmpserviceNode.appendChild(oidNode);
	    
	}

	if(community != null){
	    Node communityNode = parent.createElement("community");
	    communityNode.appendChild(parent.createTextNode(community));
	    snmpserviceNode.appendChild(communityNode);
	    
	}

	if(command != null){
	    Node commandNode = parent.createElement("command");
	    commandNode.appendChild(parent.createTextNode(command));
	    snmpserviceNode.appendChild(commandNode);
	    
	}




	return snmpserviceNode;
    }
    /** Method used to test this object...probably should not be called otherwise.
     */

    public static void main (String args[]){

	

	try{
	    SNMPService idmefnode = new SNMPService("Test_Name", new Integer(80), 
					   "26, 8, 100-1098", "http", "test_ident",
					   "test_oid", "columbia", 
					   "fetch" );

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
	      

	    SNMPService new_i = new SNMPService(tNode);


	} catch (Exception e) {e.printStackTrace();}
    }
}
