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

/** This class represents a single target of the current alert.
    See Section 5.2.4.4 of the IDMEF internet-draft for more info.
*/

public class Target implements XMLSerializable {

    protected IDMEF_Node node;

    protected User user;

    protected IDMEF_Process process;

    protected Service service;

    protected FileList fileList;
    
    //attributes

    protected String ident;

    protected String decoy;

    protected String networkInterface;


    //constants

    public static final String UNKNOWN = "unknown";
    public static final String YES = "yes";
    public static final String NO = "no";


    //getters and setters

    public IDMEF_Node getNode(){
	return node;
    }
    public void setNode(IDMEF_Node inNode){
	node = inNode;
    }

    public User getUser(){
	return user;
    }
    public void setUser(User inUser){
	user = inUser;
    }


    public IDMEF_Process getProcess(){
	return process;
    }
    public void setProcess(IDMEF_Process inProcess){
	process = inProcess;
    }

    public Service getService(){
	return service;
    }
    public void setService(Service inService){
	service = inService;
    }

    public FileList getFileList(){
        return fileList;
    }
    public void setFileList( FileList inFileList ){
        fileList = inFileList;
    }
    
    public String getIdent(){
	return ident;
    }
    public void setIdent(String inIdent){
	ident = inIdent;
    }

    public String getDecoy(){
	return decoy;
    }
    public void setDecoy(String inDecoy){
	decoy = inDecoy;
    }

    public String getNetworkInterface(){
	return networkInterface;
    }
    public void setNetworkInterface(String inNetworkInterface){
	networkInterface = inNetworkInterface;
    }

    /**Copies arguments into corresponding fields.
      */
    public Target(IDMEF_Node inNode, User inUser, IDMEF_Process inProcess,
		  Service inService, FileList inFileList, String inIdent, String inDecoy, 
		  String inNetowrkInterface){

	node = inNode;
	user = inUser;
	process = inProcess;
	service = inService;
	fileList = inFileList;
	ident = inIdent;
	decoy = inDecoy;
	networkInterface = inNetowrkInterface;

    }
    /**Creates an object with all fields null.
     */
    public Target(){
	this(null, null, null, null, null, null, null, null);
    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public Target (Node inNode){

	Node nodeNode =  XMLUtils.GetNodeForName(inNode, "Node");
	if (nodeNode == null) node = null;
	else node = new IDMEF_Node (nodeNode);

	Node userNode =  XMLUtils.GetNodeForName(inNode, "User");
	if (userNode == null) user = null;
	else user = new User (userNode);

	Node processNode =  XMLUtils.GetNodeForName(inNode, "Process");
	if (processNode == null) process = null;
	else process = new IDMEF_Process (processNode);

	Node serviceNode =  XMLUtils.GetNodeForName(inNode, "Service");
	if (serviceNode == null) service = null;
	else service = new Service (serviceNode);

    // new in v1.0
    Node fileListNode = XMLUtils.GetNodeForName( inNode, FileList.ELEMENT_NAME );
	if(fileListNode != null){
	    fileList = new FileList( fileListNode );
    }
	
	NamedNodeMap nnm = inNode.getAttributes();

	Node identNode = nnm.getNamedItem("ident");
	if(identNode == null) ident=null;
	else ident = identNode.getNodeValue();

	Node decoyNode = nnm.getNamedItem("decoy");
	if (decoyNode == null) decoy=null;
	else decoy = decoyNode.getNodeValue();

	Node networkInterfaceNode = nnm.getNamedItem("interface");
	if (networkInterfaceNode == null) networkInterface=null;
	else networkInterface = networkInterfaceNode.getNodeValue();
    }


    public Node convertToXML(Document parent){
	Element targetNode = parent.createElement("Target"
);
	if(ident != null)
	    targetNode.setAttribute("ident", ident);
	if(decoy != null)
	    targetNode.setAttribute("decoy", decoy);
	if(networkInterface != null)
	    targetNode.setAttribute("interface",networkInterface);

	if(node != null){
	    Node nodeNode = node.convertToXML(parent);
	    targetNode.appendChild(nodeNode);
	    
	}
	if(user != null){
	    Node userNode = user.convertToXML(parent);
	    targetNode.appendChild(userNode);
	    
	}
	if(process != null){
	    Node processNode = process.convertToXML(parent);
	    targetNode.appendChild(processNode);
	    
	}
	if(service != null){
	    Node serviceNode = service.convertToXML(parent);
	    targetNode.appendChild(serviceNode);
	    
	}
    if( fileList != null ){
        targetNode.appendChild( fileList.convertToXML( parent ) );
    }
    
	return targetNode;
    }
}
