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

/** This class represents a single user. 
    See Section 5.2.6.2 of the IDMEF internet-draft for more info.
*/

public class User implements XMLSerializable{

    protected UserId userIds[];


    //attributes

    protected String ident;

    protected String category;


    //constants

    public static final String UNKNOWN = "unknown";
    public static final String APPLICATION = "application";
    public static final String OS_DEVICE = "os-device";

    //getters and setters

    public UserId[] getUserIds(){
	return userIds;
    }

    public void setUserIds(UserId[] inUserIds){
	userIds = inUserIds;
    }

    public String getIdent(){
	return ident;
    }
    public void setIdent(String inIdent){
	ident = inIdent;
    }

    public String getCategory(){
	return category;
    }
    public void setCategory(String inCategory){
	category = inCategory;
    }
    /**Creates an object with all fields null.
     */
    public User(){
	this(null, null, null);
    }
    /**Copies arguments into corresponding fields.
      */
    public User (UserId inUserIds[], String inIdent, String inCategory){

	userIds = inUserIds;
	ident = inIdent;
	category = inCategory;
    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public User(Node node){
	//get userid nodes here
	NodeList children = node.getChildNodes();
	ArrayList useridNodes = new ArrayList();
	for (int i=0; i<children.getLength(); i++){
	    Node finger = children.item(i);
	    if (finger.getNodeName().equals("UserId")){
		UserId newUserid = new UserId(finger);
		useridNodes.add(newUserid);
	    }
	}
	userIds = new UserId[useridNodes.size()];
	for (int i=0; i< useridNodes.size(); i++){
	    userIds[i] = (UserId) useridNodes.get(i);
	}

	NamedNodeMap nnm = node.getAttributes();

	Node identNode = nnm.getNamedItem("ident");
	if(identNode == null) ident=null;
	else ident = identNode.getNodeValue();

	Node categoryNode = nnm.getNamedItem("category");
	if (categoryNode == null) category=null;
	else category = categoryNode.getNodeValue();

    }
    public Node convertToXML(Document parent){

	Element userNode = parent.createElement("User");
	if(ident != null)
	    userNode.setAttribute("ident", ident);
	if(category != null)
	    userNode.setAttribute("category", category);


	if (userIds != null){
	    for (int i=0; i<userIds.length; i++){
		Node currentNode = userIds[i].convertToXML(parent);
		if (currentNode != null) userNode.appendChild(currentNode);
	    }
	}


	return userNode;
    }

    /** Method used to test this object...probably should not be called otherwise.
     */
    public static void main (String args[]){

	UserId userId_list[] = {new UserId("Test_Name", new Integer (100), "Test_Ident", UserId.CURRENT_USER)};

	User user = new User(userId_list, "Test_Ident", User.APPLICATION);

	try{
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    Document document = builder.newDocument(); 
	    Element root = document.createElement("Test_IDMEF_Message"); 
	    document.appendChild (root);
	    Node node = user.convertToXML(document);
	    root.appendChild(node);

	    StringWriter buf=new StringWriter();

	    XMLSerializer sezr = new XMLSerializer (buf ,new OutputFormat(document, "UTF-8", true));
	    sezr.serialize(document);
	    System.out.println(buf.getBuffer());
	    
	} catch (Exception e) {e.printStackTrace();}
    }

}
