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

/** This class represents a single user's ID. 
    See Section 5.2.6.2.1 of the IDMEF internet-draft for more info.
*/

public class UserId implements XMLSerializable{

    protected String name;

    protected Integer number;

    //attributes

    protected String ident;

    protected String type;

    //constants
    public static final String ELEMENT_NAME        = "UserId";
    public static final String CURRENT_USER        = "current-user";
    public static final String ORIGINAL_USER       = "original-user";
    public static final String TARGET_USER         = "target-user";
    public static final String USER_PRIVS          = "user-privs";
    public static final String CURRENT_GROUP       = "current-group";
    public static final String GROUP_PRIVS         = "group-privs";
    public static final String OTHER_PRIVS         = "other-privs";

    //getters and setters

    public String getName(){
	return name;
    }
    public void setName(String inName){
	name = inName;
    }

    public Integer getNumber(){
	return number;
    }
    public void setNumber(Integer inNumber){
	number = inNumber;
    }
    

    public String getIdent(){
	return ident;
    }
    public void setIdent(String inIdent){
	ident = inIdent;
    }

    public String getType(){
	return type;
    }
    public void setType(String inType){
	type = inType;
    }

    /**Creates an object with all fields null.
     */
    public UserId(){
	this(null, null, null, null);
    }

    /**Copies arguments into corresponding fields.
      */
    public UserId(String inName, Integer inNumber, 
		  String inIdent, String inType){
	name = inName;
	if (inNumber != null) number = new Integer(inNumber.intValue());
	else number = null;
	ident = inIdent;
	type = inType;

    }

    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */

    public UserId(Node node){


	Node nameNode =  XMLUtils.GetNodeForName(node, "name");
	if (nameNode == null) name = null;
	else name = XMLUtils.getAssociatedString(nameNode);

	Node numNode =  XMLUtils.GetNodeForName(node, "number");
	if (numNode == null) number=null;
	else number = new Integer(XMLUtils.getAssociatedString(numNode));

	NamedNodeMap nnm = node.getAttributes();

	Node identNode = nnm.getNamedItem("ident");
	if(identNode == null) ident=null;
	else ident = identNode.getNodeValue();

	Node typeNode = nnm.getNamedItem("type");
	if (typeNode == null) type=null;
	else type = typeNode.getNodeValue();
    }

    public Node convertToXML(Document parent){

	Element useridNode = parent.createElement("UserId");
	if(ident != null)
	    useridNode.setAttribute("ident", ident);
	if(type != null)
	    useridNode.setAttribute("type", type);


	if(name != null){
	    Node nameNode = parent.createElement("name");
	    nameNode.appendChild(parent.createTextNode(name));
	    useridNode.appendChild(nameNode);
	    
	}
	if(number != null){
	    Node numNode = parent.createElement("number");
	    numNode.appendChild(parent.createTextNode(number.toString()));
	    useridNode.appendChild(numNode);
	    
	}


	return useridNode;
    }

    /** Method used to test this object...probably should not be called otherwise.
     */
    public static void main (String args[]){
	
	UserId userid = new UserId("Test_Name", new Integer (100), "Test_Ident", UserId.CURRENT_USER);

	try{
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    Document document = builder.newDocument(); 
	    Element root = document.createElement("Test_IDMEF_Message"); 
	    document.appendChild (root);
	    Node node = userid.convertToXML(document);
	    root.appendChild(node);

	    StringWriter buf=new StringWriter();

	    XMLSerializer sezr = new XMLSerializer (buf ,new OutputFormat(document, "UTF-8", true));
	    sezr.serialize(document);
	    System.out.println(buf.getBuffer());
	    
	} catch (Exception e) {e.printStackTrace();}
    }


}
