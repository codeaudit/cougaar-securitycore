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
/** This class represents a network node. 
    See Section 5.2.6.1 of the IDMEF internet-draft for more info.
*/
public class IDMEF_Node implements XMLSerializable{

  protected String location;

  protected String name;
    
  protected Address addresses[];


  //attributes

  protected String ident;

  protected String category;
    


  //category constants
  public static final String UNKNOWN          = "unknown";
  public static final String ADS              = "ads";
  public static final String AFS              = "ads";
  public static final String CODA             = "coda";
  public static final String DFS              = "dfs";
  public static final String DNS              = "dns";
  public static final String HOSTS            = "hosts";
  public static final String KERBEROS         = "kerberos";
  public static final String NDS              = "nds";
  public static final String NIS              = "nis";
  public static final String NISPLUS          = "nisplus";
  public static final String NT               = "nt";
  public static final String WFW              = "wfw";



  //getters and setters

  public String getLocation(){

    return location;
  }
  public void setLocation(String inLocation){
    location = inLocation;
  }


  public String getName(){

    return name;
  }
  public void setName(String inName){
    name = inName;
  }

   
  public Address[] getAddresses(){

    return addresses;
  }
  public void setAddresses(Address[] inAddresses){
    addresses = inAddresses;
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




  public Node convertToXML(Document parent){

    Element nodeNode = parent.createElement("Node");
    if(ident != null)
      nodeNode.setAttribute("ident", ident);
    if(category != null)
      nodeNode.setAttribute("category", category);

    if(location != null){
      Node locNode = parent.createElement("location");
      locNode.appendChild(parent.createTextNode(location));
      nodeNode.appendChild(locNode);
	    
    }
    if(name != null){
      Node nameNode = parent.createElement("name");
      nameNode.appendChild(parent.createTextNode(name));
      nodeNode.appendChild(nameNode);
	    
    }
    if (addresses != null){
      for (int i=0; i<addresses.length; i++){
	Node currentNode = addresses[i].convertToXML(parent);
	if (currentNode != null) nodeNode.appendChild(currentNode);
      }
    }


    return nodeNode;
  }
  /**Creates an object with all fields null.
   */
  public IDMEF_Node (){
    this(null, null, null, null, null);
  }
  /**Copies arguments into corresponding fields.
   */
  public IDMEF_Node (String inLocation, String inName, 
		     Address inAddresses[], 
		     String inIdent, String inCategory){
    location = inLocation;
    name = inName;
    addresses = inAddresses;
    ident = inIdent;
    category = inCategory;
  }
  /**Creates an object from the XML Node containing the XML version of this object.
     This method will look for the appropriate tags to fill in the fields. If it cannot find
     a tag for a particular field, it will remain null.
  */
  public IDMEF_Node (Node node){
    Node locNode =  XMLUtils.GetNodeForName(node, "location");
    if (locNode == null) location = null;
    else location = XMLUtils.getAssociatedString(locNode);

    Node nameNode =  XMLUtils.GetNodeForName(node, "name");
    if (nameNode == null) name = null;
    else name = XMLUtils.getAssociatedString(nameNode);

    //get address nodes here
    NodeList children = node.getChildNodes();
    ArrayList addressNodes = new ArrayList();
    for (int i=0; i<children.getLength(); i++){
      Node finger = children.item(i);
      if (finger.getNodeName().equals("Address")){
	Address newAddress = new Address(finger);
	addressNodes.add(newAddress);
      }
    }
    addresses = new Address[addressNodes.size()];
    for (int i=0; i< addressNodes.size(); i++){
      addresses[i] = (Address) addressNodes.get(i);
    }

    NamedNodeMap nnm = node.getAttributes();

    Node identNode = nnm.getNamedItem("ident");
    if(identNode == null) ident=null;
    else ident = identNode.getNodeValue();

    Node categoryNode = nnm.getNamedItem("category");
    if (categoryNode == null) category=null;
    else category = categoryNode.getNodeValue();
  }
  /*
    Check whether input Address is in this objects Address array 
  */
  public boolean containsAddress(Address anAddress) {
    boolean contains=false;
    Address [] myAddresses;
    Address address;
    if(this.getAddresses()!=null) {
      myAddresses=this.getAddresses();
      for(int i=0;i<myAddresses.length;i++) {
	address=myAddresses[i];
	if(address.equals(anAddress)) {
	  contains=true;
	  return contains;
	}
      }
    }
    return contains;
  }
  
  /* 
     Compares the input Object to the current object for quality and returns true
     when Addresses,category,name and location are equal; 
  */
  public boolean equals( Object anObject) {
    boolean equals=false;
    boolean areaddressesequal=false;
    boolean arecategoryequal=false;
    boolean arelocationequal=false;
    boolean arenameequal=false;
    IDMEF_Node idmefnode;
    Address[] comparingAddresses;
    if(anObject==null) {
      return equals;
    }
    if(anObject instanceof IDMEF_Node) {
      idmefnode=(IDMEF_Node)anObject;
      comparingAddresses=idmefnode.getAddresses();
      if((this.getAddresses()!=null)&&(comparingAddresses!=null)) {
	if(this.getAddresses().length==comparingAddresses.length) {
	  Address comparingaddress;
	  for(int i=0;i<comparingAddresses.length;i++) {
	    comparingaddress=comparingAddresses[i];
	    if(!containsAddress(comparingaddress)) {
	      areaddressesequal=false;
	      break;
	    }
	  }
	  areaddressesequal=true;
	}
      }
      String invalue;
      String myvalue;
      invalue=idmefnode.getCategory();
      myvalue=this.getCategory();
      if((myvalue!=null)&&(invalue!=null)) {
	if(myvalue.trim().equals(invalue.trim())) {
	  arecategoryequal=true;
	}
      }
      else if((myvalue==null)&&(invalue==null)) {
	arecategoryequal=true;
      }
      invalue=idmefnode.getLocation();
      myvalue=this.getLocation();
      if((myvalue!=null) &&(invalue!=null)) {
	if(myvalue.trim().equals(invalue.trim())) {
	  arelocationequal=true;
	}
      }
      else if((myvalue==null) &&(invalue==null)) {
	arelocationequal=true;
      }
      invalue=idmefnode.getName();
      myvalue=this.getName();
      if((myvalue!=null) &&(invalue!=null)) {
	if(myvalue.trim().equals(invalue.trim())) {
	  arenameequal=true;
	}
      }
      else if( (myvalue==null)&&(invalue==null)) {
	arenameequal=true;
      }
      if(areaddressesequal && arecategoryequal && arelocationequal && arenameequal) {
	equals=true;
      }
    }
    return equals;
  }
  
  /** Method used to test this object...probably should not be called otherwise.
   */
  public static void main (String args[]){

    Address address_list[] = {new Address("1.1.1.1", null, null, null, null, null),
			      new Address("0x0987beaf", null, null, Address.IPV4_ADDR_HEX, null, null)};
    IDMEF_Node idmefnode = new IDMEF_Node("Test Location", 
					  "Test Name", address_list, 
					  "Test_Ident", 
					  IDMEF_Node.DNS);
    try{
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
