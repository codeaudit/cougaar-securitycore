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

/** This class represents a network address.
    See Section 5.2.6.1.1 of the IDMEF internet-draft for more info.
*/

public class Address implements XMLSerializable{

    protected String address;

    protected String netmask;

    //attributes

    protected String ident;

    protected String category;

    protected String vlan_name;

    protected Integer vlan_num;



    //constants
    public static final String ELEMENT_NAME    = "Address";
    public static final String ATTRIBUTE_CATEGORY = "category";
    public static final String CHILD_ELEMENT_ADDRESS = "address";
    public static final String CHILD_ELEMENT_NETMASK = "netmask";
    
    public static final String UNKNOWN         = "unknown";
    public static final String ATM             = "atm";
    public static final String E_MAIL          = "e-mail";
    public static final String LOTUS_NOTES     = "lotus-notes";
    public static final String MAC             = "mac";
    public static final String SNA             = "sna";
    public static final String VM              = "vm";
    public static final String IPV4_ADDR       = "ipv4-addr";
    public static final String IPV4_ADDR_HEX   = "ipv4-addr-hex";
    public static final String IPV4_NET        = "ipv4-net";
    public static final String IPV4_NET_MASK   = "ipv4-net-mask";
    public static final String IPV6_ADDR       = "ipv6-addr";
    public static final String IPV6_ADDR_HEX   = "ipv6-addr-hex";
    public static final String IPV6_NET        = "ipv6-net";
    public static final String IPV6_NET_MASK   = "ipv6-addr-net-mask";
    public static final String URL_ADDR        = "url";
    
    public String getAddress(){
	return address;
    }
    public void setAddress(String inAddress){
	address = inAddress;
    }

    public String getNetmask(){
	return netmask;
    }
    public void setNetmask(String inNetmask){
	netmask = inNetmask;
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

    public String getVlan_name(){
	return vlan_name;
    }
    public void setVlan_Name(String inVlan_Name){
	vlan_name = inVlan_Name;
    }

    public Integer getVlan_num(){
	return vlan_num;
    }
    public void setVlan_Num(Integer inVlan_Num){
	vlan_num = inVlan_Num;
    }

/* 
   returns true when attributes of comparing object and this object are null or equal.
   Attributes that are compared are :
    Addresses
    Name
      
*/
  public boolean equals(Object anObject) {
    boolean equals=false;
    boolean areaddressequal=false;
    boolean arenetmaskequal=true;
    boolean arecategoryequal=false;
    boolean arevlannameequal=true;
    boolean arevlannumequal=true;
    Address inaddress;
    if(anObject==null) {
      return equals;
    }
    if(anObject instanceof Address) {
      inaddress=(Address) anObject;
      String invalue;
      String myvalue;
      invalue=inaddress.getAddress();
      myvalue=this.getAddress();
      if((myvalue!=null)&&(invalue!=null)) {
	if(myvalue.trim().equals(invalue.trim())) {
	  areaddressequal=true;
	}
      }
      else if((myvalue==null)&&(invalue==null)) {
	areaddressequal=true;
      }
      /*
      invalue=inaddress.getNetmask();
      myvalue=this.getNetmask();
      if((myvalue!=null) && (invalue!=null)){
	if(myvalue.trim().equals(invalue.trim())) {
	  arenetmaskequal=true;
	}
      }
      else if((myvalue==null) && (invalue==null)){
	arenetmaskequal=true;
      }
      */
      invalue=inaddress.getCategory();
      myvalue=this.getCategory();
      if((myvalue!=null) &&(invalue!=null)) {
	if(myvalue.trim().equals(invalue.trim())) {
	  arecategoryequal=true;
	}
      }
      else if((myvalue==null) &&(invalue==null)) {
	arecategoryequal=true;
      }
      /*
      invalue=inaddress.getVlan_name();
      myvalue=this.getVlan_name();
      if((myvalue!=null) && (invalue!=null)) {
	if(myvalue.trim().equals(invalue.trim())) {
	  arevlannameequal=true; 
	}
      }
      else if( (myvalue==null) &&(invalue==null)) {
	arevlannameequal=true;
      }
      if((this.getVlan_num()!=null) && (inaddress.getVlan_num()!=null)) {
	if(this.getVlan_num().intValue()==inaddress.getVlan_num().intValue()) {
	  arevlannumequal=true;
	}
      }
      else if((this.getVlan_num()==null) && (inaddress.getVlan_num()==null)) {
	 arevlannumequal=true;
      }
      */
      if(areaddressequal && arenetmaskequal &&  arecategoryequal && arevlannameequal && arevlannumequal) {
	equals=true;
      }
      
    }
    return equals;
  }
    /**Creates an object with all fields null.
     */
    public Address(){
	this(null, null, null, null, null, null);
    }

    /**Copies arguments into corresponding fields.
      */
    public Address(String inAddress, String inNetmask, String inIdent, 
		   String inCategory, String inVlan_name, Integer inVlan_num){
	address = inAddress;
	netmask = inNetmask;
	ident = inIdent;
	category = inCategory;
	vlan_name = inVlan_name;
	if(inVlan_num!=null) vlan_num = new Integer (inVlan_num.intValue()); 
	else vlan_num=null;
    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public Address(Node node){
	Node addrNode =  XMLUtils.GetNodeForName(node, "address");
	if (addrNode == null) address = null;
	else address = XMLUtils.getAssociatedString(addrNode);

	Node maskNode =  XMLUtils.GetNodeForName(node, "netmask");
	if (maskNode == null) netmask = null;
	else netmask = XMLUtils.getAssociatedString(maskNode);



	NamedNodeMap nnm = node.getAttributes();

	Node identNode = nnm.getNamedItem("ident");
	if(identNode == null) ident=null;
	else ident = identNode.getNodeValue();

	Node categoryNode = nnm.getNamedItem("category");
	if (categoryNode == null) category=null;
	else category = categoryNode.getNodeValue();

	Node vlanNameNode = nnm.getNamedItem("vlan_name");
	if (vlanNameNode == null) vlan_name=null;
	else vlan_name = vlanNameNode.getNodeValue();

	Node vlanNumNode = nnm.getNamedItem("vlan_num");
	if (vlanNumNode == null) vlan_num=null;
	else vlan_num = new Integer(vlanNumNode.getNodeValue());
    }

    public Node convertToXML(Document parent){
	Element addressNode = parent.createElement("Address");
	if(ident != null)
	    addressNode.setAttribute("ident", ident);
	if(category != null)
	    addressNode.setAttribute("category", category);
	if(vlan_name != null)
	    addressNode.setAttribute("vlan_name", vlan_name);
	if(vlan_num != null)
	    addressNode.setAttribute("vlan_num", vlan_num.toString() );


	if(address != null){
	    Node addrNode = parent.createElement("address");
	    addrNode.appendChild(parent.createTextNode(address));
	    addressNode.appendChild(addrNode);
	    
	}
	if(netmask != null){
	    Node maskNode = parent.createElement("netmask");
	    maskNode.appendChild(parent.createTextNode(netmask));
	    addressNode.appendChild(maskNode);
	    
	}



	return addressNode;
    }

}
