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

/** This class represents the name of an alert.
    URL's are handled in this class in this manner: if the URL is valid, it is stored in the
    url variable as a Java URL. If not, the url variable is null and the url tag will output
    the string "Unknown URL".
    See Section 5.2.4.2 of the IDMEF internet-draft for more info.
*/
public class Classification implements XMLSerializable{

  protected String name;

  protected URL url;

  //attributes
  protected String origin;

  //getters and setters

  public String getName(){
    return name;
  }
  public void setName(String inName){
    name = inName;
  }

  public URL getUrl(){
    return url;
  }
  public void setUrl(URL inUrl){
    url = inUrl;
  }

  public String getOrigin(){
    return origin;
    
  }
  public void setOrigin(String inOrigin){
    origin = inOrigin;
  }
    
  //constants

  public static final String UNKNOWN          = "unknown";
  public static final String BUGTRAQID        = "bugtraqid";
  public static final String CVE              = "cve";
  public static final String VENDOR_SPECIFIC  = "vendor-specific";


  /**Copies arguments into corresponding fields.
   */
  public Classification(String inName, URL inUrl, String inOrigin) {

    name = inName;
    url = inUrl;
    origin = inOrigin;


  }
  /**Copies arguments into corresponding fields, except url. The url field is produced
     from the passed String.
  */
  public Classification(String inName, String inUrl, String inOrigin){

    name = inName;

    try {
      url = new URL(inUrl);
    } catch (MalformedURLException e) {
      url = null;
    }
    origin = inOrigin;


  }
  /**Creates an object with all fields null.
   */
  public Classification(){

    this(null, (URL) null, null);
  }
  /**Creates an object from the XML Node containing the XML version of this object.
     This method will look for the appropriate tags to fill in the fields. If it cannot find
     a tag for a particular field, it will remain null.
  */
  public Classification (Node node){

    Node nameNode =  XMLUtils.GetNodeForName(node, "name");
    if (nameNode == null) name = null;
    else name = XMLUtils.getAssociatedString(nameNode);

    Node urlNode =  XMLUtils.GetNodeForName(node, "url");
    if (urlNode == null) url = null;
    else {
      try {
	url = new URL(XMLUtils.getAssociatedString(urlNode));
      } catch (MalformedURLException e) {
	url = null;
      }
    }

    NamedNodeMap nnm = node.getAttributes();

    Node originNode = nnm.getNamedItem("origin");
    if(originNode == null) origin=null;
    else origin = originNode.getNodeValue();


  }


  public Node convertToXML(Document parent){

    Element classificationNode = parent.createElement("Classification");
    if(origin != null)
      classificationNode.setAttribute("origin", origin);

    if(name != null){
      Node nameNode = parent.createElement("name");
      nameNode.appendChild(parent.createTextNode(name));
      classificationNode.appendChild(nameNode);
	    
    }
    if(url != null){
      Node urlNode = parent.createElement("url");
      urlNode.appendChild(parent.createTextNode(url.toString()));
      classificationNode.appendChild(urlNode);
	    
    } else {
      Node urlNode = parent.createElement("url");
      urlNode.appendChild(parent.createTextNode("Unknown URL"));
      classificationNode.appendChild(urlNode);
    }
    return classificationNode;
  }
  
  public boolean equals(Object anObject) {
    boolean equal=false;
    if(anObject==null) {
      return equal;
    }
    if(anObject instanceof Classification) {
      Classification classification=(Classification)anObject;
      if((this.getOrigin().trim().equals(classification.getOrigin().trim()))
	 &&(this.getName().trim().equals(classification.getName().trim()))) {
	equal=true;
      }
    }
    return equal;
  } 


  /** Method used to test this object...probably should not be called otherwise.
   */

  public static void main (String args[]){


	
    try{
      Classification idmefnode = new Classification("Test_Name", 
						    "http://www.yahoo.com", Classification.CVE);
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
