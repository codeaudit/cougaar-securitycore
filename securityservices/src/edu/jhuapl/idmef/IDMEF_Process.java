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

/** This class represents a single process.
    See Section 5.2.6.3 of the IDMEF internet-draft for more info.
*/

public class IDMEF_Process implements XMLSerializable{

  protected String name;
    
  protected Integer pid;

  protected String path;

  protected String args[];

  protected String envs[];

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

  public Integer getPid(){
    return pid;
  }
  public void setPid(Integer inPid){
    pid = inPid;
  }


  public String getPath(){
    return path;
  }
  public void setPath(String inPath){
    path = inPath;
  }


  public String[] getArgs(){
    return args;
  }
  public void setArgs(String[] inArgs){
    args = inArgs;
  }


  public String[] getEnvs(){
    return envs;
  }
  public void setEnvs(String[] inEnvs){
    envs = inEnvs;
  }


  public String getIdent(){
    return ident;
  }
  public void setIdent(String inIdent){
    ident = inIdent;
  }
  
  public boolean equals(Object anObject) {
    boolean equals=false;
    boolean arenameequal=false;
    boolean arepidequal=false;
    boolean arepathequal=false;
    boolean areargsequal=false;
    boolean areenvsequal=false;
    IDMEF_Process process;
    if(anObject==null) {
      return equals;
    }
    if( anObject instanceof IDMEF_Process) {
      process=( IDMEF_Process)anObject;
      String myvalue;
      String invalue;
      myvalue=this.getName();
      invalue=process.getName();
      if( (myvalue!=null) && (invalue!=null) ) {
	if(myvalue.trim().equals(invalue.trim())) {
	  arenameequal=true;
	}
      }
      else if((myvalue==null) && (invalue==null)) {
	arenameequal=true;
      }
      myvalue=this.getPath();
      invalue=process.getPath();
      if( (myvalue!=null) && (invalue!=null) ) {
	if(myvalue.trim().equals(invalue.trim())) {
	  arepathequal=true;
	}
      }
      else if((myvalue==null) && (invalue==null)) {
	arepathequal=true;
      }
      String [] myarray;
      String [] inarray;
      myarray=this.getArgs();
      inarray=process.getArgs();
      if((myarray!=null)&&(inarray!=null)) {
	if(myarray.length==inarray.length) {
	  String value;
	  for(int i=0;i<inarray.length;i++) {
	    value=inarray[i];
	    if(!contains(myarray,value)) {
	      areargsequal=false;
	      break;
	    }
	  }
	  areargsequal=true;
	}
      }
      else if((myarray==null) && (inarray==null)) {
	areargsequal=true;
      }
      
      myarray=this.getEnvs();
      inarray=process.getEnvs();
      if((myarray!=null)&&(inarray!=null)) {
	if(myarray.length==inarray.length) {
	  String value;
	  for(int i=0;i<inarray.length;i++) {
	    value=inarray[i];
	    if(!contains(myarray,value)) {
	      areenvsequal=false;
	      break;
	    }
	  }
	  areenvsequal=true;
	}
      }
      else if((myarray==null) && (inarray==null)) {
	areenvsequal=true;
      }
      if((this.getPid()!=null) && (process.getPid()!=null)) {
	if(this.getPid().equals(process.getPid())) {
	  arepidequal=true;
	}
      }
      else if((this.getPid()==null) && (process.getPid()==null)) {
	arepidequal=true;
      }
      
      if(arenameequal && arepathequal && areargsequal && areenvsequal && arepidequal) {
	equals=true;
      }

    }
    return equals;
  }

  public boolean contains(String [] container, String inString) {
    boolean contains=false;
    if(container==null) {
      return contains;
    }
    String compstring;
    for(int i=0;i<container.length;i++) {
      compstring=container[i];
      if(compstring.trim().equals(inString.trim())) {
	contains=true;
	return contains;
      }
      
    }
    return contains;
  } 
  /**Creates an object with all fields null.
   */
  public IDMEF_Process(){
    this(null, null, null, null, null, null);
  }
  /**Copies arguments into corresponding fields.
   */
  public IDMEF_Process(String inName, Integer inPid, String inPath,
		       String inArgs[], String inEnvs[], String inIdent){

    name = inName;
    pid = inPid;
    path = inPath;
    args = inArgs;
    envs = inEnvs;
    ident= inIdent;
  }

  /**Creates an object from the XML Node containing the XML version of this object.
     This method will look for the appropriate tags to fill in the fields. If it cannot find
     a tag for a particular field, it will remain null.
  */
  public IDMEF_Process (Node node){

    Node nameNode =  XMLUtils.GetNodeForName(node, "name");
    if (nameNode == null) name = null;
    else name = XMLUtils.getAssociatedString(nameNode);

    Node pidNode =  XMLUtils.GetNodeForName(node, "pid");
    if (pidNode == null) pid = null;
    else pid = new Integer(XMLUtils.getAssociatedString(pidNode));

    Node pathNode =  XMLUtils.GetNodeForName(node, "path");
    if (pathNode == null) path = null;
    else path = XMLUtils.getAssociatedString(pathNode);


    //get address nodes here
    NodeList children = node.getChildNodes();
    ArrayList argNodes = new ArrayList();
    ArrayList envNodes = new ArrayList();
    for (int i=0; i<children.getLength(); i++){
      Node finger = children.item(i);
      if (finger.getNodeName().equals("arg")){
	String newArg = XMLUtils.getAssociatedString(finger);
	argNodes.add(newArg);
      } else if (finger.getNodeName().equals("env")){
	String newEnv = XMLUtils.getAssociatedString(finger);
	envNodes.add(newEnv);
      }

    }
    args = new String[argNodes.size()];
    for (int i=0; i< argNodes.size(); i++){
      args[i] = (String) argNodes.get(i);
    }
    envs = new String[envNodes.size()];
    for (int i=0; i< envNodes.size(); i++){
      envs[i] = (String) envNodes.get(i);
    }

    NamedNodeMap nnm = node.getAttributes();

    Node identNode = nnm.getNamedItem("ident");
    if(identNode == null) ident=null;
    else ident = identNode.getNodeValue();

  }
  public Node convertToXML(Document parent){

    Element processNode = parent.createElement("Process");
    if(ident != null)
      processNode.setAttribute("ident", ident);

    if(name != null){
      Node nameNode = parent.createElement("name");
      nameNode.appendChild(parent.createTextNode(name));
      processNode.appendChild(nameNode);
	    
    }

    if(pid != null){
      Node pidNode = parent.createElement("pid");
      pidNode.appendChild(parent.createTextNode(pid.toString()));
      processNode.appendChild(pidNode);
	    
    }

    if(path != null){
      Node pathNode = parent.createElement("path");
      pathNode.appendChild(parent.createTextNode(path));
      processNode.appendChild(pathNode);
	    
    }


    if (args != null){
      for (int i=0; i<args.length; i++){
	Node argNode = parent.createElement("arg");
	argNode.appendChild(parent.createTextNode(args[i]));
	processNode.appendChild(argNode);
      }
    }
    if (envs != null){
      for (int i=0; i<envs.length; i++){
	Node envNode = parent.createElement("env");
	envNode.appendChild(parent.createTextNode(envs[i]));
	processNode.appendChild(envNode);
      }
    }

    return processNode;
  }
  /** Method used to test this object...probably should not be called otherwise.
   */
  public static void main (String args[]){
    String arg_list[] = {"-r", "-b", "12.3.4.5"};
    String env_list[] = {"HOME=/home/mccubb/", "PATH=/usr/sbin"};

    IDMEF_Process proc = new IDMEF_Process("Test_Name", new Integer(1002), "/usr/sbin/ping",
					   arg_list, env_list, "Test_Ident");
	
    try{
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document document = builder.newDocument(); 
      Element root = document.createElement("Test_IDMEF_Message"); 
      document.appendChild (root);
      Node node = proc.convertToXML(document);
      root.appendChild(node);

      StringWriter buf=new StringWriter();

      XMLSerializer sezr = new XMLSerializer (buf ,new OutputFormat(document, "UTF-8", true));
      sezr.serialize(document);
      //System.out.println(buf.getBuffer());


    } catch (Exception e) {e.printStackTrace();}
  }

}
