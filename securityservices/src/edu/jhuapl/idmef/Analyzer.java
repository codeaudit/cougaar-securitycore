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
/** This class represents the sensor that detected this alert.
    See Section 5.2.4.1 of the IDMEF internet-draft for more info.
*/
public class Analyzer implements XMLSerializable{


    protected IDMEF_Node node;

    protected IDMEF_Process process;


    //attributes
    protected String analyzerid;
    // new attributes in v1.0
    protected String manufacturer;
    protected String model;
    protected String version;
    protected String analyzerClass;
    protected String ostype;
    protected String osversion;

    //getters and setters

    public IDMEF_Node getNode(){
	return node;
    }
    public void setNode(IDMEF_Node inNode){
	node = inNode;
    }

    public IDMEF_Process getProcess(){
	return process;
    }
    public void setProcess(IDMEF_Process inProcess){
	process = inProcess;
    }

    public String getAnalyzerid(){
	return analyzerid;
    }
    public void setAnalyzerid(String inAnalyzerid){
	analyzerid = inAnalyzerid;
    }
    
    public String getManufacturer(){
        return manufacturer;
    }
    public void setManufacturer( String inManufacturer ){
        manufacturer = inManufacturer;
    }
    
    public String getModel(){
        return model;
    }
    public void setModel( String inModel ){
        model = inModel;
    }
    
    public String getVersion(){
        return version;
    }
    public void setVersion( String inVersion ){
        version = inVersion;
    }
    
    public String getAnalyzerClass(){
        return analyzerClass;
    }
    public void setAnalyzerClass( String inAnalyzerClass ){
        analyzerClass = inAnalyzerClass;
    }
    
    public String getOSType(){
        return ostype;
    }
    public void setOSType( String inOSType ){
        ostype = inOSType;
    }
    
    public String getOSVersion(){
        return osversion;
    }
    public void setOSVersion( String inOSVersion ){
        osversion = inOSVersion;
    }
    
    /**Copies arguments into corresponding fields.
      */
    public Analyzer(IDMEF_Node inNode, IDMEF_Process inProcess, 
		    String inAnalyzerid, String inManufacturer, String inModel,
		    String inVersion, String inAnalyzerClass, String inOSType, 
		    String inOSVersion){
	node = inNode;
	process = inProcess;
	analyzerid = inAnalyzerid;
	manufacturer = inManufacturer;
    model = inModel;
    version = inVersion;
    analyzerClass = inAnalyzerClass;
    ostype = inOSType;
    osversion = inOSVersion;
    }
    /**Creates an object with all fields null.
     */
    public Analyzer (){
	this(null, null, null, null, null, null, null, null, null);

    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public Analyzer (Node inNode){
	Node nodeNode =  XMLUtils.GetNodeForName(inNode, "Node");
	if (nodeNode == null) node = null;
	else node = new IDMEF_Node (nodeNode);


	Node processNode =  XMLUtils.GetNodeForName(inNode, "Process");
	if (processNode == null) process = null;
	else process = new IDMEF_Process (processNode);

	NamedNodeMap nnm = inNode.getAttributes();

	Node attribute = nnm.getNamedItem("analyzerid");
	if(attribute != null){
	    analyzerid = attribute.getNodeValue();
    }
    attribute = nnm.getNamedItem("manufacturer");
    if(attribute != null){
	    manufacturer = attribute.getNodeValue();
    }
    attribute = nnm.getNamedItem("model");
    if(attribute != null){
	    model = attribute.getNodeValue();
    }
    attribute = nnm.getNamedItem("version");
    if(attribute != null){
	    version = attribute.getNodeValue();
    }
    attribute = nnm.getNamedItem("class");
    if(attribute != null){
	    analyzerClass = attribute.getNodeValue();
    }
    attribute = nnm.getNamedItem("ostype");
    if(attribute != null){
	    ostype = attribute.getNodeValue();
    } 
    attribute = nnm.getNamedItem("osversion");
    if(attribute != null){
	    osversion = attribute.getNodeValue();
    }
    }



  public Node convertToXML(Document parent){
	  Element analyzerNode = parent.createElement("Analyzer");
	  if(analyzerid != null){
	    analyzerNode.setAttribute("analyzerid", analyzerid);
	  }
    if( manufacturer != null ){
      analyzerNode.setAttribute( "manufacturer", manufacturer );
    }
    if( model != null ){
      analyzerNode.setAttribute( "model", model );
    }
    if( version != null ){
      analyzerNode.setAttribute( "version", version );
    }
    if( analyzerClass != null ){
      analyzerNode.setAttribute( "class", analyzerClass );
    }
    if( ostype != null ){
      analyzerNode.setAttribute( "ostype", ostype );
    }
    if( osversion != null ){
      analyzerNode.setAttribute( "osversion", osversion );
    }
    
	  if(node != null){
	    Node nodeNode = node.convertToXML(parent);
	    analyzerNode.appendChild(nodeNode);  
	  }
	  if(process != null){
	    Node processNode = process.convertToXML(parent);
	    analyzerNode.appendChild(processNode); 
	  }
 
	  return analyzerNode;
  }
}
