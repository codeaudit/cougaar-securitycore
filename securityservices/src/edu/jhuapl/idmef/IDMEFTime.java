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

/** This class is a superclass of all the IDMEF Time classes (since they are so similar).
    See Section 5.2.5 of the IDMEF internet-draft for more info.
*/

public class IDMEFTime implements XMLSerializable{

    public String idmefDate;
    
    public String ntpstamp;

    /**This method creates a new IDMEFTime set to the current time.
     */

    public IDMEFTime(){
	Date date = new Date();
        idmefDate = convertToIDMEFFormat(date);
        ntpstamp = convertToNTP(date);
    }
  
    /**This method creates a new IDMEFTime set to any date.
     */

    public IDMEFTime(Date inDate){
	idmefDate = convertToIDMEFFormat(inDate);
        ntpstamp = convertToNTP(inDate);
    }

    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */

    public IDMEFTime (Node node){
	idmefDate = XMLUtils.getAssociatedString(node);
	NamedNodeMap nnm = node.getAttributes();
	Node ntpNode = nnm.getNamedItem("ntpstamp");
	ntpstamp = ntpNode.getNodeValue();
	
    }

    /** Converts a Date to the IDMEF Date format. Currently only does Zulu time (UTC)

     */

    public static String convertToIDMEFFormat(Date date){

	SimpleDateFormat formatter = new SimpleDateFormat ("yyyy-MM-dd'T'HH:mm:ss'Z'");
 
	return formatter.format(date);



    }
    /** Converts a Date to the NTP format. 

     */

    public static String convertToNTP(Date date){

        SimpleDateFormat formatter = new SimpleDateFormat ("'.0x'SSS'00000'");
	String currentSecs = (new Long(  (date.getTime())/1000 ).toString());
	BigInteger seconds = new BigInteger("2208988800").add(new BigInteger(currentSecs));
	
	return "0x" + seconds.toString(16) + formatter.format(date);
	



    }
    public String getidmefDate(){
	return idmefDate;

    }
    public void setIdmefDate(Date inDate){
        idmefDate = convertToIDMEFFormat(inDate);
    }

    public String getNtpstamp(){
	return ntpstamp;

    }
    public void setNtpstamp(Date inDate){
	ntpstamp = convertToNTP(inDate);
    }

    public Node convertToXML(Document parent){

	Element timeNode = parent.createElement("IDMEFTime");
	timeNode.setAttribute("ntpstamp", getNtpstamp());


	timeNode.appendChild(parent.createTextNode(getidmefDate()));
	return timeNode;
    }

    /** Method used to test this object...probably should not be called otherwise.
     */
    public static void main(String args[]){
	IDMEFTime t = new IDMEFTime ();
	DetectTime d = new DetectTime ();
	CreateTime c = new CreateTime();
	AnalyzerTime a = new AnalyzerTime();
	try{
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    Document document = builder.newDocument(); 
	    Element root = document.createElement("Test_IDMEF_Message"); 
	    document.appendChild (root);
	    Node tNode = t.convertToXML(document);
	    root.appendChild(tNode);
	    root.appendChild(d.convertToXML(document));
	    root.appendChild(c.convertToXML(document));
	    root.appendChild(a.convertToXML(document));


	    StringWriter buf=new StringWriter();

	    XMLSerializer sezr = new XMLSerializer (buf ,new OutputFormat(document, "UTF-8", true));
	    sezr.serialize(document);
	    System.out.println(buf.getBuffer());
	      

	    IDMEFTime new_t = new IDMEFTime(tNode);

	    System.out.println("Test of Node constructor: " 
			       + new_t.getNtpstamp()+ " " 
			       + new_t.getidmefDate() );


	} catch (Exception e) {e.printStackTrace();}
    }

}
