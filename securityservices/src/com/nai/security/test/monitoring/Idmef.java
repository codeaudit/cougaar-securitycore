/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */

package com.nai.security.test.monitoring;

import java.net.*;
import java.util.*;
import java.text.*;
import java.io.*;
import java.math.*;

import org.w3c.dom.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.apache.xml.serialize.*;

import edu.jhuapl.idmef.*;
import org.cougaar.core.security.monitoring.blackboard.*;

public class Idmef {
        
  public static void main(String[] args) {
    Idmef tc = new Idmef();

    tc.start(args);
  }

  public void start(String[] args)
  {
    try{
      System.out.println("Creating an Alert message");

      //make a node
      Address address_list[] = {
	new Address("1.1.1.1", null, null, null, null, null),
	new Address("0x0987beaf", null, null, Address.IPV4_ADDR_HEX,
		    null, null)};
      IDMEF_Node testNode = new IDMEF_Node("Test Location", 
					   "Test Name", address_list, 
					   "Test_Ident", 
					   IDMEF_Node.DNS);
      //make a user
      UserId userId_list[] = {
	new UserId("Test_Name", new Integer (100), "Test_Ident",
		   UserId.CURRENT_USER)};
	    
      User testUser = new User(userId_list, "Test_Ident",
			       User.APPLICATION);
	    
	    
      //make a Process
      String arg_list[] = {"-r", "-b", "12.3.4.5"};
      String env_list[] = {"HOME=/home/mccubb/", "PATH=/usr/sbin"};
      IDMEF_Process testProcess =
	new IDMEF_Process("Test_Name", new Integer(1002), "/usr/sbin/ping",
			  arg_list, env_list, "Test_Ident");
	    
      //make a service
      Service testService = new Service("Test_Name", new Integer(23), 
					"26, 8, 100-1098", "telnet",
					"test_ident");

      //make an analyzer
      Analyzer testAnalyzer = new Analyzer(testNode, testProcess, "test_id");
	    
      //make a createTime
      //make a detectTime
      //make a AnalyzerTime
	    
      DetectTime d = new DetectTime ();
      CreateTime c = new CreateTime();
      AnalyzerTime a = new AnalyzerTime();

      //make a target list

      Target target[] = {
	new Target(testNode, testUser, testProcess, testService, "test_ident", 
		   Target.YES, "/dev/eth0")};

      //make a source list
	
      Source source[] = {
	new Source(testNode, testUser, testProcess, testService, "test_ident", 
		   Source.YES, "/dev/eth0")};

      //make a Classification list
      Classification testClassification[] = {
	new Classification("Test_Name", 
			   "http://www.yahoo.com", Classification.CVE)};
      //make an additionalData list
      AdditionalData ad[] = {new AdditionalData (AdditionalData.INTEGER, 
						 "Chris' Age", "24")};


      Alert testAlert =
	new Alert(testAnalyzer, c, d, a, source, target,
		  testClassification, ad, 
		  "test_ident", Alert.NOT_SUSPICIOUS);

      System.out.println("=========================== Alert message:");
      System.out.println(testAlert.toString());
      System.out.println("===========================");

      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document document = builder.newDocument(); 
      Element root = (Element) document.createElement("Test_IDMEF_Message"); 
      document.appendChild (root);
      Node tNode = testAlert.convertToXML(document);
      root.appendChild(tNode);

      StringWriter buf=new StringWriter();

      XMLSerializer sezr = new XMLSerializer (buf ,new OutputFormat(document, "UTF-8", true));
      sezr.serialize(document);
      System.out.println(buf.getBuffer());
	      

      Alert new_i = new Alert(tNode);


    } catch (Exception e) {e.printStackTrace();}
  }
}
