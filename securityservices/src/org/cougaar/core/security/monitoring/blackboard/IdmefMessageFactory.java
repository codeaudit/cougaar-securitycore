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

package org.cougaar.core.security.monitoring.blackboard;

import edu.jhuapl.idmef.*;

/** Helper class to create IDMEF messages
 **/
public class IdmefMessageFactory {

  /*********************************************************************
                            +---------------+
                            | IDMEF-Message |
                            +---------------+
                                   /_\
                                    |
       +----------------------------+-------+
       |                                    |
   +-------+   +----------------+     +-----------+   +----------------+
   | Alert |<>-|    Analyzer    |     | Heartbeat |<>-|    Analyzer    |
   +-------+   +----------------+     +-----------+   +----------------+
   |       |   +----------------+     |           |   +----------------+
   |       |<>-|   CreateTime   |     |           |<>-|   CreateTime   |
   |       |   +----------------+     |           |   +----------------+
   |       |   +----------------+     |           |   +----------------+
   |       |<>-|   DetectTime   |     |           |<>-| AdditionalData |
   |       |   +----------------+     +-----------+   +----------------+
   |       |   +----------------+
   |       |<>-|  AnalyzerTime  |
   |       |   +----------------+
   |       |   +--------+   +----------+
   |       |<>-| Source |<>-|   Node   |
   |       |   +--------+   +----------+
   |       |   |        |   +----------+
   |       |   |        |<>-|   User   |
   |       |   |        |   +----------+
   |       |   |        |   +----------+
   |       |   |        |<>-| Process  |
   |       |   |        |   +----------+
   |       |   |        |   +----------+
   |       |   |        |<>-| Service  |
   |       |   +--------+   +----------+
   |       |   +--------+   +----------+
   |       |<>-| Target |<>-|   Node   |
   |       |   +--------+   +----------+
   |       |   |        |   +----------+
   |       |   |        |<>-|   User   |
   |       |   |        |   +----------+
   |       |   |        |   +----------+
   |       |   |        |<>-| Process  |
   |       |   |        |   +----------+
   |       |   |        |   +--------- +
   |       |   |        |<>-| Service  |       +----------------+
   |       |   |        |   +----------+  +----| Classification |
   |       |   |        |   +----------+  |    +----------------+
   |       |   |        |<>-| FileList |  |    +----------------+
   |       |   +--------+   +----------+  | +--|   Assessment   |
   |       |<>----------------------------+ |  +----------------+
   |       |<>------------------------------+  +----------------+
   |       |<>---------------------------------| AdditionalData |
   +-------+                                   +----------------+

   * Analyzer
   *   Exactly one.  Identification information for the analyzer that
   *   originated the alert.
   *
             +---------------------+
             |      Analyzer       |
             +---------------------+       0..1 +---------+
             | STRING analyzerid   |<>----------|  Node   |
             | STRING manufacturer |            +---------+
             | STRING model        |       0..1 +---------+
             | STRING version      |<>----------| Process |
             | STRING class        |            +---------+
             | STRING ostype       |
             | STRING osversion    |
             +---------------------+


                +---------------+
                |     Node      |
                +---------------+       0..1 +----------+
                | STRING ident  |<>----------| location |
                | ENUM category |            +----------+
                |               |       0..1 +----------+
                |               |<>----------|   name   |
                |               |            +----------+
                |               |       0..* +----------+
                |               |<>----------|  Address |
                |               |            +----------+
                +---------------+


               +------------------+
               |     Address      |
               +------------------+            +---------+
               | STRING ident     |<>----------| address |
               | ENUM category    |            +---------+
               | STRING vlan-name |       0..1 +---------+
               | INTEGER vlan-num |<>----------| netmask |
               |                  |            +---------+
               +------------------+


                   +--------------+
                   |    UserId    |
                   +--------------+       0..1 +--------+
                   | STRING ident |<>----------|  name  |
                   | ENUM type    |            +--------+
                   |              |       0..1 +--------+
                   |              |<>----------| number |
                   |              |            +--------+
                   +--------------+

   *
   *******************************************************************
   */

  /** Helper method to create an alert.
   *
   * Need to define the right parameters.
   * 2002-02-27 This is currently just a stub method.
   * 
   */
  public Alert createAlert()
  {
    /* Make an IPv4 address for the current host
     * The Address class is used to represent network, hardware, and
     * application addresses.
     */
    Address address_list[] = {
      new Address("1.1.1.1", null, null, null, null, null),
      new Address("0x0987beaf", null, null, Address.IPV4_ADDR_HEX,
		  null, null)};

    /* Make a Node object for the current host
     * The Node class is used to identify hosts and other network devices
     * (routers, switches, etc.).
     */
    IDMEF_Node testNode = new IDMEF_Node("Test Location", 
					 "Test Name", address_list, 
					 "Test_Ident", 
					 IDMEF_Node.DNS);
    /* Make a user
     * The User class is used to describe users.  It is primarily used as a
     * "container" class for the UserId aggregate class
     */
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


    Alert theAlert =
      new Alert(testAnalyzer, c, d, a, source, target,
		testClassification, ad, 
		"test_ident", Alert.NOT_SUSPICIOUS);

    System.out.println("=========================== Alert message:");
    System.out.println(theAlert.toString());
    System.out.println("===========================");

    return theAlert;
  }


  /** Helper method to create a heartbeat.
   */
  public void setHeartBeat()
  {
  }

}
