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

package org.cougaar.core.security.monitoring.idmef;


import java.io.File;
import java.util.Date;

import edu.jhuapl.idmef.*;
import org.w3c.dom.Node;


/********************************************************************* 
 * 
 * Factory to create IDMEF messages
 *
 * 
 *                           +---------------+
 *                           | IDMEF-Message |
 *                           +---------------+
 *                                  /_\
 *                                   |
 *      +----------------------------+-------+
 *      |                                    |
 *  +-------+   +----------------+     +-----------+   +----------------+
 *  | Alert |<>-|    Analyzer    |     | Heartbeat |<>-|    Analyzer    |
 *  +-------+   +----------------+     +-----------+   +----------------+
 *  |       |   +----------------+     |           |   +----------------+
 *  |       |<>-|   CreateTime   |     |           |<>-|   CreateTime   |
 *  |       |   +----------------+     |           |   +----------------+
 *  |       |   +----------------+     |           |   +----------------+
 *  |       |<>-|   DetectTime   |     |           |<>-| AdditionalData |
 *  |       |   +----------------+     +-----------+   +----------------+
 *  |       |   +----------------+
 *  |       |<>-|  AnalyzerTime  |
 *  |       |   +----------------+
 *  |       |   +--------+   +----------+
 *  |       |<>-| Source |<>-|   Node   |
 *  |       |   +--------+   +----------+
 *  |       |   |        |   +----------+
 *  |       |   |        |<>-|   User   |
 *  |       |   |        |   +----------+
 *  |       |   |        |   +----------+
 *  |       |   |        |<>-| Process  |
 *  |       |   |        |   +----------+
 *  |       |   |        |   +----------+
 *  |       |   |        |<>-| Service  |
 *  |       |   +--------+   +----------+
 *  |       |   +--------+   +----------+
 *  |       |<>-| Target |<>-|   Node   |
 *  |       |   +--------+   +----------+
 *  |       |   |        |   +----------+
 *  |       |   |        |<>-|   User   |
 *  |       |   |        |   +----------+
 *  |       |   |        |   +----------+
 *  |       |   |        |<>-| Process  |
 *  |       |   |        |   +----------+
 *  |       |   |        |   +--------- +
 *  |       |   |        |<>-| Service  |       +----------------+
 *  |       |   |        |   +----------+  +----| Classification |
 *  |       |   |        |   +----------+  |    +----------------+
 *  |       |   |        |<>-| FileList |  |    +----------------+
 *  |       |   +--------+   +----------+  | +--|   Assessment   |
 *  |       |<>----------------------------+ |  +----------------+
 *  |       |<>------------------------------+  +----------------+
 *  |       |<>---------------------------------| AdditionalData |
 *  +-------+                                   +----------------+
 *
 * Analyzer
 *     Exactly one.  Identification information for the analyzer that
 *     originated the alert.
 *
 *  CreateTime
 *     Exactly one.  The time the alert was created.  Of the three times
 *     that may be provided with an Alert, this is the only one that is
 *     required.
 *
 *  DetectTime
 *     Zero or one.  The time the event(s) leading up to the alert was
 *     detected.  In the case of more than one event, the time the first
 *     event was detected.  In some circumstances, this may not be the
 *     same value as CreateTime.
 *
 *  AnalyzerTime
 *     Zero or one.  The current time on the analyzer (see Section 7.3).
 *
 *  Source
 *     Zero or more.  The source(s) of the event(s) leading up to the
 *     alert.
 *
 *  Target
 *     Zero or more.  The target(s) of the event(s) leading up to the
 *     alert.
 *
 *  Classification
 *     One or more.  The "name" of the alert, or other information
 *     allowing the manager to determine what it is.
 *
 *  Assessment
 *     Zero or one.  Information about the impact of the event, actions
 *     taken by the analyzer in response to it, and the analyzer's
 *     confidence in its evaluation.
 *
 *  AdditionalData
 *     Zero or more.  Information included by the analyzer that does not
 *     fit into the data model.  This may be an atomic piece of data, or
 *     a large amount of data provided through an extension to the IDMEF
 *     (see Section 6).
 *
 *  Because DTDs do not support subclassing (see Section 4.3.4), the
 *  inheritance relationship between Alert and the ToolAlert,
 *  CorrelationAlert, and OverflowAlert subclasses shown in Figure 5.2
 *  has been replaced with an aggregate relationship.
 *
 *  Alert is represented in the XML DTD as follows:
 *
 *     <!ELEMENT Alert                         (
 *         Analyzer, CreateTime, DetectTime?, AnalyzerTime?, Source*,
 *         Target*, Classification+, Assessment?, (ToolAlert |
 *         OverflowAlert | CorrelationAlert)?, AdditionalData*
 *       )>
 *     <!ATTLIST Alert
 *         ident               CDATA                   '0'
 *       >
 *
 *  The Alert class has one attribute:
 *
 *  ident
 *     Optional.  A unique identifier for the alert, see Section 4.4.9.
 *
 ********************************************************************/
final public class IdmefMessageFactory {

    public static String CLASSIFICATION_ORIGIN = "Cougaar";

    public static IdmefMessageFactory getFactory() {
        if( m_idmefMessageFactory == null ) {
            synchronized( factoryLock ) {
                if( m_idmefMessageFactory == null ) {
                    m_idmefMessageFactory = new IdmefMessageFactory();
                }
            }
        }
        return m_idmefMessageFactory;
    }
        
   /** 
    * Stub Factory method to create an alert.
    *
    * @return a stub alert message
    */
    public Alert createAlert()
    {
       /** 
        * Make  an IPv4 address for the current host
        * The Address class is  used to represent network, hardware, and
        * application addresses.
        */
        Address address_list[] = {
            new Address( "1.1.1.1", null, null, null, null, null),
            new Address( "0x0987beaf",   null, null, Address.IPV4_ADDR_HEX,
                         null, null) };

       /** Make a Node object for the current host
        * The Node  class is used to identify hosts and other network devices
        * (routers, switches, etc.).
        */
        IDMEF_Node testNode = new IDMEF_Node( "Test Location", 
                                              "Test Name", 
                                              address_list, 
                                              "Test_Ident", 
                                              IDMEF_Node.DNS );
    
       /** 
        * Make a user
        * The User  class is used to describe users.  It is primarily used as a
        * "container" class for the UserId aggregate class
        */
        UserId userId_list[] = { new UserId( "Test_Name", 
                                             new Integer(100), 
                                             "Test_Ident",
                                             UserId.CURRENT_USER ) };
        
        User testUser = new User(userId_list, "Test_Ident",
                 User.APPLICATION);
        
        
        //make a Process
        String arg_list[] = {"-r", "-b", "12.3.4.5"};
        String env_list[] = {"HOME=/home/mccubb/", "PATH=/usr/sbin"};
        IDMEF_Process testProcess =
        new IDMEF_Process( "Test_Name", 
                           new Integer(1002), 
                           "/usr/sbin/ping",
                           arg_list, env_list, 
                           "Test_Ident" );
        
        //make a service
        Service testService = new Service( "Test_Name", new Integer(23), 
                                           "26, 8, 100-1098", "telnet",
                                           "test_ident" );

        //make an analyzer
        Analyzer testAnalyzer = new Analyzer( testNode, testProcess, "test_id", 
                                              "test_manufacturer", "test_model",
                                              "test_version", "test_class", OS_TYPE,
                                              OS_VERSION );
        
        //make a createTime
        //make a detectTime
        //make a AnalyzerTime
        
        DetectTime d = new DetectTime ();
        CreateTime c = new CreateTime();
        AnalyzerTime a = new AnalyzerTime();

        //make a target list

        Target target[] = { new Target( testNode, 
                                        testUser, 
                                        testProcess, 
                                        testService,
                                        null, 
                                        "test_ident", 
                                        Target.YES, 
                                        "/dev/eth0" ) };

        //make a source list
    
        Source source[] = { new Source( testNode, 
                                        testUser, 
                                        testProcess, 
                                        testService, 
                                        "test_ident", 
                                        Source.YES, 
                                        "/dev/eth0" ) };
    
        //make a Classification list
        Classification testClassification[] = { new Classification("Test_Name", 
                "http://www.yahoo.com", Classification.CVE)};
        //make an Assessment
        Impact impact = new Impact( Impact.HIGH,
		                            Impact.SUCCEEDED,
		                            Impact.OTHER,
		                            "test_impact" );
		Action actions[] = { new Action( Action.OTHER, "test_action" ) };
		Confidence confidence = new Confidence( Confidence.NUMERIC, new Float( 0.5f ) );					  
	    Assessment testAssessment = new Assessment( impact, actions, confidence );
	    
        //make an additionalData list
        AdditionalData ad[] = {new AdditionalData (AdditionalData.INTEGER, 
                               "Chris' Age", "24")};
    
    
        Alert theAlert =
          new Alert(testAnalyzer, c, d, a, source, target,
            testClassification, testAssessment, ad, 
            "test_ident" );
    
        System.out.println("=========================== Alert message:");
        System.out.println(theAlert.toString());
        System.out.println("===========================");
    
        return theAlert;
        
    }
    
    /**
     * Factory method to create an IDMEF Alert.
     *
     * @param analyzer the analyzer that originated the alert
     * @param sources list of sources that are involved in the event
     * @param targets list of targets that are involved in the event
     * @param classification list of classification for the event
     * @param data list of additional data that may be useful
     *
     * @return an Alert message
     */
    public Alert createAlert( Analyzer analyzer,
                              Source []sources,
                              Target []targets,
                              Classification []classifications,
                              AdditionalData []data ){
        return new Alert( analyzer,
                          new CreateTime(),
                          new DetectTime(),
                          new AnalyzerTime(),   // is this needed? if not, null.
                          sources,
                          targets,
                          classifications,
                          null,                 // assessment null for now
                          data,
                          createUniqueId() );  // should we generated unique id for messages?
    }
    
    /**
     * Factory method to create an IDMEF Alert.
     *
     * @param analyzer the analyzer that originated the alert
     * @param sources list of sources that are involved in the event
     * @param targets list of targets that are involved in the event
     * @param classification list of classification for the event
     * @param data list of additional data that may be useful
     *
     * @return an Alert message
     */
    public Alert createAlert( Sensor sensor,
                              Source []sources,
                              Target []targets,
                              Classification []classifications,
                              AdditionalData []data ){
        return createAlert( createAnalyzer( sensor ),
                            sources,
                            targets,
                            classifications,
                            data );  // should we generated unique id for messages?
    }
    
    /**
     *
     * Factory method to create a message for sensor capability registration.
     *
     * @param sensor the sensor creating a registration message
     * @param events a list of events the sensor is capable of tracking
     * @param events a list of event origins
     *
     * @return a capability Registration message
     */
    public Registration createRegistration( Sensor sensor, 
                                            String []events,
                                            String []origins ){
        int len = events.length;
        Classification capabilities[] = new Classification[ len ];
        Source sources[];
        Target targets[];
        //TODO: move string constants to appropriate classes
        AdditionalData data[] = { createAdditionalData( AdditionalData.STRING, 
                                                        "cougaar-alert-type", 
                                                        "sensor-registration" ) };
        // create classifications for each capability                                                
        for( int i = 0; i < len; i++ ) {
            capabilities[ i ] = createClassification( events[ i ], 
                                                      null,
                                                      origins[ i ] );   // not used at this moment
                                                      
        }
        
        Registration reg = new Registration( createAnalyzer( sensor ), 
                                             null,
                                             null, 
                                             capabilities,
                                             data ); 
        return reg;
    }

    /**
     * Factory method to create a registration for sensor capabilities.
     *
     * @param sensor the sensor that wants to register its capabilities
     *
     * @return a capability Registration message
     */
    public Registration createRegistration( Sensor sensor ){
        // get all the info from the sensor for capability registration
        Source sources[] = null; // get the source info from the sensor
        Target targets[] = null; // get the target info from the sensor
        Classification capabilities[] = null;  // get the capabilities from the sensor
        AdditionalData data[] = { createAdditionalData( AdditionalData.STRING, 
                                                        "cougaar-alert-type", 
                                                        Registration.TYPE ) };
                                                        
        return new Registration( createAnalyzer( sensor ),
                                 sources,
                                 targets, 
                                 capabilities,
                                 data );
    }
    
    /** 
     * Factory method to create a heartbeat.
     *
     * @param analyzer analyzer creating the heartbeat                   
     * @param additionalData additional data
     *
     * @return a Heartbeat message
     */
    public Heartbeat createHeartBeat( Analyzer analyzer, 
                                      AdditionalData []data ){
        Heartbeat heartBeat = new Heartbeat( analyzer, 
                                             new CreateTime(), 
                                             new AnalyzerTime(), 
                                             data,
                                             null ); // not used at the moment
        return heartBeat;
    }
    
    /** 
     * Factory method to create a heartbeat.
     *
     * @param sensor the sensor that is creating this heartbeat
     * @param additionalData additional data
     *
     * @return a Heartbeat message
     */
    public Heartbeat createHeartBeat( Sensor sensor,
                                      AdditionalData []data ){                                        
        return createHeartBeat( createAnalyzer( sensor ), data );
    }
     
   /**
    * Factory method to create an Analyzer
    *
    * @param sensor analyzer object containing pertinent info such as id,
    *               manufacturer, model, version, etc..
    *
    * @return an Analyzer object
    */
    public Analyzer createAnalyzer( Sensor sensor ){
        String analyzerId = sensor.getName();           // get the sensor id
        String manufacturer = sensor.getManufacturer(); // get the sensor manufacturer
        String model = sensor.getModel();               // get the sensor model
        String version = sensor.getVersion();           // get the sensor version
        String analyzerClass = sensor.getAnalyzerClass();    // get the sensor class
        String osType = sensor.getOSType();
        String osVersion = sensor.getOSVersion();
        IDMEF_Node node = sensor.getNode();             // get the node that the sensor resides
        IDMEF_Process process = sensor.getProcess();    // get the process that the sensor resides
        
        return new Analyzer( node,  // node 
                             process,  // process
                             analyzerId,
                             manufacturer,  // manufacturer
                             model,  // model
                             version,  // version
                             analyzerClass,  // class
                             osType,
                             osVersion );
    }
                                           
   /**
    * Factory method to create an Analyzer
    *
    * @param analyzerId unique across all analyzers in the intrusion 
    *                   detection environment.
    *
    * @return an Analyzer object
    */
    
    public Analyzer createAnalyzer( String analyzerId,
                                    String manufacturer,
                                    String model,
                                    String version,
                                    String analyzerClass ){
        return new Analyzer( null,  // node 
                             null,  // process
                             analyzerId,
                             manufacturer,  // manufacturer
                             model,  // model
                             version,  // version
                             analyzerClass,  // class
                             OS_TYPE,
                             OS_VERSION );
    }
    
   /**
    * Factory method to create an Analyzer
    *
    * @param analyzerId unique across all analyzers in the intrusion 
    *                   detection environment.
    * @param node node host or device on which the analyzer resides 
    * @param process process in which the analyzer is executing
    *
    * @return an Analyzer object
    */ 
    public Analyzer createAnalyzer( String analyzerId, 
                                    IDMEF_Node node, 
                                    IDMEF_Process process,
                                    String manufacturer,
                                    String model,
                                    String version,
                                    String analyzerClass ){
        return new Analyzer( node,      // node 
                             process,   // process
                             analyzerId,
                             manufacturer,  // manufacturer
                             model,  // model
                             version,  // version
                             analyzerClass,  // class
                             OS_TYPE,
                             OS_VERSION );    
    }
    
   /**
    * Factory method to create a Source
    *
    * @param node node host or device on which the analyzer resides 
    * @param spoofed indication of whether the source is, as far as the
    *                analyzer can determine, a decoy 
    *                ( Source.YES | Source.NO | Source.UNKNOWN ).
    *
    * @return a Source object
    */ 
    public Source createSource( IDMEF_Node node, String spoofed ){
        return new Source( node, 
                           null, 
                           null, 
                           null, 
                           createUniqueId(), // needed to associate agent information
                           spoofed, 
                           null );  // network interface not necessary
    
    }
    
   /**
    * Factory method to create a Source
    *
    * @param user a user of the system, device, or application 
    * @param spoofed indication of whether the source is, as far as the
    *                analyzer can determine, a decoy 
    *                ( Source.YES | Source.NO | Source.UNKNOWN ).
    *
    * @return a Source object
    */ 
    public Source createSource( User user, String spoofed ){
        return new Source( null, 
                           user, 
                           null, 
                           null, 
                           createUniqueId(), // needed to associate agent information
                           spoofed, 
                           null );  // network interface not necessary
    
    }
    
   /**
    * Factory method to create a Source
    *
    * @param process describe processes being executed on a sources
    * @param spoofed indication of whether the source is, as far as the
    *                analyzer can determine, a decoy 
    *                ( Source.YES | Source.NO | Source.UNKNOWN ).
    *
    * @return a Source object
    */ 
    public Source createSource( IDMEF_Process process, String spoofed ){
        return new Source( null, 
                           null, 
                           process, 
                           null, 
                           createUniqueId(), // needed to associate agent information
                           spoofed, 
                           null );  // network interface not necessary
    
    }
    
   /**
    * Factory method to create a Source
    *
    * @param service network services on source
    * @param spoofed indication of whether the source is, as far as the
    *                analyzer can determine, a decoy 
    *                ( Source.YES | Source.NO | Source.UNKNOWN ).
    *
    * @return a Source object
    */ 
    public Source createSource( Service service, String spoofed ){
        return new Source( null, 
                           null, 
                           null, 
                           service, 
                           createUniqueId(), // needed to associate agent information
                           spoofed, 
                           null );  // network interface not necessary
    
    }
    
   /**
    * Factory method to create a Node
    *
    * @param name the name of a node
    * @param address an array of Address
    *
    * @return an IDMEF_Node object
    */    
    public IDMEF_Node createNode( String name, Address[] addresses ){
        return new IDMEF_Node( null,  // location not necessary
                               name, 
                               addresses, 
                               null,  // unique id not necessary
                               null ); // category not necessary
    }
    
    /**
     * Factory method to create a Process
     *
     * @param program the name of the program being executed
     * @param pid the process id
     * @param path the full path of the program being executed
     * @param args the command-line arguments to the program
     * @param envs the environment string associated with the
     *             process; generally of the format "[VARIABLE=value]".  
     *
     * @return an IDMEF_Process object
     */
    public IDMEF_Process createProcess( String program, 
                                        Integer pid, 
                                        String path, 
                                        String []args, 
                                        String []envs ){
        return new IDMEF_Process( program, 
                                  pid, 
                                  path, 
                                  args, 
                                  envs, 
                                  null ); // unique id not necessary
    }
    
    /**
     * Factory method to create a User
     *
     * @param userIds the unique ids of the user
     *
     * @return a User object
     */
    public User createUser( UserId []userIds ){
        return new User( userIds, null, null );
    }
   
   /**
     * Factory method to create a Service
     *
     * @param name the name of the service
     * @param protocol the protocol being used (optional)
     *
     * @return a Service object
     */
    public Service createService( String name, String protocol ){
        return new Service( name, 
                            null, 
                            null, 
                            protocol, 
                            null ); // ident not necessary
    }
    
    /**
     * Factory method to create a Service
     *
     * @param port the port number being used
     * @param protocol the protocol being used (optional)
     *
     * @return a Service object
     */
    public Service createService( Integer port, String protocol ){
        return new Service( null, 
                            port, 
                            null, 
                            protocol, 
                            null ); // ident not necessary
    }
    
     /**
     * Factory method to create a Service
     *
     * @param name the name of the service
     * @param port the port number being used
     * @param protocol the protocol being used (optional)
     *
     * @return a Service object
     */
    public Service createService( String name, Integer port, String protocol ){
        return new Service( name, 
                            port, 
                            null, 
                            protocol, 
                            null ); // ident not necessary
    }
    
   /**
    * Factory method to create a Service with port list
    *
    * @param portList - Port lists consist of a comma-separated list of numbers 
    *                    (individual integers) and ranges (N-M means ports N through 
    *                    M, inclusive).  Any combination of numbers and ranges may be
    *                    used in a single list.  For example, 
    *                    "5-25,37,42,43,53,69-119,123-514".
    * @param protocol - The protocol being used (optional)
    */
    public Service createServiceWithPortList( String portList, String protocol ){
        return new Service( null, 
                            null, 
                            portList, 
                            protocol, 
                            null ); // ident not necessary
    }
    
     /**
     * Factory method to create a FileList
     *
     * @param files information about an individual file, as indicated
     *               by the files' "category" and "fstype" attributes 
     *
     * @return a FileList object
     */
    public FileList createFileList( IDMEF_File []files ){
        return new FileList( files );
    }
    
     /**
     * Factory method to create a Target 
     *
     * @param node information about the host or device at which the
     *             event(s) (network address, network name, etc.) is
     *             being directed
     * @param decoy an indication of whether the target is, as far as the
     *             analyzer can determine, a decoy.  The permitted values
     *             for this attribute are shown below.  The default value
     *             is "unknown".
     *
     * Rank   Keyword           Description
     * ----   -------           -----------
     *   0    Target.UNKNOWN    Accuracy of target information unknown
     *   1    Target.YES        Target is believed to be a decoy
     *   2    Target.NO         Target is believed to be "real"
     *
     * @return a Target object
     */
    public Target createTarget( IDMEF_Node node, String decoy ){
        return new Target( node, 
                           null, 
                           null, 
                           null,
                           null,
                           createUniqueId(), 
                           decoy, 
                           null );
    }

     /**
     * Factory method to create a Target 
     *
     * @param user information about the user at which the event(s) is
     *             being directed
     * @param decoy an indication of whether the target is, as far as the
     *             analyzer can determine, a decoy.  The permitted values
     *             for this attribute are shown below.  The default value
     *             is "unknown".
     *
     * Rank   Keyword           Description
     * ----   -------           -----------
     *   0    Target.UNKNOWN    Accuracy of target information unknown
     *   1    Target.YES        Target is believed to be a decoy
     *   2    Target.NO         Target is believed to be "real"
     *
     * @return a Target object
     */
    public Target createTarget( User user, String decoy ){
        return new Target( null, 
                           user, 
                           null, 
                           null,
                           null, 
                           createUniqueId(), 
                           decoy, 
                           null );
    }
    
   /**
     * Factory method to create a Target 
     *
     * @param process information about the process at which the event(s) is
     *                being directed
     * @param decoy an indication of whether the target is, as far as the
     *             analyzer can determine, a decoy.  The permitted values
     *             for this attribute are shown below.  The default value
     *             is "unknown".
     *
     * Rank   Keyword           Description
     * ----   -------           -----------
     *   0    Target.UNKNOWN    Accuracy of target information unknown
     *   1    Target.YES        Target is believed to be a decoy
     *   2    Target.NO         Target is believed to be "real"
     *
     * @return a Target object
     */
    public Target createTarget( IDMEF_Process process, String decoy ){
        return new Target( null, 
                           null, 
                           process, 
                           null,
                           null, 
                           createUniqueId(), 
                           decoy, 
                           null );
    }
    
    /**
     * Factory method to create a Target 
     *
     * @param service information about the service at which the event(s) is
     *                being directed
     * @param decoy an indication of whether the target is, as far as the
     *             analyzer can determine, a decoy.  The permitted values
     *             for this attribute are shown below.  The default value
     *             is "unknown".
     *
     * Rank   Keyword           Description
     * ----   -------           -----------
     *   0    Target.UNKNOWN    Accuracy of target information unknown
     *   1    Target.YES        Target is believed to be a decoy
     *   2    Target.NO         Target is believed to be "real"
     *
     * @return a Target object
     */
    public Target createTarget( Service service, String decoy ){
        return new Target( null, 
                           null, 
                           null, 
                           service,
                           null, 
                           createUniqueId(), 
                           decoy, 
                           null );
    }
    
  /**
     * Factory method to create a Target 
     *
     * @param fileList information about file(s) involved in the event(s)
     * @param decoy an indication of whether the target is, as far as the
     *             analyzer can determine, a decoy.  The permitted values
     *             for this attribute are shown below.  The default value
     *             is "unknown".
     *
     * Rank   Keyword           Description
     * ----   -------           -----------
     *   0    Target.UNKNOWN    Accuracy of target information unknown
     *   1    Target.YES        Target is believed to be a decoy
     *   2    Target.NO         Target is believed to be "real"
     *
     * @return a Target object
     */
    public Target createTarget( FileList fileList, String decoy ){
        return new Target( null, 
                           null, 
                           null, 
                           null,
                           fileList, 
                           createUniqueId(), 
                           decoy, 
                           null );
        
    }
    
    /**
     * Factory method to create a Classification
     *
     * @param name the name of the alert
     * @param url a URL at which the manager (or the human
     *            operator of the manager) can find additional information about the
     *            alert.  The document pointed to by the URL may include an in-depth
     *            description of the attack, appropriate countermeasures, or other
     *            information deemed relevant by the vendor.
     * @param type The source from which the name of the alert originates.
     *             The permitted values for this attribute are shown below.  The
     *             default value is "unknown". (Required)
     *
     * Rank   Keyword                           Description
     * ----   -------                           -----------
     *   0    Classification.UNKNOWN            Origin of the name is not known
     *   1    Classification.BUGTRAQID          The SecurityFocus.com ("Bugtraq")
     *                                          vulnerability database identifier
     *                                          (http://www.securityfocus.com/vdb)
     *   2    Classification.CVE                The Common Vulnerabilities and Exposures
     *                                          (CVE) name (http://www.cve.mitre.org/)
     *   3    Classification.VENDOR_SPECIFIC    A vendor-specific name (and hence, URL);
     *                                          this can be used to provide product-
     *                                          specific information
     *
     * @return a Classification object
     */
    public Classification createClassification( String name, 
                                                String url, 
                                                String type ){
         return new Classification( name, 
                                    url, 
                                    type );
    }
    
    /**
     * Factory method to create a vendor-specific Classification
     *
     * @param name The name of the alert.
     * @param url A URL at which the manager (or the human
     *            operator of the manager) can find additional information about the
     *            alert.  The document pointed to by the URL may include an in-depth
     *            description of the attack, appropriate countermeasures, or other
     *            information deemed relevant by the vendor.
     *
     * @return a Classification object
     */
    public Classification createClassification( String name, String url ){
        return createClassification( name, 
                                     url, 
                                     Classification.VENDOR_SPECIFIC );     
    }

   /**
     * Factory method to create an Assessment
     *
     * @param impact The analyzer's assessment of the impact of the event
     *               on the target(s).
     * @param actions The action(s) taken by the analyzer in response to
     *                the event.
     * @param confidence A measurement of the confidence the analyzer has
     *                   in its evaluation of the event.
     *
     * @return an Assessment object
     */
    public Assessment createAssessment( Impact impact, Action []actions, Confidence confidence ){
        return new Assessment( impact, actions, confidence );
    }
 
    /**
     * Factory method to create an AdditionalData
     *
     * @param type The type of data included in the element content.
     *             The permitted values for this attribute are shown 
     *             below.  The default value is "string".
     *
     * Rank   Keyword                   Description
     * ----   -------                   -----------
     *   0    AdditionalData.BOOLEAN    The element contains a boolean value,
     *                                  i.e., the strings "true" or "false"
     *   1    AdditionalData.BYTE       The element content is a single 8-bit
     *                                  byte
     *   2    AdditionalData.CHARACTER  The element content is a single
     *                                  character
     *   3    AdditionalData.DATE_TIME  The element content is a date-time
     *   4    AdditionalData.INTEGER    The element content is an integer
     *   5    AdditionalData.NTPSTAMP   The element content is an NTP timestamp
     *   6    AdditionalData.PORTLIST   The element content is a list of ports
     *   7    AdditionalData.REAL       The element content is a real number
     *   8    AdditionalData.STRING     The element content is a string
     *   9    AdditionalData.XML        The element content is XML-tagged data
     * @param meaning A string describing the meaning of the element content.
     *                These values will be vendor/implementation dependent; 
     *                the method for ensuring that managers understand the
     *                strings sent by analyzer is outside the scope of this
     *                specification. (Optional)
     * @param data atomic data (integers, strings, etc.) in cases where only
     *             small amounts of additional information need to be sent;
     *             it can also be used to transmission of complex data (such as
     *             packet headers).
     *
     * @return an AdditionalData object
     */
    public AdditionalData createAdditionalData( String type, 
                                                String meaning, 
                                                String data ){
        return new AdditionalData( type, 
                                   meaning, 
                                   data );
    }
    
    /**
     * Factory method to create an AdditionalData
     *
     * @param xmlData xml serializable data representing a complex object
     * @param meaning A string describing the meaning of the element content.
     *                These values will be vendor/implementation dependent; 
     *                the method for ensuring that managers understand the
     *                strings sent by analyzer is outside the scope of this
     *                specification. (Optional)
     *
     * @return an AdditionalData object
     */
    public AdditionalData createAdditionalData( XMLSerializable xmlData, String meaning ){
        return new AdditionalData( xmlData, meaning );
    }
    
    /**
     * Factory method to create an IDMEF File
     * 
     * @param file the file associated with this alert
     * @param fileAccesses the file access permissions
     * @param linkages other files that this file references
     * @param inode additional information contained in a Unix file system i-node
     * @param category the context for the information being provided
     * @param fstype the file system type
     *
     * @return an IDMEF_File object
     */
    public IDMEF_File createFile( File file, 
                                  FileAccess []fileAccesses,
                                  Linkage []linkages, 
                                  Inode inode, 
                                  String category,
                                  String fstype ){
        return new IDMEF_File( file.getName(), 
                               file.getPath(), 
                               null, // createTime
                               new Date( file.lastModified() ), 
                               null, // accessTime
                               null, // data size 
                               null, // disk size
                               fileAccesses, 
                               linkages, 
                               inode, 
                               category,
                               fstype, 
                               null ); // ident not necessary
    }

    /**
     * Factory method to create a FileAccess
     *
     * @param userId The user (or group) to which these permissions apply.
     *               The value of the "type" attribute must be "user-privs",
     *               "group-privs", or "other-privs" as appropriate.  Other
     *               values for "type" MUST NOT be used in this context.
     * @param permissions Level of access allowed.  Recommended values are
     *                    "noAccess", "read", "write", "execute", "delete",
     *                    "executeAs", "changePermissions", and "takeOwnership".
     *                    The "changePermissions" and "takeOwnership" strings
     *                    represent those concepts in Windows.  On Unix, the
     *                    owner of the file always has "changePermissions"
     *                    access, even if no other access is allowed for
     *                    that user.  "Full Control" in Windows is represented
     *                    by enumerating the permissions it contains.  The
     *                    "executeAs" string represents the set-user-id and
     *                    set-group-id features in Unix.
     *
     * @return a FileAccess object
     */    
    public FileAccess createFileAccesses( String userId, String []permissions ){
        return new FileAccess( createUserId( userId ), permissions );
    }
    
    /**
     * Factory method to create a Linkage
     *
     * @param file the file that is linked to another file 
     * @param category The type of object that the link describes.  The 
     *                 permitted values are shown below.  There is no
     *                 default value.
     *
     * Rank   Keyword               Description
     * ----   -------               -----------
     *   0    Linkage.HARD_LINK     The <name> element represents another
     *                              name for this file.  This information
     *                              may be more easily obtainable on NTFS
     *                              file systems than others.
     *   1    Linkage.MOUNT_POINT   An alias for the directory specified by
     *                              the parent's <name> and <path> elements.
     *   2    Linkage.REPARSE_POINT Applies only to Windows; excludes
     *                              symbolic links and mount points, which
     *                              are specific types of reparse points.
     *   3    Linkage.SHORTCUT      The file represented by a Windows
     *                              "shortcut."  A shortcut is distinguished
     *                              from a symbolic link because of the
     *                              difference in their contents, which may
     *                              be of importance to the manager.
     *   4    Linkage.STREAM        An Alternate Data Stream (ADS) in
     *                              Windows; a fork on MacOS.  Separate file
     *                              system entity that is considered an
     *                              extension of the main <File>.
     *   5    Linkage.SYMBOLIC_LINK The <name> element represents the file
     *                              to which the link points.
     * @return a Linkage object
     */  
    public Linkage createLinkage( File file, String category ){
        return new Linkage( file.getName(), file.getPath(), category );
    }
    
     /**
     * Factory method to create a Linkage
     *
     * @param file an IDMEF_File that is linked to another file 
     * @param category The type of object that the link describes.  The 
     *                 permitted values are shown below.  There is no
     *                 default value.
     *
     * Rank   Keyword               Description
     * ----   -------               -----------
     *   0    Linkage.HARD_LINK     The <name> element represents another
     *                              name for this file.  This information
     *                              may be more easily obtainable on NTFS
     *                              file systems than others.
     *   1    Linkage.MOUNT_POINT   An alias for the directory specified by
     *                              the parent's <name> and <path> elements.
     *   2    Linkage.REPARSE_POINT Applies only to Windows; excludes
     *                              symbolic links and mount points, which
     *                              are specific types of reparse points.
     *   3    Linkage.SHORTCUT      The file represented by a Windows
     *                              "shortcut."  A shortcut is distinguished
     *                              from a symbolic link because of the
     *                              difference in their contents, which may
     *                              be of importance to the manager.
     *   4    Linkage.STREAM        An Alternate Data Stream (ADS) in
     *                              Windows; a fork on MacOS.  Separate file
     *                              system entity that is considered an
     *                              extension of the main <File>.
     *   5    Linkage.SYMBOLIC_LINK The <name> element represents the file
     *                              to which the link points.
     * @return a Linkage object
     */  
    public Linkage createLinkage( IDMEF_File file, String category ){
        return new Linkage( file, category );    
    }
    
    /**
     * Factory method to create an Inode (relevant to UNIX systems ONLY)
     *
     * @param changeTime The time of the last inode change.
     * @param number The inode number.
     * @param majorDevice The major device number of the device the
     *                    file resides on.
     * @param minorDevice The minor device number of the device the
     *                    file resides on.
     *
     * @return an Inode object
     */  
    public Inode createInode( Date changeTime, Integer number, 
                              Integer majorDevice, Integer minorDevice ){
        return new Inode( changeTime, number, majorDevice, minorDevice );
    }
    
    /**
     * Factory method to create an Inode (relevant to UNIX systems ONLY)
     *
     * @param changeTime The time of the last inode change.
     * @param cMajorDevice The major device of the file itself, if it
     *                     is a character special device.
     * @param cMinorDevice The minor device of the file itself, if it
     *                     is a character special device.
     *
     * @return an Inode object
     */  
    public Inode createInode( Date changeTime, Integer cMajorDevice, 
                              Integer cMinorDevice ){
        return new Inode( changeTime, cMajorDevice, cMinorDevice );
    }
    
    /**
     * Factory method to create a UserId
     *
     * @param aUser A user or group name.
     *
     * @return a UserId object
     */  
    public UserId createUserId( String aUser ){
        // user name and user identifier is the same in cougaar
        return new UserId( aUser, null, aUser, null );
    }   
    
    /**
     * Factory method to create an Address
     *
     * @param address The address information.  The format of
     *                this data is governed by the category attribute.
     * @param netMask The network mask for the address, if
     *                appropriate.
     * @param category The type of address represented.  The permitted values
     *                 for this attribute are shown below.  The default value
     *                 is "unknown".
     *
     * Rank   Keyword               Description
     * ----   -------               -----------
     *   0    Address.UNKNOWN       Address type unknown
     *   1    Address.ATM           Asynchronous Transfer Mode network
     *                              address
     *   2    Address.EMAIL         Electronic mail address (RFC 822)
     *   3    Address.LOTUS_NOTES   Lotus Notes e-mail address
     *   4    Address.MAC           Media Access Control (MAC) address
     *   5    Address.SNA           IBM Shared Network Architecture (SNA)
     *                              address
     *   6    Address.VM            IBM VM ("PROFS") e-mail address
     *   7    Address.IPV4_ADDR     IPv4 host address in dotted-decimal
     *                              notation (a.b.c.d)
     *   8    Address.IPV4_ADDR_HEX IPv4 host address in hexadecimal
     *                              notation
     *   9    Address.IPV4_NET      IPv4 network address in dotted-decimal
     *                              notation, slash, significant bits
     *                              (a.b.c.d/nn)
     *  10    Address.IPV4_NET_MASK IPv4 network address in dotted-decimal
     *                              notation, slash, network mask in dotted-
     *                              decimal notation (a.b.c.d/w.x.y.z)
     *  11    Address.IPV6_ADDR     IPv6 host address
     *  12    Address.IPV6_ADDR_HEX IPv6 host address in hexadecimal
     *                              notation
     *  13    Address.IPV6_NET      IPv6 network address, slash, significant
     *                              bits
     *  14    Address.IPV6_NET_MASK IPv6 network address, slash, network
     *                              mask
     *  99    Address.URL_ADDR      A url
     *
     * @return a Address object
     */  
    public Address createAddress( String address, 
                                  String netMask, 
                                  String category ){    
        return new Address( address, 
                            netMask, 
                            null, // unique id not necessary
                            category, 
                            null, // vlan-name not necessary 
                            null );  // vlan-num not necessary
    }
    
    /**
     * Factory method to create an Impact
     *
     * All three attributes are optional.  The element itself may be empty,
     * or may contain a textual description of the impact, if the analyzer
     * is able to provide additional details.
 
     * @param severity An estimate of the relative severity of the event.  
     *                 The permitted values are shown below.  There is no
     *                 default value.
     *
     * Rank   Keyword            Description
     * ----   -------            -----------
     *   0    Impact.LOW         Low severity
     *   1    Impact.MEDIUM      Medium severity
     *   2    Impact.HIGH        High severity
     *
     * @param completion An indication of whether the analyzer believes the
     *                   attempt that the event describes was successful or not.
     *                   The permitted values are shown below.  There is no
     *                   default value.
     *
     * Rank   Keyword            Description
     * ----   -------            -----------
     *   0    Impact.FAILED      The attempt was not successful
     *   1    Impact.SUCCEEDED   The attempt succeeded
     *
     * @param type The type of attempt represented by this event, in relatively broad
     * categories.  The permitted values are shown below.  The default
     * value is "other."
     *
     * Rank   Keyword            Description
     * ----   -------            -----------
     *   0    Impact.ADMIN       Administrative privileges were
     *                           attempted or obtained
     *   1    Impact.DOS         A denial of service was attempted or
     *                           completed
     *   2    Impact.FILE        An action on a file was attempted or
     *                           completed
     *   3    Impact.RECON       A reconnaissance probe was attempted
     *                           or completed
     *   4    Impact.USER        User privileges were attempted or
     *                           obtained
     *   5    Impact.OTHER       Anything not in one of the above
     *                           categories
     *
     * @param description a description of the impact.
     *
     * @return a Impact object
     */   
    public Impact createImpact( String severity, 
                                String completion, 
                                String type,
                                String description ){
        return new Impact( severity, completion, type, description );
    }
    
    /**
     * Factory method to create an Action
     *
     * @param category The type of action taken.  The permitted values are
     *                 shown below.  The default value is "other."
     *
     * Rank   Keyword                   Description
     * ----   -------                   -----------
     *   0    Action.BLOCK_INSTALLED    A block of some sort was installed to
     *                                  prevent an attack from reaching its
     *                                  destination.  The block could be a port
     *                                  block, address block, etc., or disabling
     *                                  a user account.
     *   1    Action.NOTIFICATION_SENT  A notification message of some sort was
     *                                  sent out-of-band (via pager, e-mail,
     *                                  etc.).  Does not include the
     *                                  transmission of this alert.
     *   2    Action.TAKEN_OFFLINE      A system, computer, or user was taken
     *                                  offline, as when the computer is shut
     *                                  down or a user is logged off.
     *   3    Action.OTHER              Anything not in one of the above
     *                                  categories.
     * @param description a description of the action
     *
     * @return a Action object
     */  
    public Action createAction( String category, String description ){
        return new Action( category, description );
    }
    
    /**
     * Factory method to create a Confidence
     *
     * @param rating The analyzer's rating of its analytical validity.
     *               Permitted values:
     *                  Confidence.LOW, Confidence.MEDIUM, 
     *                  Confidence.HIGH, Confidence.NUMERIC
     * @param numeric if the rating is Confidence.NUMERIC, set numeric to 
     *                a Float object between 0.0 and 1.0., null otherwise.
     *
     * @return a Confidence object
     */  
    public Confidence createConfidence( String rating, Float numeric ){
        return new Confidence( rating, numeric );
    }
    
    /**
     * Factory method to create a unique id
     *
     * @return a unique String id
     */      
    private String createUniqueId(){
        // delegate to some global unique id generator
        return null;   
    }
    
    private IdmefMessageFactory(){ 
    }
    
    /**
     * This is a dummy Sensor implementation class for compilation purposes.
     * The concrete Sensor class MUST implement getters for obtaining
     * sensor name/id, sources and targets known to the sensor,
     * and sensor capabilities.  All concrete sensors should extend
     * from the Sensor interface.
     *
     * NOTE: this class should be removed
     */
    private class SensorImpl implements Sensor {
        
        public String getName(){
            return "<sensor-name>";
        }
        public String getManufacturer(){
            return "<manufacturer>";
        }
        public String getModel(){
            return "<model>";
        }
        public String getVersion(){
            return "<version>";
        }
        public String getAnalyzerClass(){
            return "<class>";
        }
        public String getOSType(){
            return OS_TYPE;
        }
        public String getOSVersion(){
            return OS_VERSION;
        }
        public IDMEF_Node getNode(){
            return m_node;
        }
        public IDMEF_Process getProcess(){
            return m_process;
        }
        
        private IDMEF_Node m_node;
        private IDMEF_Process m_process;
    }
    
    // Need for Analyzer information as per IDMEF v1.0 draft
    private static String OS_TYPE;
    private static String OS_VERSION;
    private static IdmefMessageFactory m_idmefMessageFactory;
    private static Object factoryLock = new Object();
    static {
        OS_TYPE = System.getProperty( "os.name" );
        OS_VERSION = System.getProperty( "os.version" ); 
    }
}
