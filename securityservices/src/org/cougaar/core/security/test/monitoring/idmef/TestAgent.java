/*
 * <copyright>
 *  Copyright 1997-2002 Network Associates
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
package org.cougaar.core.security.test.monitoring.idmef;

import org.cougaar.core.security.monitoring.idmef.Agent;

import java.net.InetAddress;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.XMLUtils;

public class TestAgent extends TestIdmef {
    
    public TestAgent(){
        this( null );
    }
    public TestAgent( String name ){
        super( name );
    }
    public static void main( String []args ){
        TestIdmef test = new TestAgent( "TestAgent" );
        test.run();
    }
    public void init(){
     // m_addressTester = new TestAddress();
    }
    public Agent createAgent(){
        String refIdents[] = { "00000001", "00000002" };
        Address address = null;
        try {
            address = m_msgFactory.createAddress( InetAddress.getLocalHost().getHostAddress(), 
                                                  null, Address.IPV4_ADDR );
        }
        catch( Exception e ){
            e.printStackTrace();
        }
        
        return m_msgFactory.createAgent( "test-agent",
                                         "a test agent",
                                         "SF, CA",
                                         address,
                                         refIdents );
        
    }
  
    public void compare( Agent agent1, Agent agent2 ){
      String refIdents1[] = agent1.getReferenceIdents();
      String refIdents2[] = agent2.getReferenceIdents();
      Address address1 = agent1.getAddress();
      Address address2 = agent2.getAddress();
        if( !( agent1.getName().equals( agent2.getName() ) ) ){
            System.out.println( "Agent name is inconsistent!" );
            System.out.println( "Agent1.name = " + agent1.getName() );
            System.out.println( "Agent2.name = " + agent2.getName() );
        }
        if( !( agent1.getDescription().equals( agent2.getDescription() ) ) ){
            System.out.println( "Agent description is inconsistent!" );
            System.out.println( "Agent1.description = " + agent1.getDescription() );
            System.out.println( "Agent2.description = " + agent2.getDescription() );
        }
        if( !( agent1.getLocation().equals( agent2.getLocation() ) ) ){
            System.out.println( "Agent location is inconsistent!" );
            System.out.println( "Agent1.location = " + agent1.getLocation() );
            System.out.println( "Agent2.location = " + agent2.getLocation() );
        }
        // m_addressTester.compare( address1, address2 );
        if( !( address1.getAddress().equals( address2.getAddress() ) ) ){
            System.out.println( "Agent address is inconsistent!" );
            System.out.println( "Agent1.address = " + address1.getAddress() );
            System.out.println( "Agent2.address = " + address2.getAddress() );
        }
        if( !( address1.getCategory().equals( address2.getCategory() ) ) ){
            System.out.println( "Agent address category is inconsistent!" );
            System.out.println( "Agent1.address.category = " + address1.getCategory() );
            System.out.println( "Agent2.address.category = " + address2.getCategory() );
        }
        if( refIdents1.length == refIdents2.length ){
            int len = refIdents1.length;
            for( int i = 0; i < len; i++ ){
                if( !( refIdents1[ i ].equals( refIdents2[ i ] ) ) ){
                  System.out.println(" Agent.refIdents[ " + i + " ] is inconsistent!" );
                  System.out.println(" Agent.refIdents1[ " + i + " ] = " + refIdents1[ i ] );
                  System.out.println(" Agent.refIdents2[ " + i + " ] = " + refIdents2[ i ] );
                }
            }
        }
        else{
            System.out.println(" Agent.refIdents lengths NOT EQUAL!" );
            System.out.println(" Agent.refIdents1.length = " + refIdents1.length );
            System.out.println(" Agent.refIdents2.length = " + refIdents2.length );
        }
    }
    public void run(){
        Agent agent1 = createAgent();
        Document document = m_docBuilder.newDocument();
        Node agentNode = agent1.convertToXML( document );
        
        Agent agent2 = new Agent( agentNode );
        compare( agent1, agent2 );
        
        document.appendChild( agentNode );
        XMLUtils.printDocument( document );
    }
  //private TestAddress m_addressTester;
}
