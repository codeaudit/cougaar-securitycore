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
package org.cougaar.core.security.monitoring.idmef;

import java.util.ArrayList;

import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.XMLSerializable;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.NamedNodeMap;

/**
 *
 * Agent class represents a Cougaar Agent.  Agent information is specified in
 * AdditionalData that references a Source or Target of an event.
 *
 *            +---------------------+
 *            |        Agent        |
 *            +---------------------+
 *            | STRING name         |
 *            |                     | 0..1       +---------------+
 *            |                     |<>----------|  description  |
 *            |                     |            +---------------+
 *            |                     | 0..1       +-----------+
 *            |                     |<>----------|  location |
 *            |                     |            +-----------+
 *            |                     | 0..1       +-----------+
 *            |                     |<>----------|  Address  |
 *            |                     |            +-----------+
 *            |                     | 1..n       +-------------+
 *            |                     |<>----------|  ref-ident  |
 *            |                     |            +-------------+
 *            +---------------------+ 
 *
 *
 *  <!ELEMENT Cougaar:Agent (
 *   Cougaar:description?, 
 *   Cougaar:location?,
 *   Address?, 
 *   Cougaar:ref-ident+ ) >
 *
 *  <!ATTLIST Cougaar:Agent
 *      xmlns                   CDATA                #FIXED
 *          'idmef+cougaar'
 *      xmlns:Cougaar           CDATA                #FIXED
 *          'idmef+cougaar'
 *      Cougaar:name            CDATA                #REQUIRED >
 *
 *  <!ELEMENT Cougaar:description   (#PCDATA) >
 *  <!ELEMENT Cougaar:location      (#PCDATA) >
 *  <!ELEMENT Cougaar:ref-ident     (#PCDATA) >
 *
 */
public class Agent implements XMLSerializable {
    
    public static String COUGAAR_NAMESPACE = "idmef+cougaar";
    public static String COUGAAR_NAMESPACE_PREFIX = "Cougaar:";
    public static String ELEMENT_NAME = COUGAAR_NAMESPACE_PREFIX + "Agent";
    public static String NAME_ATTRIBUTE = COUGAAR_NAMESPACE_PREFIX + "name";
    public static String DESCRIPTION_ELEMENT = COUGAAR_NAMESPACE_PREFIX + "desciption";
    public static String LOCATION_ELEMENT = COUGAAR_NAMESPACE_PREFIX + "location";
    public static String REF_IDENT_ELEMENT = COUGAAR_NAMESPACE_PREFIX + "ref-ident";
    
    public Agent()
    {
        this( null, null, null, null, null );
    }
  
    public Agent( String name, String description, 
                  String location, Address address, 
                  String []refIdents ){
        m_name = name;
        m_description = description;
        m_location = location;
        m_address = address;
        m_refIdents = refIdents;
    }

    public Agent( Node agentNode ){
        // set the private member variables accordingly
      
        NodeList children = agentNode.getChildNodes();
    	ArrayList refIdents = new ArrayList();
        int len = children.getLength();
    	for( int i = 0; i < len; i++ ){
    	    Node child = children.item(i);
    	    String nodeName = child.getNodeName();
    	    if( ( m_description == null ) && 
    	        nodeName.equals( DESCRIPTION_ELEMENT ) ){
        		m_description = child.getNodeValue();
	        }
	        else if( ( m_location == null ) && 
    	        nodeName.equals( LOCATION_ELEMENT ) ){
        		m_location = child.getNodeValue();
	        }
	        else if( nodeName.equals( Address.ELEMENT_NAME ) ){
	            m_address = new Address( child );
	        }
	        else if( nodeName.equals( REF_IDENT_ELEMENT ) ){
                refIdents.add( child.getNodeValue() );
    	    }
	    }

        // TODO: this is slow, change
        m_refIdents = ( String [] ) refIdents.toArray();
        
    	NamedNodeMap nnm = agentNode.getAttributes();

    	Node nameNode = nnm.getNamedItem( NAME_ATTRIBUTE );
    	if( nameNode != null) {
    	    m_name = nameNode.getNodeValue();
        }
    }
    
    public String getDescription(){
        return m_description;
    }
    public void setDescription( String description ){
        m_description = description;
    }
    
    public String getLocation(){
        return m_location;
    }
    public void setLocation( String location ){
        m_location = location;
    }
    
    public Address getAddress(){
        return m_address;
    }
    public void setAddress( Address address ){
        m_address = address;
    }

    public String[] getReferenceIdents()
    {
        return m_refIdents;
    }
    public void setReferenceIdents( String []refIdents )
    {
        m_refIdents = refIdents;
    }
    
    /**
     *
     *   Example Agent node:
     *
     *   <Cougaar:Agent Cougaar:name="ViewRecordAgent">
     *      <Cougaar:description>Agent used to view confidential records</Cougaar:description>
     *      <Cougaar:location>Santa Clara, CA</Cougaar:location>
     *      <Address category="url">
     *          <address>rmi://myhost.com:2121/ViewRecordAgent</address>
     *      </Address>
     *      <Cougaar:ref-ident>a1b2c3d4</Cougaar:ref-ident>
     *   </Cougaar:Agent>
     *
     */
    public Node convertToXML( Document parent )
    {
        
        Element agentNode = parent.createElement( ELEMENT_NAME );
        
        if( m_name != null ){
            agentNode.setAttribute( NAME_ATTRIBUTE, m_name );
	    }
	    if( m_description != null ) {
            Node descriptionElm = parent.createElement( DESCRIPTION_ELEMENT );
	        descriptionElm.appendChild( parent.createTextNode( m_description ) );
	        agentNode.appendChild( descriptionElm );
	    }
	    if( m_location != null ) {
	        Node locationElm = parent.createElement( LOCATION_ELEMENT );
	        locationElm.appendChild( parent.createTextNode( m_location ) );
	        agentNode.appendChild( locationElm );
	    }
	    if( m_address != null ) {
	        agentNode.appendChild( m_address.convertToXML( parent ) );    
	    }
        if( m_refIdents != null && m_refIdents.length > 0 ) {
	        int len = m_refIdents.length;
	        for( int i = 0; i < len; i++ ) {
	            Node refIdentNode = parent.createElement( REF_IDENT_ELEMENT );
	            refIdentNode.appendChild( parent.createTextNode( m_refIdents[ i ] ) );
	            agentNode.appendChild( refIdentNode );
	        }
	    }
	    /*
	    TODO: determine if this is necessary!
	    
	    Element agentNode = parent.createElementNS( COUGAAR_NAMESPACE, ELEMENT_NAME );
        
        if( m_name != null ){
            Attr nameAttr = parent.createAttributeNS( COUGAAR_NAMESPACE, NAME_ATTRIBUTE );
	        nameAttr.setValue( m_name );
	        agentNode.setAttributeNodeNS( nameAttr );
	    }
	    if( m_description != null ) {
            Node descriptionElm = parent.createElementNS( COUGAAR_NAMESPACE, DESCRIPTION_ELEMENT );
	        descriptionElm.appendChild( parent.createTextNode( m_description ) );
	        agentNode.appendChild( descriptionElm );
	    }
	    if( m_location != null ) {
	        Node locationElm = parent.createElementNS( COUGAAR_NAMESPACE, LOCATION_ELEMENT );
	        locationElm.appendChild( parent.createTextNode( m_location ) );
	        agentNode.appendChild( locationElm );
	    }
	    if( m_address != null ) {
	        agentNode.appendChild( m_address.convertToXML( parent ) );    
	    }
        if( m_refIdents != null && m_refIdents.length > 0 ) {
	        int len = m_refIdents.length;
	        for( int i = 0; i < len; i++ ) {
	            Node refIdentNode = parent.createElementNS( COUGAAR_NAMESPACE, REF_IDENT_ELEMENT );
	            refIdentNode.appendChild( parent.createTextNode( m_refIdents[ i ] ) );
	            agentNode.appendChild( refIdentNode );
	        }
	    }
	    */
	    return agentNode;
    }
   
    private String m_name;
    private String m_description;
    private String m_location;
    private Address m_address;
    private String m_refIdents[];
}
