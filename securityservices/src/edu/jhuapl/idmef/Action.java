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

package edu.jhuapl.idmef;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;

/**
 * <pre>
 * The Action class is used to describe any actions taken by the
 * analyzer in response to the event.  Is is represented in the XML DTD
 * as follows:
 * 
 *    &lt!ENTITY % attvals.actioncat            "
 *        ( block-installed | notification-sent | taken-offline |
 *          other )
 *    "&gt
 *    &lt!ELEMENT Action     (#PCDATA | EMPTY)* &gt
 *    &lt!ATTLIST Action
 *        category            %attvals.actioncat;     'other'
 *    &gt
 * 
 * Action has one attribute:
 * 
 * category
 *  The type of action taken.  The permitted values are shown below.
 *  The default value is "other."
 *
 *    Rank   Keyword            Description
 *    ----   -------            -----------
 *     0    BLOCK_INSTALLED    A block of some sort was installed to
 *                             prevent an attack from reaching its
 *                             destination.  The block could be a port
 *                             block, address block, etc., or disabling
 *                             a user account.
 *     1    NOTIFICATION_SENT  A notification message of some sort was
 *                             sent out-of-band (via pager, e-mail,
 *                             etc.).  Does not include the
 *                             transmission of this alert.
 *     2    TAKEN_OFFLINE      A system, computer, or user was taken
 *                             offline, as when the computer is shut
 *          OTHER              Anything not in one of the above
 *                             categories.
 *
 * The element itself may be empty, or may contain a textual description
 * of the action, if the analyzer is able to provide additional details.
 * </pre> 
 * @since IDMEF Message v1.0
 */
public class Action implements XMLSerializable {
    
    // xml element and attribute names
    public static String ELEMENT_NAME = "Action";
    public static String ATTRIBUTE_CATEGORY = "category";
    
    // action categories
    public static String BLOCK_INSTALLED = "block-installed";
    public static String NOTIFICATION_SENT = "notification-sent";
    public static String TAKEN_OFFLINE = "taken-offline";
    public static String OTHER = "other";
    
    
    public Action(){
        this( null, null );
    }
    
    public Action( String category, String description ){
        if( category != null ){
            m_category = category;
        }
        m_description = description;    
    }
    
    public Action( Node node ){
        NamedNodeMap attributes = node.getAttributes();
        
        Node attribute = attributes.getNamedItem( ATTRIBUTE_CATEGORY );
        if( attribute != null ){
            m_category = attribute.getNodeValue();
        }
        m_description = XMLUtils.getAssociatedString( node );
    }
    
    public String getCategory(){
        return m_category;
    }
    public void setCategory( String category ){
        m_category = category;   
    }
    
    public String getDescription(){
        return m_description;
    }
    public void setDescription( String description ){
        m_description = description;
    }
    
    public Node convertToXML( Document parent ){
        Element actionNode = parent.createElement( ELEMENT_NAME );  
        if( m_category != null ){
            actionNode.setAttribute( ATTRIBUTE_CATEGORY, m_category );
        }
        if( m_description != null ){
            actionNode.appendChild( parent.createTextNode( m_description ) );
        }
        return actionNode;
    }
    
    // default to other
    private String m_category = "other";
    private String m_description;
}
