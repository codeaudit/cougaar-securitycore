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

import java.util.ArrayList;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


/**
 *  The Assessment class is used to provide the analyzer's assessment of
 *  an event -- its impact, actions taken in response, and confidence.
 *
 *  The Assessment class is composed of three aggregate classes, as shown
 *  in Figure below.
 *
 *              +------------------+
 *              |   Assessment     |
 *              +------------------+       0..1 +------------+
 *              |                  |<>----------|   Impact   |
 *              |                  |            +------------+
 *              |                  |       0..* +------------+
 *              |                  |<>----------|   Action   |
 *              |                  |            +------------+
 *              |                  |       0..1 +------------+
 *              |                  |<>----------| Confidence |
 *              |                  |            +------------+
 *              +------------------+
 *
 *  The aggregate classes that make up Assessment are:
 *
 *  Impact
 *      Zero or one.  The analyzer's assessment of the impact of the event
 *      on the target(s).
 *
 *  Action
 *      Zero or more.  The action(s) taken by the analyzer in response to
 *      the event.
 *
 *  Confidence
 *      A measurement of the confidence the analyzer has in its evaluation
 *      of the event.
 *
 * @since IDMEF Message v1.0
 */
public class Assessment implements XMLSerializable {
    
    public static String ELEMENT_NAME = "Assessment";
    
    public Assessment( Impact impact, Action []actions, Confidence confidence ){
        m_impact = impact;
        m_actions = actions;
        m_confidence = confidence;
    }
    
    public Assessment( Node node ){
	    NodeList childList = node.getChildNodes();
	    ArrayList actionList = new ArrayList();
	    int len = childList.getLength();
    	
    	for ( int i = 0; i < len; i++ ){
    	    Node childNode = childList.item( i );
    	    String nodeName = childNode.getNodeName();
    	    if( m_impact == null && nodeName.equals( Impact.ELEMENT_NAME ) ){
         		// there should be one impact element
         		m_impact = new Impact( childNode );
	        }
	        else if( nodeName.equals( Action.ELEMENT_NAME ) ){
	            // there could be more than one action element
	            actionList.add( new Action( childNode ) );
	        }
	        else if( m_confidence == null && 
	                 nodeName.equals( Confidence.ELEMENT_NAME ) ){
	            // there should be one confidence element
	            m_confidence = new Confidence( childNode );	            
	        }
	    }
	    int size = actionList.size();
	    if( size > 0 ){ 
	        m_actions = new Action[ size ];
	        for( int i = 0; i < size; i++ ){
	            m_actions[ i ] = ( Action )actionList.get( i );
            }
        }
    }
    
    public Impact getImpact(){
        return m_impact;
    }
    public void setImpact( Impact impact ){
        m_impact = impact;
    }
    
    public Action []getActions(){
        return m_actions;
    }
    public void setActions( Action []actions ){
        m_actions = actions;
    }
    
    public Confidence getConfidence(){
        return m_confidence;
    }
    public void setConfidence( Confidence confidence ){
        m_confidence = confidence;
    }
    
    public Node convertToXML( Document parent ) {
        Element assessmentNode = parent.createElement( ELEMENT_NAME );
        if( m_impact != null ){
            assessmentNode.appendChild( m_impact.convertToXML( parent ) );
        }
        if( m_actions != null ){
            int len = m_actions.length;
            for( int i = 0; i < len; i++ ){
                assessmentNode.appendChild( m_actions[ i ].convertToXML( parent ) );
            }
        }
        if( m_confidence != null ){
            assessmentNode.appendChild( m_confidence.convertToXML( parent ) );
        }
        return assessmentNode;
    }
 
    private Impact m_impact;
    private Action m_actions[];
    private Confidence m_confidence;
}
