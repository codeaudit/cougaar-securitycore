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
 * The Impact class is used to provide the analyzer's assessment of the
 * impact of the event on the target(s).  It is represented in the XML
 *  DTD as follows:
 *
 *     <!ENTITY % attvals.severity             "
 *         ( low | medium | high )
 *       ">
 *     <!ENTITY % attvals.completion           "
 *         ( failed | succeeded )
 *       ">
 *     <!ENTITY % attvals.impacttype           "
 *         ( admin | dos | file | recon | user | other )
 *       ">
 *     <!ELEMENT Impact     (#PCDATA | EMPTY)* >
 *     <!ATTLIST Impact
 *         severity            %attvals.severity;      #IMPLIED
 *         completion          %attvals.completion;    #IMPLIED
 *         type                %attvals.impacttype;    'other'
 *       >
 *
 * The Impact class has three attributes:
 *
 * severity
 *    An estimate of the relative severity of the event.  The permitted
 *    values are shown below.  There is no default value.
 *
 *    Rank   Keyword            Description
 *    ----   -------            -----------
 *      0    low                Low severity
 *      1    medium             Medium severity
 *      2    high               High severity
 *
 * completion
 *    An indication of whether the analyzer believes the attempt that
 *    the event describes was successful or not.  The permitted values
 *    are shown below.  There is no default value.
 *
 *    Rank   Keyword            Description
 *    ----   -------            -----------
 *      0    failed             The attempt was not successful
 *      1    succeeded          The attempt succeeded
 *
 * type
 *    The type of attempt represented by this event, in relatively broad
 *    categories.  The permitted values are shown below.  The default
 *    value is "other."
 * 
 *    Rank   Keyword            Description
 *    ----   -------            -----------
 *      0    admin              Administrative privileges were
 *                              attempted or obtained
 *      1    dos                A denial of service was attempted or
 *                              completed
 *      2    file               An action on a file was attempted or
 *                              completed
 *      3    recon              A reconnaissance probe was attempted
 *                              or completed
 *      4    user               User privileges were attempted or
 *                              obtained
 *      5    other              Anything not in one of the above
 *                              categories
 *
 * All three attributes are optional.  The element itself may be empty,
 * or may contain a textual description of the impact, if the analyzer
 * is able to provide additional details.
 *
 * @since IDMEF Message v1.0
 */
public class Impact implements XMLSerializable {
    
    public static String ELEMENT_NAME = "Impact";
    public static String ATTRIBUTE_SEVERITY = "severity";
    public static String ATTRIBUTE_COMPLETION = "completion";
    public static String ATTRIBUTE_TYPE = "type";
    
    // severity
    public static String LOW = "low";
    public static String MEDIUM = "medium";
    public static String HIGH = "high";
    
    // completion
    public static String FAILED = "failed";
    public static String SUCCEEDED = "succeeded";
    
    // type
    public static String ADMIN = "admin";
    public static String DOS = "dos";
    public static String FILE = "file";
    public static String USER = "user";
    public static String OTHER = "other";
    
    public Impact(){
        this( null, null, null, null );
    }
    
    public Impact( String severity, 
                   String completion, 
                   String type,
                   String description ){
        m_severity = severity;
        m_completion = completion;
        m_type = type;
        m_description = description;
    }
    
    public Impact( Node node ){
        Node impactNode = XMLUtils.GetNodeForName( node, ELEMENT_NAME );
        NamedNodeMap attributes = impactNode.getAttributes();
        
        Node attribute = attributes.getNamedItem( ATTRIBUTE_SEVERITY );
        if( attribute != null ){
            m_severity = attribute.getNodeValue();
        }
        attribute = attributes.getNamedItem( ATTRIBUTE_COMPLETION );
        if( attribute != null ){
            m_completion = attribute.getNodeValue();
        }
        attribute = attributes.getNamedItem( ATTRIBUTE_TYPE );
        if( attribute != null ){
            m_type = attribute.getNodeValue();
        }
        m_description = impactNode.getNodeValue();
    }
    
    public String getSeverity(){
        return m_severity;
    }
    public void setSeverity( String severity ){
        m_severity = severity;
    }
    
    public String getCompletion(){
        return m_completion;
    }
    public void setCompletion( String completion ){
        m_completion = completion;
    }
    
    public String getType(){
        return m_type;
    }
    public void setType( String type ){
        m_type = type;
    }
    
    public String getDescription(){
        return m_description;
    }
    public void setDesciption( String description ){
        m_description = description;
    }
            
    public Node convertToXML( Document parent ){
        Element impactNode = parent.createElement( ELEMENT_NAME );  
        if( m_severity != null ){
            impactNode.setAttribute( ATTRIBUTE_SEVERITY, m_severity );
        }
        if( m_completion != null ){
            impactNode.setAttribute( ATTRIBUTE_COMPLETION, m_completion );
        }
        if( m_type != null ){
            impactNode.setAttribute( ATTRIBUTE_TYPE, m_type );
        }
        if( m_description != null ){
            impactNode.appendChild( parent.createTextNode( m_description ) );
        }
        
        return impactNode; 
    }
    
    private String m_severity;
    private String m_completion;
    private String m_type;
    private String m_description;
}