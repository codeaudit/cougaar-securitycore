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

import java.lang.Float;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;

/**
 * <pre>
 * The Confidence class is used to represent the analyzer's best
 * estimate of the validity of its analysis.  It is represented in the
 * XML DTD as follows:
 * 
 *     &lt!ENTITY % attvals.rating               "
 *         ( low | medium | high | numeric )
 *     "&gt
 *     &lt!ELEMENT Confidence (#PCDATA | EMPTY)* &gt
 *     &lt!ATTLIST Confidence
 *         rating              %attvals.rating;        'numeric'
 *     &gt
 *
 *  The Confidence class has one attribute:
 *
 *  rating
 *     The analyzer's rating of its analytical validity.  The permitted
 *     values are shown below.  The default value is "numeric."
 *
 *     Rank   Keyword            Description
 *     ----   -------            -----------
 *       0    LOW                The analyzer has little confidence in
 *                               its validity
 *       1    MEDIUM             The analyzer has average confidence in
 *                               its validity
 *       2    HIGH               The analyzer has high confidence in its
 *                               validity
 *       3    NUMERIC            The analyzer has provided a posterior
 *                               probability value indicating its
 *                               confidence in its validity
 *
 *  This element should be used only when the analyzer can produce
 *  meaningful information.  Systems that can output only a rough
 *  heuristic should use "low", "medium", or "high" as the rating value.
 *  In this case, the element content should be omitted.
 *
 *  Systems capable of producing reasonable probability estimates should
 *  use "numeric" as the rating value and include a numeric confidence
 *  value in the element content. This numeric value should reflect a
 *  posterior probability (the probability that an attack has occurred
 *  given the data seen by the detection system and the model used by the
 *  system). It is a floating point number between 0.0 and 1.0,
 *  inclusive. The number of digits should be limited to those
 *  representable by a single precision floating point value, and may be
 *  represented as described in Section 4.4.2.
 * <b>
 *  NOTE: It should be noted that different types of analyzers may
 *        compute confidence values in different ways and that in many
 *        cases, confidence values from different analyzers should not be
 *        compared (for example, if the analyzers use different methods
 *        of computing or representing confidence, or are of different
 *        types or configurations).  Care should be taken when
 *        implementing systems that process confidence values (such as
 *        event correlators) not to make comparisons or assumptions that
 *        cannot be supported by the system's knowledge of the
 *        environment in which it is working.
 * </b>
 * </pre>
 * @since IDMEF Message v1.0
 */
public class Confidence implements XMLSerializable {
    
    // xml element and attribute names
    public static String ELEMENT_NAME = "Confidence";
    public static String ATTRIBUTE_RATING = "rating";
    
    // rating
    public static String LOW = "low";
    public static String MEDIUM = "medium";
    public static String HIGH = "high";
    public static String NUMERIC = "numeric";
    
    public Confidence(){
        this( null, null );
    }
    
    public Confidence( String rating, Float numeric ){
        m_rating = rating;
        m_numeric = numeric;
    }
    
    public Confidence( Node node ){
        NamedNodeMap attributes = node.getAttributes();
        
        Node attribute = attributes.getNamedItem( ATTRIBUTE_RATING );
        if( attribute != null ){
            m_rating = attribute.getNodeValue();
        }
        if( m_rating.equals( NUMERIC ) ){
           try {
                String numeric = XMLUtils.getAssociatedString( node );
                if( numeric != null ){
                    m_numeric = new Float( numeric );
                }
            }
            catch( NumberFormatException nfe ){
                // do we care?  
            }
        }
    }
    
    public String getRating(){
        return m_rating;
    }
    public void setRating( String rating ){
        m_rating = rating;
    }
    
    public Float getNumeric(){
        return m_numeric;
    }
    public void setNumeric( Float numeric ){
        m_numeric = numeric;
    }
    
    public Node convertToXML( Document parent ){
        Element confidenceNode = parent.createElement( ELEMENT_NAME );  
        if( m_rating != null ){
            confidenceNode.setAttribute( ATTRIBUTE_RATING, m_rating );
        }
        if( m_rating.equals( NUMERIC ) &&
            ( m_numeric != null ) ){
            // set the Confidence node value iff rating is NUMERIC
            confidenceNode.appendChild( parent.createTextNode( m_numeric.toString() ) );   
        } 
        return confidenceNode;  
    }   
    
    private String m_rating = NUMERIC;
    private Float m_numeric;
}