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

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import edu.jhuapl.idmef.Confidence;
import edu.jhuapl.idmef.XMLUtils;

public class TestConfidence extends TestIdmef {
    
    public TestConfidence(){
        this( null );
    }
    public TestConfidence( String name ){
        super( name );
    }
    public static void main( String []args ){
        TestIdmef test = new TestConfidence( "TestConfidence" );
        test.run();
    }
    public Confidence createConfidence(){
        return m_msgFactory.createConfidence( Confidence.NUMERIC, new Float( 0.5f ) );
    }
    public void compare( Confidence confidence1, Confidence confidence2 ){
        if( !( confidence1.getRating().equals( confidence2.getRating() ) ) ){
            System.out.println( "Confidence category is inconsistent!" );
            System.out.println( "Confidence1.category = " + confidence1.getRating() );
            System.out.println( "Confidence2.category = " + confidence2.getRating() );
        }
        if( !( confidence1.getNumeric().equals( confidence2.getNumeric() ) ) ){
            System.out.println( "Confidence description is inconsistent!" );
            System.out.println( "Confidence1.description = " + confidence1.getNumeric() );
            System.out.println( "Confidence2.description = " + confidence2.getNumeric() );
        }
    }
    public void run(){
        Confidence confidence1 = createConfidence();
        Document document = m_docBuilder.newDocument();
        Node confidenceNode = confidence1.convertToXML( document );
        
        Confidence confidence2 = new Confidence( confidenceNode );
        compare( confidence1, confidence2 );
        document.appendChild( confidenceNode );
        XMLUtils.printDocument( document );
    }
}
