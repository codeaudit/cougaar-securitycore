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

// idmef package
import edu.jhuapl.idmef.Impact;
import edu.jhuapl.idmef.XMLUtils;

public class TestImpact extends TestIdmef {
    
    public TestImpact(){
        this( null );
    }
    public TestImpact( String name ){
        super( name );
    }
    public static void main( String []args ){
        TestIdmef test = new TestImpact( "TestImpact" );
        test.run();
    }
    public Impact createImpact(){
        return m_msgFactory.createImpact( Impact.HIGH, 
                                          Impact.SUCCEEDED, 
                                          Impact.DOS,
                                          "test dos attack" );    
    }
    public void compare( Impact impact1, Impact impact2 ){
        if( !( impact1.getSeverity().equals( impact2.getSeverity() ) ) ){
            System.out.println( "Impact severity is inconsistent!" );
            System.out.println( "Impact1.severity = " + impact1.getSeverity() );
            System.out.println( "Impact2.severity = " + impact2.getSeverity() );
        }
        if( !( impact1.getCompletion().equals( impact2.getCompletion() ) ) ){
            System.out.println( "Impact completion is inconsistent!" );
            System.out.println( "Impact1.completion = " + impact1.getCompletion() );
            System.out.println( "Impact2.completion = " + impact2.getCompletion() );
        }
        if( !( impact1.getType().equals( impact2.getType() ) ) ){
            System.out.println( "Impact type is inconsistent!" );
            System.out.println( "Impact1.type = " + impact1.getType() );
            System.out.println( "Impact2.type = " + impact2.getType() );
        }
        if( !( impact1.getDescription().equals( impact2.getDescription() ) ) ){
            System.out.println( "Impact description is inconsistent!" );
            System.out.println( "Impact1.description = " + impact1.getDescription() );
            System.out.println( "Impact2.description = " + impact2.getDescription() );
        }
    }
    public void run(){
        Impact impact1 = createImpact();
        Document document = m_docBuilder.newDocument();
        Node impactNode = impact1.convertToXML( document );
        
        Impact impact2 = new Impact( impactNode );
        compare( impact1, impact2 );
        document.appendChild( impactNode );
        XMLUtils.printDocument( document );
    }
}
