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
import edu.jhuapl.idmef.Action;
import edu.jhuapl.idmef.XMLUtils;

public class TestAction extends TestIdmef {
    
    public TestAction( String name ){
        super( name );
    }
    
    public static void main( String []args ){
        TestIdmef test = new TestAction( "TestAction" );
        test.run();
    }
    
    public void run(){
        Action action1 = m_msgFactory.createAction( null, "this is a test action" );
        Document document = m_docBuilder.newDocument();
        Node actionNode = action1.convertToXML( document );
        
        Action action2 = new Action( actionNode );
        if( !( action1.getCategory().equals( action2.getCategory() ) ) ){
            System.out.println( "Action category is inconsistent!" );
            System.out.println( "Action1.category = " + action1.getCategory() );
            System.out.println( "Action2.category = " + action2.getCategory() );
        }
        if( !( action1.getDescription().equals( action2.getDescription() ) ) ){
            System.out.println( "Action description is inconsistent!" );
            System.out.println( "Action1.description = " + action1.getDescription() );
            System.out.println( "Action2.description = " + action2.getDescription() );
        }
        document.appendChild( actionNode );
        XMLUtils.printDocument( document );
    }
}
