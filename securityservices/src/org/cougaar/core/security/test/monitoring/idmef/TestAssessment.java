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

import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

// idmef package
import edu.jhuapl.idmef.Assessment;
import edu.jhuapl.idmef.Action;
import edu.jhuapl.idmef.Confidence;
import edu.jhuapl.idmef.Impact;
import edu.jhuapl.idmef.XMLUtils;

public class TestAssessment extends TestIdmef {
    
    public TestAssessment( String name ){
        super( name );   
    }
    
    public static void main( String []args ){
        TestIdmef test = new TestAssessment( "TestAssessment" );
        test.init();
        test.run();
    }
    public void init(){
        m_impactTester = new TestImpact();
        m_actionTester = new TestAction();
        m_confidenceTester = new TestConfidence();
    }
    public Assessment createAssessment(){
        Impact impact = m_impactTester.createImpact();
        Confidence confidence = m_confidenceTester.createConfidence();
        Action actions[] = { m_actionTester.createAction() };
        List actionList = convertToList( actions );
        return m_msgFactory.createAssessment( impact, actionList, confidence );
    }
    public void compare( Assessment assessment1, Assessment assessment2 ){
        m_impactTester.compare( assessment1.getImpact(), assessment2.getImpact() );
        m_confidenceTester.compare( assessment1.getConfidence(), assessment2.getConfidence() );
        m_actionTester.compare( assessment1.getActions(), assessment2.getActions() );
    }
    public void run(){        
        Assessment assessment1 = createAssessment();
        Document document = m_docBuilder.newDocument();
        Node assessmentNode = assessment1.convertToXML( document );
        
        Assessment assessment2 = new Assessment( assessmentNode );
        compare( assessment1, assessment2 );
        document.appendChild( assessmentNode );
        XMLUtils.printDocument( document );
    }
    private TestImpact m_impactTester;
    private TestAction m_actionTester;
    private TestConfidence m_confidenceTester;
}
