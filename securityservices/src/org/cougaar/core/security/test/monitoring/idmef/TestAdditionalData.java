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

// java xml packages
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.net.InetAddress;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

// xerces package
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;

// idmef package
import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.XMLUtils;

// cougaar package
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;

public class TestAdditionalData extends TestIdmef {
    public static String MEANING = "test-additional-data";
    
    public TestAdditionalData( String name ){
        super( name );
    }
    
    public static void main( String []args ){
        TestIdmef test = new TestAdditionalData( "TestAdditionalData" );
        test.run();
    }
    public AdditionalData createAdditionalData(){
        String refIdents[] = { "00000001", "00000002" };
        Address address = null;
        try {
            address = m_msgFactory.createAddress( InetAddress.getLocalHost().getHostAddress(), 
                                                  null, Address.IPV4_ADDR );
        }
        catch( Exception e ){
            e.printStackTrace();
        }
        
        Agent agent = m_msgFactory.createAgent( "test-agent",
                                                "a test agent",
                                                "SF, CA",
                                                address,
                                                refIdents );
        
        return m_msgFactory.createAdditionalData( AdditionalData.XML,
                                                  MEANING,
                                                   agent.toTaggedString() );
    }
    public void compare( AdditionalData ad1, AdditionalData ad2 ){
       if( !( ad1.getType().equals( ad2.getType() ) ) ){
            System.out.println( "Additional Data type is inconsistent!" );
            System.out.println( "AdditionalData1.type = " + ad1.getType() );
            System.out.println( "AdditionalData2.type = " + ad2.getType() );
        }
        if( !( ad1.getMeaning().equals( ad2.getMeaning() ) ) ){
            System.out.println( "Additional Data meaning is inconsistent!" );
            System.out.println( "AdditionalData1.meaning = " + ad1.getMeaning() );
            System.out.println( "AdditionalData2.meaning = " + ad2.getMeaning() );
        }
        if( !( ad1.getAdditionalData().equals( ad2.getAdditionalData() ) ) ){
            System.out.println( "Additional Data data is inconsistent!" );
            System.out.println( "AdditionalData1.data = " + ad1.getAdditionalData() );
            System.out.println( "AdditionalData2.data = " + ad2.getAdditionalData() );
        }
    }
    public void run(){
       
        Document document = m_docBuilder.newDocument();
        AdditionalData ad1 = createAdditionalData();
        
        Node adNode = ad1.convertToXML( document );
        AdditionalData ad2 = new AdditionalData( adNode );
        compare( ad1, ad2 );
        
        document.appendChild( adNode );
        XMLUtils.printDocument( document );
    }
}