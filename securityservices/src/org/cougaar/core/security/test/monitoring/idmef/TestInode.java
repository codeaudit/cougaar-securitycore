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

import java.util.Date;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

// idmef package
import edu.jhuapl.idmef.Inode;
import edu.jhuapl.idmef.XMLUtils;

public class TestInode extends TestIdmef {

    public TestInode(){
        this( null );
    }
    public TestInode( String name ){
        super( name );
    }
    public static void main( String []args ){
        TestIdmef test = new TestInode( "TestInode" );
        test.run();
    }

    public Inode createInode(){
        return m_msgFactory.createInode( new Date(), new Integer( 100 ), new Integer( 50 ) );
    }
    public void compare( Inode inode1, Inode inode2 ){

        if( !( inode1.getChangeTime().toString().equals( inode2.getChangeTime().toString() ) ) ){
            System.out.println( "Inode category is inconsistent!" );
            System.out.println( "Inode1.category = " + inode1.getChangeTime() );
            System.out.println( "Inode2.category = " + inode2.getChangeTime() );
        }
        if( !( inode1.getCMajorDevice().equals( inode2.getCMajorDevice() ) ) ){
            System.out.println( "Inode category is inconsistent!" );
            System.out.println( "Inode1.category = " + inode1.getCMajorDevice() );
            System.out.println( "Inode2.category = " + inode2.getCMajorDevice() );
        }
        if( !( inode1.getCMinorDevice().equals( inode2.getCMinorDevice() ) ) ){
            System.out.println( "Inode description is inconsistent!" );
            System.out.println( "Inode1.description = " + inode1.getCMinorDevice() );
            System.out.println( "Inode2.description = " + inode2.getCMinorDevice() );
        }
    }
    public void run(){
        Inode inode1 = createInode();
        Document document = m_docBuilder.newDocument();
        Node inodeNode = inode1.convertToXML( document );

        Inode inode2 = new Inode( inodeNode );
        compare( inode1, inode2 );

        document.appendChild( inodeNode );
        XMLUtils.printDocument( document );
    }
}
