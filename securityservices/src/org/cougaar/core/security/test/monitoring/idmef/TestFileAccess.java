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
import edu.jhuapl.idmef.FileAccess;
import edu.jhuapl.idmef.UserId;
import edu.jhuapl.idmef.XMLUtils;

public class TestFileAccess extends TestIdmef {
    
    public TestFileAccess(){
        this( null );
    }
    public TestFileAccess( String name ){
        super( name );
    }
    public static void main( String []args ){
        TestIdmef test = new TestFileAccess( "TestFileAccess" );
        test.run();
    }
    public FileAccess createFileAccess(){
        //createFileAccess( String userId, String []permissions )
        String permissions[] = { "read", "write" };
        return m_msgFactory.createFileAccess( "mluu", permissions );   
    }
    public void compare( FileAccess []fileAccesses1, FileAccess []fileAccesses2 ){
        if( fileAccesses1.length == fileAccesses2.length ){
            int len = fileAccesses1.length;
            for( int i = 0; i < len; i++ ){
                compare( fileAccesses1[ i ], fileAccesses2[ i ] );
            }
        }
        else{
            System.out.println(" FileAccess lengths NOT EQUAL!" );
            System.out.println(" FileAccess1.length = " + fileAccesses1.length );
            System.out.println(" FileAccess2.length = " + fileAccesses2.length );
        }
        
    }
    public void compare( FileAccess fileAccess1, FileAccess fileAccess2 ){
        UserId user1 = fileAccess1.getUserId();
        UserId user2 = fileAccess2.getUserId();
        String permissions1[] = fileAccess1.getPermissions();
        String permissions2[] = fileAccess2.getPermissions();
        
        if( !( user1.getName().equals( user2.getName() ) ) ){
            System.out.println( "FileAccess user is inconsistent!" );
            System.out.println( "FileAccess1.user = " + user1.getName() );
            System.out.println( "FileAccess2.user = " + user2.getName() );
        }
        if( permissions1.length == permissions2.length ){
            int len = permissions1.length;
            for( int i = 0; i < len; i++ ){
                if( !( permissions1[ i ].equals( permissions2[ i ] ) ) ){
                    System.out.println( "FileAccess permission is inconsistent!" );
                    System.out.println( "FileAccess1.permission = " + permissions1[ i ] );
                    System.out.println( "FileAccess2.permission = " + permissions2[ i ] );
                }
            }
        }
        else{
            System.out.println(" FileAccess.permission lengths NOT EQUAL!" );
            System.out.println(" FileAccess1.permission.length = " + permissions1.length );
            System.out.println(" FileAccess2.permission.length = " + permissions2.length );
        }    
    }
    public void run(){
        FileAccess fileAccess1 = createFileAccess();
        Document document = m_docBuilder.newDocument();
        Node fileAccessNode = fileAccess1.convertToXML( document );
        
        FileAccess fileAccess2 = new FileAccess( fileAccessNode );
        compare( fileAccess1, fileAccess2 );
        
        document.appendChild( fileAccessNode );
        XMLUtils.printDocument( document );
    }
}
