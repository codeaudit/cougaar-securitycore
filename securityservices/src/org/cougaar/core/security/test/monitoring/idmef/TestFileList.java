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

import java.io.File;
import java.util.Date;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

// idmef package
import edu.jhuapl.idmef.FileList;
import edu.jhuapl.idmef.IDMEF_File;
import edu.jhuapl.idmef.FileAccess;
import edu.jhuapl.idmef.Linkage;
import edu.jhuapl.idmef.Inode;
import edu.jhuapl.idmef.UserId;
import edu.jhuapl.idmef.XMLUtils;

public class TestFileList extends TestIdmef {
    
    public TestFileList( String name ){
        super( name );
    }
    
    public static void main( String []args ){
        TestIdmef test = new TestFileList( "TestFileList" );
        test.run();
    }
    
    public void run(){
        
        Inode inode = m_msgFactory.createInode( new Date(), 
                                                new Integer( 101 ),
                                                new Integer( 100 ) );
        File aFile1 = new File( new String( "e:/devtools/cygwin/home/mluu/.ssh/id_rsa.pub" ) );
        File aFile2 = new File( new String( "e:/devtools/cygwin/home/mluu/.ssh/id_rsa" ) );
        Linkage linkages[] = { m_msgFactory.createLinkage( aFile2,
                                                           Linkage.HARD_LINK ) };
        String permissions[] = { new String( "read" ), 
                                 new String( "write" ) };
        FileAccess fileAccesses[] = { m_msgFactory.createFileAccess( new String( "mluu" ),
                                                                   permissions ) };
        
        IDMEF_File files[] = { m_msgFactory.createFile( aFile1, 
                                                     fileAccesses,
                                                     linkages,
                                                     inode,
                                                     IDMEF_File.ORIGINAL,
                                                     new String( "fat16" ) ) };
        FileList fileList1 = m_msgFactory.createFileList( files );
        
        Document document = m_docBuilder.newDocument();
        Node fileListNode = fileList1.convertToXML( document );
        
        FileList fileList2 = new FileList( fileListNode );
        
        IDMEF_File files1[] = fileList1.getFiles();
        FileAccess fileAccesses1[] = files1[ 0 ].getFileAccesses();
        Linkage linkages1[] = files1[ 0 ].getLinkages();
        Inode inode1 = files1[ 0 ].getInode();
        
        String fstype1 = files1[ 0 ].getFstype();
        String category1 = files1[ 0 ].getCategory();
        String fileName1 = files1[ 0 ].getName();
        String filePath1 = files1[ 0 ].getPath();
        
        String permissions1[] = fileAccesses1[ 0 ].getPermissions();
        UserId userId1 = fileAccesses1[ 0 ].getUserId();
        String user1 = userId1.getName();
        String userIdent1 = userId1.getIdent();
        
        String linkageName1 = linkages1[ 0 ].getName();
        String linkagePath1 = linkages1[ 0 ].getPath();
        String linkageCategory1 = linkages1[ 0 ].getCategory();
        
        Date changeTime1 = inode1.getChangeTime();
        Integer cMajorDevice1 = inode1.getCMajorDevice();
        Integer cMinorDevice1 = inode1.getCMinorDevice();
        
        IDMEF_File files2[] = fileList2.getFiles();
        FileAccess fileAccesses2[] = files2[ 0 ].getFileAccesses();
        Linkage linkages2[] = files2[ 0 ].getLinkages();
        Inode inode2 = files2[ 0 ].getInode();
        
        String fstype2 = files2[ 0 ].getFstype();
        String category2 = files2[ 0 ].getCategory();
        String fileName2 = files2[ 0 ].getName();
        String filePath2 = files2[ 0 ].getPath();
        
        String permissions2[] = fileAccesses2[ 0 ].getPermissions();
        UserId userId2 = fileAccesses2[ 0 ].getUserId();
        String user2 = userId2.getName();
        String userIdent2 = userId2.getIdent();
        
        String linkageName2 = linkages2[ 0 ].getName();
        String linkagePath2 = linkages2[ 0 ].getPath();
        String linkageCategory2 = linkages2[ 0 ].getCategory();
        
        Date changeTime2 = inode2.getChangeTime();
        Integer cMajorDevice2 = inode2.getCMajorDevice();
        Integer cMinorDevice2 = inode2.getCMinorDevice();
        
        if( !( fileName1.equals( fileName2 ) ) ){
            System.out.println( "IDMEF_File name is inconsistent!" );
            System.out.println( "IDMEF_File1.name = " + fileName1 );
            System.out.println( "IDMEF_File2.name = " + fileName2 );
        }
        if( !( filePath1.equals( filePath2 ) ) ){
            System.out.println( "IDMEF_File path is inconsistent!" );
            System.out.println( "IDMEF_File1.path = " + filePath1 );
            System.out.println( "IDMEF_File2.path = " + filePath2 );
        }
        if( !( category1.equals( category2 ) ) ){
            System.out.println( "IDMEF_File category is inconsistent!" );
            System.out.println( "IDMEF_File1.category = " + category1 );
            System.out.println( "IDMEF_File2.category = " + category2 );
        }
        if( !( fstype1.equals( fstype2 ) ) ){
            System.out.println( "IDMEF_File fstype is inconsistent!" );
            System.out.println( "IDMEF_File1.fstype = " + fstype1 );
            System.out.println( "IDMEF_File2.fstype = " + fstype2 );
        }
        if( !( user1.equals( user2 ) ) ){
            System.out.println( "FileAccess user is inconsistent!" );
            System.out.println( "FileAccess1.user = " + user1 );
            System.out.println( "FileAccess2.user = " + user2 );
        }
        if( !( permissions1[ 0 ].equals( permissions2[ 0 ] ) ) ){
            System.out.println( "FileAccess permission0 is inconsistent!" );
            System.out.println( "FileAccess1.permission0 = " + permissions1[ 0 ] );
            System.out.println( "FileAccess2.permission0 = " + permissions2[ 0 ] );
        }
        if( !( permissions1[ 1 ].equals( permissions2[ 1 ] ) ) ){
            System.out.println( "FileAccess permission1 is inconsistent!" );
            System.out.println( "FileAccess1.permission1 = " + permissions1[ 1 ] );
            System.out.println( "FileAccess2.permission1 = " + permissions2[ 1 ] );
        }
        if( !( linkageName1.equals( linkageName2 ) ) ){
            System.out.println( "Linkage name is inconsistent!" );
            System.out.println( "Linkage1.name = " + linkageName1 );
            System.out.println( "Linkage2.name = " + linkageName2 );
        }
        if( !( linkagePath1.equals( linkagePath2 ) ) ){
            System.out.println( "Linkage path is inconsistent!" );
            System.out.println( "Linkage1.path = " + linkagePath1 );
            System.out.println( "Linkage2.path = " + linkagePath2 );
        }
        if( !( linkageCategory1.equals( linkageCategory2 ) ) ){
            System.out.println( "Linkage category is inconsistent!" );
            System.out.println( "Linkage1.category = " + linkageCategory1 );
            System.out.println( "Linkage2.category = " + linkageCategory2);
        }
        if( !( changeTime1.toString().equals( changeTime2.toString() ) ) ){
            System.out.println( "Inode changeTime is inconsistent!" );
            System.out.println( "Inode1.changeTime = " + changeTime1 );
            System.out.println( "Inode2.changeTime = " + changeTime2 );
        }
        if( !( cMajorDevice1.equals( cMajorDevice2 ) ) ){
            System.out.println( "Inode cMajorDevice is inconsistent!" );
            System.out.println( "Inode1.cMajorDevice = " + cMajorDevice1 );
            System.out.println( "Inode2.cMajorDevice = " + cMajorDevice2);
        }
        if( !( cMinorDevice1.equals( cMinorDevice2 ) ) ){
            System.out.println( "Inode cMinorDevice is inconsistent!" );
            System.out.println( "Inode1.cMinorDevice = " + cMinorDevice1 );
            System.out.println( "Inode2.cMinorDevice = " + cMinorDevice2);
        }
        
        document.appendChild( fileListNode );
        XMLUtils.printDocument( document );
    }
}
