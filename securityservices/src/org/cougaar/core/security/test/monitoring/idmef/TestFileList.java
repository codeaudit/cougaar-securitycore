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

import edu.jhuapl.idmef.FileList;
import edu.jhuapl.idmef.IDMEF_File;
import edu.jhuapl.idmef.XMLUtils;

public class TestFileList extends TestIdmef {
    
    public TestFileList( String name ){
        super( name );
    }
    
    public static void main( String []args ){
        TestIdmef test = new TestFileList( "TestFileList" );
        test.init();
        test.run();
    }
    public void init(){
      m_fileTester = new TestFile();
      m_fileTester.init();
    }
    public FileList createFileList(){
      IDMEF_File files[] = { m_fileTester.createFile() };
      List fileList = convertToList( files );
      return m_msgFactory.createFileList( fileList ); 
    }
    public void compare( FileList fileList1, FileList fileList2 ){
      m_fileTester.compare( fileList1.getFiles(), fileList2.getFiles() ); 
    }
    public void run(){
        FileList fileList1 = createFileList();
        Document document = m_docBuilder.newDocument();
        Node fileListNode = fileList1.convertToXML( document );
        FileList fileList2 = new FileList( fileListNode );   
        compare( fileList1, fileList2 );
        
        document.appendChild( fileListNode );
        XMLUtils.printDocument( document );
    }
    private TestFile m_fileTester;
}
