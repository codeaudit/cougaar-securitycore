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

import java.util.ArrayList;
import java.util.Date;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.NamedNodeMap;

/**
 * The File class provides specific information about a file or other
 *  file-like object that has been created, deleted, or modified on the
 *  target.  More than one File can be used within the FileList class to
 *  provide information about more than one file.  The description can
 *  provide either the file settings prior to the event or the file
 *  settings at the time of the event, as specified using the "category"
 *  attribute.
 *
 *  The File class is composed of ten aggregate classes, as shown in
 *  below.
 *
 *              +--------------+
 *              |     File     |
 *              +--------------+            +-------------+
 *              |              |<>----------|    name     |
 *              |              |            +-------------+
 *              |              |            +-------------+
 *              |              |<>----------|    path     |
 *              |              |            +-------------+
 *              |              |       0..1 +-------------+
 *              |              |<>----------| create-time |
 *              |              |            +-------------+
 *              |              |       0..1 +-------------+
 *              |              |<>----------| modify-time |
 *              |              |            +-------------+
 *              |              |       0..1 +-------------+
 *              |              |<>----------| access-time |
 *              |              |            +-------------+
 *              |              |       0..1 +-------------+
 *              |              |<>----------|  data-size  |
 *              |              |            +-------------+
 *              |              |       0..1 +-------------+
 *              |              |<>----------|  disk-size  |
 *              |              |            +-------------+
 *              |              |       0..* +-------------+
 *              |              |<>----------| FileAccess  |
 *              |              |            +-------------+
 *              |              |       0..* +-------------+
 *              |              |<>----------|   Linkage   |
 *              |              |            +-------------+
 *              |              |       0..1 +-------------+
 *              |              |<>----------|    Inode    |
 *              |              |            +-------------+
 *              +--------------+
 *
 *  The aggregate classes that make up File are:
 *
 *  name
 *     Exactly one.  STRING.  The name of the file to which the alert
 *     applies, not including the path to the file.
 *
 *  path
 *     Exactly one.  STRING.  The full path to the file, including the
 *     name.  The path name should be represented in as "universal" a
 *     manner as possible, to facilitate processing of the alert.
 *
 *     For Windows systems, the path should be specified using the
 *     Universal Naming Convention (UNC) for remote files, and using a
 *     drive letter for local files (e.g., "C:\boot.ini").  For Unix
 *     systems, paths on network file systems should use the name of the
 *     mounted resource instead of the local mount point (e.g.,
 *     "fileserver:/usr/local/bin/foo").  The mount point can be provided
 *     using the <Linkage> element.
 *
 *  create-time
 *     Zero or one.  DATETIME.  Time the file was created.  Note that
 *     this is *not* the Unix "st_ctime" file attribute (which is not
 *     file creation time).  The Unix "st_ctime" attribute is contained
 *     in the "Inode" class. 
 *
 *  modify-time
 *     Zero or one.  DATETIME.  Time the file was last modified.
 *
 *  access-time
 *     Zero or one.  DATETIME.  Time the file was last accessed.
 *
 *  data-size
 *     Zero or one.  INTEGER.  The size of the data, in bytes.  Typically
 *     what is meant when referring to file size.  On Unix UFS file
 *     systems, this value corresponds to stat.st_size.  On Windows NTFS,
 *     this value corres- ponds to VDL.
 *
 *  disk-size
 *     Zero or one.  INTEGER.  The physical space on disk consumed by the
 *     file, in bytes.  On Unix UFS file systems, this value corresponds
 *     to 512 * stat.st_blocks.  On Windows NTFS, this value corresponds
 *     to EOF.
 *
 *  FileAccess
 *     Zero or more.  Access permissions on the file.
 *
 *  Linkage
 *     Zero or more.  File system objects to which this file is linked
 *     (other references for the file).
 *
 *  Inode
 *     Zero or one.  Inode information for this file (relevant to Unix).
 *
 *  This is represented in the XML DTD as follows:
 *
 *     <!ENTITY % attvals.filecat              "
 *         ( current | original )
 *       ">
 *     <!ELEMENT File                          (
 *         name, path, create-time?, modify-time?, access-time?,
 *         data-size?, disk-size?, FileAccess*, Linkage*, Inode?
 *       )>
 *     <!ATTLIST File
 *         ident               CDATA                   '0'
 *         category            %attvals.filecat;       #REQUIRED
 *         fstype              CDATA                   #REQUIRED
 *       >
 *       
 *  The File class has three attributes:
 *
 *  ident
 *     Optional.  A unique identifier for this file, see Section 4.4.9.
 *
 *  category
 *     Required.  The context for the information being provided.  The
 *     permitted values are shown below.  There is no default value. 
 *
 *     Rank   Keyword            Description
 *     ----   -------            -----------
 *       0     current           The file information is from after the
 *                               reported change
 *       1     original          The file information is from before the
 *                               reported change 
 *
 *  fstype
 *     Required.  The type of file system the file resides on.  The name
 *     should be specified using a standard abbreviation, e.g., "ufs",
 *     "nfs", "afs", "ntfs", "fat16", "fat32", "pcfs", "joliet", "cdfs",
 *     etc.  This attribute governs how path names and other attributes
 *     are interpreted.
 *
 * @since IDMEF Message v1.0
 */
public class IDMEF_File implements XMLSerializable {

    // xml elements and attributes
    public static String ELEMENT_NAME = "File";
    public static String CHILD_ELEMENT_NAME = "name";
    public static String CHILD_ELEMENT_PATH = "path";
    public static String CHILD_ELEMENT_CREATE_TIME = "create-time";
    public static String CHILD_ELEMENT_MODIFY_TIME = "modify-time";
    public static String CHILD_ELEMENT_ACCESS_TIME = "access-time";
    public static String CHILD_ELEMENT_DATA_SIZE = "data-size";
    public static String CHILD_ELEMENT_DISK_SIZE = "disk-size";
    public static String CHILD_ELEMENT_FILEACCESS = "FileAccess";
    public static String CHILD_ELEMENT_LINKAGE = "Linkage";
    public static String CHILD_ELEMENT_INODE = "Inode";
                    
    public static String ATTRIBUTE_CATEGORY = "category";
    public static String ATTRIBUTE_FSTYPE = "fstype";
    public static String ATTRIBUTE_IDENT = "ident";
    
    // category values
    public static String CURRENT = "current";
    public static String ORIGINAL = "original";
    
    public IDMEF_File( String name, String path, 
            Date createTime, Date modifyTime, Date accessTime, 
            Integer dataSize, Integer diskSize, FileAccess []fileAccesses,
            Linkage []linkages, Inode inode, String category,
            String fstype, String ident ){
        m_name = name;
        m_path = path;
        m_createTime = createTime;
        m_modifyTime = modifyTime;
        m_accessTime = accessTime;
        m_dataSize = dataSize;
        m_diskSize = diskSize;
        m_fileAccesses = fileAccesses;
        m_linkages = linkages;
        m_inode = inode;
        m_category = category;
        m_fstype = fstype;
        m_ident = ident;
    }
    
    public IDMEF_File( Node node ){
        
        SimpleDateFormat formatter = 
                new SimpleDateFormat ("yyyy-MM-dd'T'hh:mm:ss'Z'");
        
        Node nameNode =  XMLUtils.GetNodeForName( node, CHILD_ELEMENT_NAME );
	    if( nameNode != null ){
	        m_name = nameNode.getNodeValue();
        }
        Node pathNode =  XMLUtils.GetNodeForName( node, CHILD_ELEMENT_PATH );
	    if( pathNode != null ){
	        m_path = pathNode.getNodeValue();
        }
        Node cTimeNode =  XMLUtils.GetNodeForName( node, 
                CHILD_ELEMENT_CREATE_TIME );
	    if( cTimeNode != null ){
	        try{
	            m_createTime = formatter.parse( cTimeNode.getNodeValue() );
            }
            catch( ParseException pe ){
                pe.printStackTrace();
            }
        }
        Node mTimeNode =  XMLUtils.GetNodeForName( node, 
                CHILD_ELEMENT_MODIFY_TIME );
	    if( mTimeNode != null ){
	        try{
	            m_modifyTime = formatter.parse( mTimeNode.getNodeValue() );
            }
            catch( ParseException pe ){
                pe.printStackTrace();
            }
        }
        Node aTimeNode =  XMLUtils.GetNodeForName( node, 
                CHILD_ELEMENT_ACCESS_TIME );
	    if( aTimeNode != null ){
	        try{
	            m_accessTime = formatter.parse( aTimeNode.getNodeValue() );
            }
            catch( ParseException pe ){
                pe.printStackTrace();
            }
        }
        Node dataSizeNode = XMLUtils.GetNodeForName( node, 
                CHILD_ELEMENT_DATA_SIZE );
        if( dataSizeNode != null ){
            m_dataSize = new Integer( dataSizeNode.getNodeValue() );
        }
        Node diskSizeNode = XMLUtils.GetNodeForName( node, 
                CHILD_ELEMENT_DISK_SIZE );
        if( diskSizeNode != null ){
            m_diskSize = new Integer( diskSizeNode.getNodeValue() );
        }

        Node inodeNode = XMLUtils.GetNodeForName( node, 
                CHILD_ELEMENT_INODE );
        if( inodeNode != null ){
            m_inode = new Inode( inodeNode );
        }
       
    	NodeList children = node.getChildNodes();
    	ArrayList fileAccesses = new ArrayList();
    	ArrayList linkages = new ArrayList();

    	for (int i=0; i<children.getLength(); i++){
    	    Node child = children.item(i);
    	    if( child.getNodeName().equals( FileAccess.ELEMENT_NAME ) ){
         		fileAccesses.add( new FileAccess( child ) );
	        }
    	    else if( child.getNodeName().equals( Linkage.ELEMENT_NAME ) ){
         		linkages.add( new Linkage( child ) );
	        }
	    }

        // TODO: change since toArray is slow due to System.arraycopy()
        m_fileAccesses = ( FileAccess [] )fileAccesses.toArray();
        m_linkages = ( Linkage [] )linkages.toArray();
        
        // get the attributes
    	NamedNodeMap nnm = node.getAttributes();

    	Node attr = nnm.getNamedItem( ATTRIBUTE_IDENT );
    	if(attr != null){
    	    m_ident = attr.getNodeValue();
        }
        node = nnm.getNamedItem( ATTRIBUTE_CATEGORY );
        if(attr != null){
    	    m_category = attr.getNodeValue();
        }
        node = nnm.getNamedItem( ATTRIBUTE_FSTYPE );
        if(attr != null){
    	    m_fstype = attr.getNodeValue();
        }
    }
    
    public String getName(){
        return m_name;
    }
    public void setName( String name ){
        m_name = name;
    }
    
    public String getPath(){
        return m_path;
    }
    public void setPath( String path ){
        m_path = path;
    }
    
    public Date getCreateTime(){
        return m_createTime;
    }
    public void setCreateTime( Date createTime ){
        m_createTime = createTime;
    }
    
    public Date getModifyTime(){
        return m_modifyTime;
    }
    public void setModifyTime( Date modifyTime ){
        m_modifyTime = modifyTime;
    }
    
    public Date getAccessTime(){
        return m_accessTime;
    }
    public void setAccessTime( Date accessTime ){
        m_accessTime = accessTime;
    }
    
    public Integer getDataSize(){
        return m_dataSize;
    }
    public void setDateSize( Integer dataSize ){
        m_dataSize = dataSize;
    }
    
    public Integer getDiskSize(){
        return m_diskSize;
    }
    public void setDiskSize( Integer diskSize ){
        m_diskSize = diskSize;
    }
    
    public FileAccess []getFileAccesses(){
        return m_fileAccesses;
    }
    public void setFileAccesses( FileAccess []fileAccesses ){
        m_fileAccesses = fileAccesses;
    }
    
    public Linkage []getLinkages(){
        return m_linkages;
    }
    public void setLinkages( Linkage []linkages ){
        m_linkages = linkages;
    }
    
    public Inode getInode(){
        return m_inode;
    }
    public void setInode( Inode inode ){
        m_inode = inode;
    }
    
    public String getIdent(){
        return m_ident;
    }
    public void setIdent( String ident ){
        m_ident = ident;
    }
    
    public String getCategory(){
        return m_category;
    }
    public void setCategory( String category ){
        m_category = category;
    }
    
    public String getFstype(){
        return m_fstype;
    }
    public void setFstype( String fstype ){
        m_fstype = fstype;
    }
    
    public Node convertToXML( Document parent ){
        Element fileNode = parent.createElement( IDMEF_File.ELEMENT_NAME );
        Element node = parent.createElement( CHILD_ELEMENT_NAME );
        int len = 0;
        if( m_name != null ){
            node.setNodeValue( m_name );
            fileNode.appendChild( node );
        }
        node = parent.createElement( CHILD_ELEMENT_PATH );
        if( m_path != null ){
            node.setNodeValue( m_path );
            fileNode.appendChild( node );
        }
        node = parent.createElement( CHILD_ELEMENT_CREATE_TIME );
        if( m_createTime != null ){
            node.setNodeValue( IDMEFTime.convertToIDMEFFormat( m_createTime ) );
            fileNode.appendChild( node );
        }
        node = parent.createElement( CHILD_ELEMENT_MODIFY_TIME );
        if( m_modifyTime != null ){
            node.setNodeValue( IDMEFTime.convertToIDMEFFormat( m_modifyTime ) );
            fileNode.appendChild( node );
        }
        node = parent.createElement( CHILD_ELEMENT_ACCESS_TIME );
        if( m_accessTime != null ){
            node.setNodeValue( IDMEFTime.convertToIDMEFFormat( m_accessTime ) );
            fileNode.appendChild( node );
        }
        node = parent.createElement( CHILD_ELEMENT_DATA_SIZE );
        if( m_dataSize != null ){
            node.setNodeValue( m_dataSize.toString() );
            fileNode.appendChild( node );
        }
        node = parent.createElement( CHILD_ELEMENT_DISK_SIZE );
        if( m_diskSize != null ){
            node.setNodeValue( m_diskSize.toString() );
            fileNode.appendChild( node );
        }
        
        len = m_fileAccesses.length;
        for( int i = 0; i < len; i++ ){
            fileNode.appendChild( m_fileAccesses[ i ].convertToXML( parent ) );
        }
        
        len = m_linkages.length;
        for( int i = 0; i < len; i++ ){
            fileNode.appendChild( m_linkages[ i ].convertToXML( parent ) );
        }
        
        if( m_inode != null ){
            fileNode.appendChild( m_inode.convertToXML( parent ) );
        }
        
        if( m_ident != null ){
            fileNode.setAttribute( ATTRIBUTE_IDENT, m_ident );
        }
        if( m_category != null ){
            fileNode.setAttribute( ATTRIBUTE_CATEGORY, m_category );
        }
        if( m_fstype != null ){
            fileNode.setAttribute( ATTRIBUTE_FSTYPE, m_fstype );
        }
        return fileNode;   
    }
    
    
    private String m_name;
    private String m_path;
    private Date m_createTime;
    private Date m_modifyTime;
    private Date m_accessTime;
    private Integer m_dataSize;
    private Integer m_diskSize;
    private FileAccess m_fileAccesses[];
    private Linkage m_linkages[];
    private Inode m_inode;
    private String m_ident = "0";
    private String m_category;
    private String m_fstype;
}