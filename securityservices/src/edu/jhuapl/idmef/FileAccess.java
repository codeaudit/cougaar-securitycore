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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.NamedNodeMap;

/**
 *  The FileAccess class represents the access permissions on a file.
 *  The representation is intended to be usefule across operating
 *  systems.
 *
 *  The FileAccess class is composed of two aggregate classes, as shown
 *  below.
 *
 *              +--------------+
 *              |  FileAccess  |
 *              +--------------+            +------------+
 *              |              |<>----------|   UserId   |
 *              |              |            +------------+
 *              |              |       1..* +------------+
 *              |              |<>----------| permission |
 *              |              |            +------------+
 *              +--------------+
 *
 *
 *  The aggregate classes that make up FileAccess are:
 *
 *  UserId
 *     Exactly one.  The user (or group) to which these permissions
 *     apply.  The value of the "type" attribute must be "user-privs",
 *     "group-privs", or "other-privs" as appropriate.  Other values for
 *     "type" MUST NOT be used in this context.
 *
 * permission
 *     One or more.  STRING.  Level of access allowed.  Recommended
 *     values are "noAccess", "read", "write", "execute", "delete",
 *     "executeAs", "changePermissions", and "takeOwnership".  The
 *     "changePermissions" and "takeOwnership" strings represent those
 *     concepts in Windows.  On Unix, the owner of the file always has
 *     "changePermissions" access, even if no other access is allowed for
 *     that user.  "Full Control" in Windows is represented by
 *     enumerating the permissions it contains.  The "executeAs" string
 *     represents the set-user-id and set-group-id features in Unix.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     <!ELEMENT FileAccess                    (
 *         UserId, permission+
 *       )>
 *
 * @since IDMEF Message v1.0
 */
public class FileAccess implements XMLSerializable {
    public static String ELEMENT_NAME = "FileAccess";
    public static String CHILD_ELEMENT_PERMISSION = "permission";
    
    public FileAccess( UserId userId, String []permissions ){
        m_userId = userId;
        m_permissions = permissions;
    }
    
    public FileAccess( Node node ){
        Node userIdNode = XMLUtils.GetNodeForName( node, UserId.ELEMENT_NAME );
        m_userId = new UserId( userIdNode );
        NodeList childList = node.getChildNodes();
        int len = childList.getLength();
        ArrayList permissions = new ArrayList();
        for( int i = 0; i < len; i++ ){
            permissions.add( childList.item( i ).getNodeValue() );
        }
        m_permissions = ( String [] )permissions.toArray();
    }
    
    public UserId getUserId(){
        return m_userId;
    }
    public void setUserId( UserId userId ){
        m_userId = userId;
    }
    
    public String []getPermissions(){
        return m_permissions;
    }
    public void setPermissions( String []permissions ){
        m_permissions = permissions;
    }
    
    public Node convertToXML( Document parent ){
        Element fileAccessNode = parent.createElement( ELEMENT_NAME );    
        fileAccessNode.appendChild( m_userId.convertToXML( parent ) );
        int len = m_permissions.length;
        for( int i = 0; i < len; i++ ){
            Element pNode = parent.createElement( CHILD_ELEMENT_PERMISSION );
            pNode.setNodeValue( m_permissions[ i ] );
            fileAccessNode.appendChild( pNode );
        }
        return fileAccessNode;
    }
    
    private UserId m_userId;
    private String m_permissions[];
}
