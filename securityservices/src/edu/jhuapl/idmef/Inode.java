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
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 *  The Inode class is used to represent the additional information
 *  contained in a Unix file system i-node.
 *
 *  The Inode class is composed of six aggregate classes, as shown 
 *  below.
 *
 *              +--------------+
 *              |    Inode     |
 *              +--------------+            +----------------+
 *              |              |<>----------|   change-time  |
 *              |              |            +----------------+
 *              |              |            +----------------+
 *              |              |<>----------|     number     |
 *              |              |            +----------------+
 *              |              |            +----------------+
 *              |              |<>----------|  major-device  |
 *              |              |            +----------------+
 *              |              |            +----------------+
 *              |              |<>----------|  minor-device  |
 *              |              |            +----------------+
 *              |              |            +----------------+
 *              |              |<>----------| c-major-device |
 *              |              |            +----------------+
 *              |              |            +----------------+
 *              |              |<>----------| c-minor-device |
 *              |              |            +----------------+
 *              +--------------+
 *
 *  The aggregate classes that make up Inode are:
 *
 *  change-time
 *     Zero or one.  DATETIME.  The time of the last inode change, given
 *     by the st_ctime element of "struct stat".
 *
 *  number
 *     Zero or one.  INTEGER.  The inode number.
 *
 *  major-device
 *     Zero or one.  INTEGER.  The major device number of the device the
 *     file resides on.
 *
 *  minor-device
 *     Zero or one.  INTEGER.  The minor device number of the device the
 *     file resides on.
 *
 *  c-major-device
 *     Zero or one.  INTEGER.  The major device of the file itself, if it
 *     is a character special device.
 *
 *  c-minor-device
 *     Zero or one.  INTEGER.  The minor device of the file itself, if it
 *     is a character special device.
 *
 *  Note that <number>, <major-device>, and <minor-device> must be given
 *  together, and the <c-major-device> and <c-minor-device> must be given
 *  together.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     <!ELEMENT Inode                         (
 *         change-time?, (number, major-device, minor-device)?,
 *         (c-major-device, c-minor-device)?
 *       )>
 *
 * @since IDMEF Message v1.0
 */
public class Inode implements XMLSerializable {
    
    public static String ELEMENT_NAME = "Inode";
    public static String CHILD_ELEMENT_CHANGE_TIME = "change-time";
    public static String CHILD_ELEMENT_NUMBER = "number";
    public static String CHILD_ELEMENT_MAJOR_DEVICE = "major-device";
    public static String CHILD_ELEMENT_MINOR_DEVICE = "minor-device";
    public static String CHILD_ELEMENT_C_MAJOR_DEVICE = "c-major-device";
    public static String CHILD_ELEMENT_C_MINOR_DEVICE = "c-minor-device";
    
    public Inode( Date changeTime, Integer number, Integer majorDevice, Integer minorDevice ){
        m_changeTime = changeTime;
        m_number = number;
        m_majorDevice = majorDevice;
        m_minorDevice = minorDevice;
    }
    
    public Inode( Date changeTime, Integer cMajorDevice, Integer cMinorDevice ){
        m_changeTime = changeTime;
        m_cMajorDevice = cMajorDevice;
        m_cMinorDevice = cMinorDevice;
    }
    
    public Inode( Node node ){
        Node numberNode = XMLUtils.GetNodeForName( node, 
                                CHILD_ELEMENT_NUMBER );
        Node majorDeviceNode = XMLUtils.GetNodeForName( node, 
                                    CHILD_ELEMENT_MAJOR_DEVICE );
        Node minorDeviceNode = XMLUtils.GetNodeForName( node, 
                                    CHILD_ELEMENT_MINOR_DEVICE );
        Node cMajorDeviceNode = XMLUtils.GetNodeForName( node, 
                                    CHILD_ELEMENT_C_MAJOR_DEVICE );
        Node cMinorDeviceNode = XMLUtils.GetNodeForName( node, 
                                    CHILD_ELEMENT_C_MINOR_DEVICE );
        Node changeTimeNode = XMLUtils.GetNodeForName( node,
                                    CHILD_ELEMENT_CHANGE_TIME );
        SimpleDateFormat formatter = 
                new SimpleDateFormat ("yyyy-MM-dd'T'hh:mm:ss'Z'");
        
        if( changeTimeNode != null ){
            try{
                m_changeTime = formatter.parse( changeTimeNode.getNodeValue() );
            }
            catch( ParseException pe ){
                pe.printStackTrace();
            }    
        }
        
        if( ( numberNode != null ) &&
            ( majorDeviceNode != null ) &&
            ( minorDeviceNode != null ) ){
            
            m_number = new Integer( numberNode.getNodeValue() );
            m_majorDevice = new Integer( majorDeviceNode.getNodeValue() );
            m_minorDevice = new Integer( minorDeviceNode.getNodeValue() );
        }
        else if( ( cMajorDeviceNode != null ) && 
                 ( cMinorDeviceNode != null ) ){
            m_majorDevice = new Integer( cMajorDeviceNode.getNodeValue() );
            m_minorDevice = new Integer( cMinorDeviceNode.getNodeValue() );        
        }
    }
    
    public Date getChangeTime(){
        return m_changeTime;
    }
    public void setChangeTime( Date changeTime ){
        m_changeTime = changeTime;
    }
    
    public Integer getNumber(){
        return m_number;
    }
    public void setNumber( Integer number ){
        m_number = number;
    }
    
    public Integer getMajorDevice(){
        return m_majorDevice;
    }
    public void setMajorDevice( Integer majorDevice ){
        m_majorDevice = majorDevice;
    }
    
    public Integer getMinorDevice(){
        return m_minorDevice;
    }
    public void setMinorDevice( Integer minorDevice ){
        m_minorDevice = minorDevice;
    }
    
    public Integer getCMajorDevice(){
        return m_cMajorDevice;
    }
    public void setCMajorDevice( Integer cMajorDevice ){
        m_cMajorDevice = cMajorDevice;
    }
    
    public Integer getCMinorDevice(){
        return m_cMinorDevice;
    }
    public void setCMinorDevice( Integer cMinorDevice ){
        m_cMinorDevice = cMinorDevice;
    }
   
    public Node convertToXML( Document parent ){
    
        Element inodeNode = parent.createElement( ELEMENT_NAME );

        Element childNode = null;
        
        if( m_changeTime != null ){
            childNode = parent.createElement( CHILD_ELEMENT_CHANGE_TIME );
            childNode.setNodeValue( IDMEFTime.convertToIDMEFFormat( m_changeTime ) );
            inodeNode.appendChild( childNode );
        }
        if( ( m_number != null ) &&
            ( m_majorDevice != null ) &&
            ( m_minorDevice != null ) ){
            childNode = parent.createElement( CHILD_ELEMENT_NUMBER );
            childNode.setNodeValue( m_number.toString() );
            inodeNode.appendChild( childNode );

            childNode = parent.createElement( CHILD_ELEMENT_MAJOR_DEVICE );
            childNode.setNodeValue( m_majorDevice.toString() );
            inodeNode.appendChild( childNode );

            childNode = parent.createElement( CHILD_ELEMENT_MINOR_DEVICE );
            childNode.setNodeValue( m_minorDevice.toString() );
            inodeNode.appendChild( childNode );
        }
        else if( ( m_cMajorDevice != null ) &&
                 ( m_cMinorDevice != null ) ){
            childNode = parent.createElement( CHILD_ELEMENT_C_MAJOR_DEVICE );
            childNode.setNodeValue( m_cMajorDevice.toString() );
            inodeNode.appendChild( childNode );
        
            childNode = parent.createElement( CHILD_ELEMENT_C_MINOR_DEVICE );
            childNode.setNodeValue( m_cMinorDevice.toString() );
            inodeNode.appendChild( childNode );
        }
        return inodeNode;
    }
    
    private Date m_changeTime;
    private Integer m_number;
    private Integer m_majorDevice;
    private Integer m_minorDevice;
    private Integer m_cMajorDevice;
    private Integer m_cMinorDevice;
     
}