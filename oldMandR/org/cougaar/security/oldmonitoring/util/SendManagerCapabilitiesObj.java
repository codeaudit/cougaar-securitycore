
  
  /*
 * <copyright>
 *  Copyright 1997-2001 Network Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */

 package org.cougaar.core.security.oldmonitoring.util;

 
import java.util.Vector;
import org.cougaar.glm.ldm.asset.Organization;

public class SendManagerCapabilitiesObj implements java.io.Serializable
{
  public Organization org;
  public Vector Sensors;
  public Vector Analyzers;
  public SendManagerCapabilitiesObj(Organization orgn,Vector Sens,Vector analyz)
  {
    this.org=orgn;
    this.Sensors=Sens;
    this.Analyzers=analyz;
  }
  public SendManagerCapabilitiesObj()
  {
    this.Sensors=new Vector();
    this.Analyzers=new Vector();
  }
  public String toString()
  {
    StringBuffer buff=new StringBuffer();
    buff.append("Organization :"+org.getUID().getOwner());
    buff.append("\n Sensors ---\n");
    for(int i=0;i<Sensors.size();i++)   {
      buff.append(i+":"+(String)Sensors.elementAt(i)+"\n");
    }
    buff.append("\n Analyzer ---\n");
    for(int i=0;i<Analyzers.size();i++)  {
      buff.append(i+":"+(String)Analyzers.elementAt(i)+"\n");
    }
    return buff.toString();
    
  }
  
}

