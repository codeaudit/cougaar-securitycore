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




package com.nai.security.monitoring.util;

 
import java.util.Vector;
import org.cougaar.glm.ldm.asset.Organization ;

public class SendCapabilitiesObj implements java.io.Serializable
{
  public Organization org;
  public String Type;
  public Vector Services;
  
  public SendCapabilitiesObj(Organization orgn,String ty,Vector Capabilities)
  {
    this.org=orgn;
    this.Type=ty;
    this.Services=Capabilities;
    
  }
  public String toString()
  {
    StringBuffer buff=new StringBuffer();
    buff.append("Organization in send capabilities is ::"+org.toString()+" / ");
    buff.append("type is :"+Type+" / ");
    if(Services!=null)   {
      for(int i=0;i<  Services.size();i++)
	buff.append((String)Services.elementAt(i)+":");
    }
    return buff.toString();
  }
  
}
