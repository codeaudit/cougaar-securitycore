/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
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

package org.cougaar.core.security.securebootstrap;

import java.security.Permission;
import java.security.Principal;
import java.util.Date;


public class BootstrapEvent {
  public String classification=null;
  public Date detecttime=null;
  public Principal [] principals=null;
  public String subjectStackTrace=null;
  public static final String SecurityAlarm="SecurityManagerAlarm";
  public static final String JarVerificationAlarm="JarVerificationAlarm";
 
  public BootstrapEvent(String type,
			Date detectTime,
			Principal [] subjectsprincipal,
			String stackinfo) {
    classification=type;
    detecttime=detectTime;
    principals=subjectsprincipal;
    subjectStackTrace=stackinfo;
   
    
  }
  public BootstrapEvent(){
  }
  public String toString() {
    StringBuffer buffer=new StringBuffer();
    buffer.append("Type :"+classification +"\n");
    if(detecttime!=null)
      buffer.append("Time :"+detecttime.toString() +"\n"); 
    if(principals!=null){
      buffer.append("Principals  :"+principals.toString() +"\n"); 
    }
    buffer.append("Stack Trace :"+subjectStackTrace +"\n");
    return buffer.toString();
  }
			
}
