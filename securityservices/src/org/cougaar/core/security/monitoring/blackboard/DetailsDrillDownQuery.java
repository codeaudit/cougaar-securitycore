/*
 * <copyright>
 *  Copyright 1997-2003 CougaarSoftware Inc.
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



package org.cougaar.core.security.monitoring.blackboard;

import org.cougaar.core.util.UID;

public class DetailsDrillDownQuery implements java.io.Serializable {

  private UID originator_UID=null;
  private UID parentQuery_UID=null;
  
  public DetailsDrillDownQuery(UID originatorID, UID parentQueryID) {
    originator_UID=originatorID;
    parentQuery_UID=parentQueryID;
    
  }

  public UID getOriginatorUID(){
    return originator_UID;
  }
  public UID getParentUID(){
    return parentQuery_UID;
  }

  public String toString() {
    StringBuffer buff=new StringBuffer(" DetailsDrillDownQuery: \n");
    if(originator_UID==null) {
      buff.append("Originator UID : NULL \n");
    }
    else {
      buff.append("Originator UID :"+originator_UID + "\n");
    }
    if(parentQuery_UID ==null) {
      buff.append("Parent UID : NULL \n");
    }
    else {
      buff.append("Parent  UID :"+parentQuery_UID + "\n");
    }
    return buff.toString();
      
  }
} 
