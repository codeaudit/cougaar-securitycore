/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
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

import org.cougaar.core.blackboard.Publishable;
import org.cougaar.core.util.UID;

import java.io.Serializable;
import java.util.ArrayList;



public class QueryMapping implements Publishable, Serializable {
  private ArrayList queryList;
  private ArrayList localsensors;
  private UID relay_uid;
  private boolean alreadypublished=false;  
  public QueryMapping (UID id, ArrayList query) {
    this.relay_uid=id;
    this.queryList=query;
  }

  public UID getRelayUID() {
    return this.relay_uid;
  }
  
  public ArrayList getQueryList() {
    return this.queryList;
  }
  
  public void setQueryList(ArrayList querylist) {
    this.queryList=querylist;
  }
   public void setResultPublished(boolean published) {
    this.alreadypublished=published;
  }

   public boolean isPersistable() {
    return true;
  } 
  public boolean isResultPublished() {
    return alreadypublished;
  }
  public ArrayList getLocalSensors() {
    return localsensors;
  }
  
  public void setLocalSensors(ArrayList sensorlist){
    this.localsensors=sensorlist;
  }
}
