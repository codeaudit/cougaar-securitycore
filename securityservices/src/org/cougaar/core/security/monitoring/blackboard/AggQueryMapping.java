/*
 * <copyright>
 *  Copyright 1997-2003 CougaarSoftware Inc
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

import java.util.Hashtable;
import java.util.ArrayList;
import java.io.Serializable;



public class AggQueryMapping implements Publishable, Serializable {
  private ArrayList queryList;
  private UID parentQuery_uid;
  private UID originator_uid;
  private int _total;
  private int _currentcount;
  private double _rate;
  
  public AggQueryMapping (UID originatorUID, UID parentqueryUID, ArrayList query) {
    this.originator_uid=originatorUID;
    this.parentQuery_uid=parentqueryUID;
    this.queryList=query;
    _total=0;
    _currentcount=0;
    _rate=0.0;
    
  }

  public UID getOriginatorUID() {
    return this.originator_uid;
  }
  
   public UID getParentQueryUID() {
    return this.parentQuery_uid;
  }
  
  public ArrayList getQueryList() {
    return this.queryList;
  }
  
  public void setQueryList(ArrayList querylist) {
    this.queryList=querylist;
  }
  
  
  public void setCurrentCount(int currentCount) {
    _currentcount=currentCount;
  }
  
  public void setTotal(int total) {
    _total=total; 
  }
  
  public void setRate(double rate) {
    _rate=rate; 
  }
  /*
    Gives number of event received in a window period specified in AggregateResponseplugin
  */
  public int getCurrentCount(){
    return _currentcount;
  }

  public int getTotal() {
    return _total;
  }
  
  public  double getRate() {
    return _rate;
  }

  public boolean isPersistable() {
    return true;
  }
  
  public String toString() {
    StringBuffer buff=new StringBuffer();
    buff.append("Originators id:"+ originator_uid.toString()+"\n");
    buff.append("parent id:"+ parentQuery_uid.toString()+"\n");
    buff.append("child are :\n");
    for(int i=0;i<queryList.size();i++) {
      buff.append(queryList.get(i).toString()+"\n");
    }
    buff.append("Count="+_currentcount+"\n");
    buff.append("Total="+_total+"\n");
    buff.append("Rate="+_rate+"\n");
    return buff.toString();
  }
}
