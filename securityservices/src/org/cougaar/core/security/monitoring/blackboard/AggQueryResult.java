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

import java.io.Serializable;

public class AggQueryResult implements Publishable, Serializable {

  private UID _uid;
  private int _total;
  private int _currentcount;
  private double _rate;
  
  public AggQueryResult ( UID uid ) {
    _uid=uid;
    _total=0;
    _currentcount=0;
    _rate=0.0;
  }
  public AggQueryResult ( UID uid ,int currentcount, int  total ) {
    _uid=uid;
    _total=total;
    _currentcount=currentcount;
    _rate=0.0;
  } 
  
  public AggQueryResult ( int currentcount, int  total , double rate) {
    _uid=null;
    _total=total;
    _currentcount=currentcount;
    _rate=rate;
  } 
  public AggQueryResult ( UID uid, int currentcount, int  total , double rate) {
    _uid=uid;
    _total=total;
    _currentcount=currentcount;
    _rate=rate;
  } 
  
  public UID getUID() {
    return _uid;
  }
  
  public void setCurrentCount(int currentCount) {
    _currentcount=currentCount;
  }
  
  public void setTotal(int total) {
    _total=total; 
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

  public void resetCurrentCount(){
    _currentcount=0;
  }

  public void incrementCurrentCount() {
    _currentcount++;
    _total++;
  }


  public void setRate(double rate) {
    _rate=rate;
  }

  public double getRate() {
    return _rate;
  }
  public boolean isPersistable() {
    return true;
  }

  public String toString() {
    StringBuffer buff=new StringBuffer();
    buff.append("Query id:"+ _uid.toString()+"\n");
    buff.append("Count="+_currentcount+"\n");
    buff.append("Total="+_total+"\n");
    return buff.toString();
  }
  
}
