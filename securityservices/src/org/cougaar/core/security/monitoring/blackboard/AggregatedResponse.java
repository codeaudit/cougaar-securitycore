/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software
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

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;

public class AggregatedResponse implements java.io.Serializable {

  private List results;
  
  public AggregatedResponse (List list) {
    this.results=list;
  }
/*
  This method returns an Iterator on the list of Events.It never returns a NULL.
  If List is Null it creates and emptyList and retrns an Iterator on an emptylist.
 */
  public Iterator getEvents() {
    Iterator iterator=null;
    if(results!=null) {
      iterator=results.iterator();
      return iterator;
    }
    List list=new ArrayList();
    return list.iterator();
  }
  public String toString() {
    Iterator iterator=null;
    StringBuffer buff=new StringBuffer();
    if(results!=null) {
      iterator=results.iterator();
      int counter=1;
      buff.append(" Consolidated Events in AggregatedResponse :");
      while(iterator.hasNext()) {
        buff.append(counter+"\n");
        buff.append(iterator.next().toString()+"\n");
        counter++;
      }
    }
    else {
      buff.append("No Consolidated Events  in AggregatedResponse ");
    }
    return buff.toString();
  }
}
