/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software Inc.
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

import org.cougaar.lib.aggagent.query.AggregationQuery;
import org.cougaar.core.util.UID;



public class AggregationDrillDownQuery implements DrillDownQuery,java.io.Serializable
{
  //AggregationQuery query ;
  String _query;
  AggregationType _type;
  boolean _wantdetails=false;
  boolean _persistent=true;
  UID originators_uid=null;
  
/*
  public AggregationDrillDownQuery (AggregationQuery iQuery, 
  AggregationType iType, 
  boolean iwantDetails) {
    
  _query=iQuery;
  _type=iType;
  _wantdetails=iwantDetails;
  }
  
  public AggregationDrillDownQuery (AggregationQuery iQuery, 
  AggregationType iType ) {
    
  _query=iQuery;
  _type=iType;
  }
*/
  public AggregationDrillDownQuery (UID originatorUID,String  query, 
                                    AggregationType iType ) {
    originators_uid=originatorUID;
    _query=query;
    _type=iType;
  }
  public AggregationDrillDownQuery (String  query, 
                                    AggregationType iType ) {
    
    _query=query;
    _type=iType;
  }
  public AggregationDrillDownQuery (String  query, 
                                    AggregationType iType,
                                    boolean persistent  ) {
    
    _query=query;
    _type=iType;
    _persistent=persistent;
  }
  /**
   */
  /*
    public AggregationQuery getAggQuery() {
    return _query;
    }
  */

  public String getAggQuery() {
    return _query;
  }
  /**
   */
  public AggregationType getAggregationType() {
    return _type;
  }
  /**
   */
  public boolean wantDetails() {
    return _wantdetails;
  }

  public void setOriginatorsUID(UID originatorUID) {
    originators_uid=originatorUID;
  }
   public UID getOriginatorsUID() {
    return originators_uid;
  }
}
