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

package org.cougaar.core.security.monitoring.event;

import edu.jhuapl.idmef.DetectTime;

/**
 * A base representation of an Failure Event that could occurs in the cougaar
 * services, agents, or nodes.   This data structure represent events that are
 * described by the source and target of the event, the classification, the reason, 
 * and data supporting that reason.  Any events that requires additional information
 * should not use extend this class. 
 *
 * @see MessageFailureEvent
 */
public class FailureEvent implements java.io.Serializable {
  private String m_source;
  private String m_target;
  private String m_reason;
  private String m_data;
  private String m_classification;
  private String m_reasonId;
  private String m_dataId;
  private DetectTime m_detectTime;
  
  public FailureEvent(String classification, String source, String target, 
    String reason, String reasonId, String data, String dataId){
    m_classification = classification;
    m_source = source;
    m_target = target;
    m_reason = reason;
    m_reasonId = reasonId;
    m_data = data;    
    m_dataId = dataId;
    m_detectTime = new DetectTime();
  }
  
  /**
   * get the originator of the event
   */
  public String getSource(){
    return m_source;
  }
  
  /**
   * get the target of the event
   */
  public String getTarget(){
    return m_target;
  }
  
  /**
   * get the reason or "code" for the event
   */
  public String getReason(){
    return m_reason;
  }
  
  /**
   * get the data of the event
   */
  public String getData(){
    return m_data;
  }
   
  /**
   * get the detection time of the event
   */
  public DetectTime getDetectTime(){
    return m_detectTime;
  }
 
  /**
   * get the reason identifier for the event.  this identifier is the meaning
   * attribute of an AdditionalData object
   */
  public String getReasonIdentifier(){
    return m_reasonId;
  }
  
  /**
   * get the data identifier for the event.  this identifier is the meaning
   * attribute of an AdditionalData object
   */
  public String getDataIdentifier(){
    return m_dataId;
  }
  
  /**
   * get the classification of the event
   */
  public String getClassification(){
    return m_classification;
  }
}