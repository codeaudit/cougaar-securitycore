/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.monitoring.event;

import java.util.Date;

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
  
  public FailureEvent(String classification, String source, String target, 
    String reason, String reasonId, String data, String dataId, Date detectTime){
    this(classification, source, target, reason, reasonId, data, dataId);
    m_detectTime.setIdmefDate(detectTime);
    m_detectTime.setNtpstamp(detectTime);
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

  public String toString(){
    StringBuffer sb = new StringBuffer(128);
    sb.append("[classification: " + getClassification() + "]\n");
    sb.append("[detection time: " + m_detectTime.getidmefDate() + "]\n");
    sb.append("[source: " + getSource() + "]\n");
    sb.append("[target: " + getTarget() + "]\n");
    sb.append("[reason: " + getReason() + "]\n");
    sb.append("[data: " + getData() + "]\n");
    return sb.toString();
  }
}
