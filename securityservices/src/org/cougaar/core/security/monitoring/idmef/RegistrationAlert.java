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
package org.cougaar.core.security.monitoring.idmef;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.CreateTime;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;

import java.io.Serializable;

/**
 * Registration subclasses Alert, and is used to distinguish
 * the difference been an Alert message and a Registration message
 * avoiding the need to determine the message type via the AdditionalData
 * object.
 */
public class RegistrationAlert extends Alert implements Registration,Serializable{
    
  private String Type=null;
  private int operation_type=-1;
  private String AgentName;
  /**
   * Creates a message for a sensor to register its capabilities.
   * Can only be create through IdmefMessageFactory
   */
  RegistrationAlert( Analyzer analyzer,
		     Source []sources,
		     Target []targets,
		     Classification []capabilities,
		     AdditionalData []data,
		     String ident,int operationtype,String type,String agentName){
    super( analyzer, 
	   new CreateTime(), 
	   null,  // detection time
	   null,  // don't think we need AnalyzerTime
	   sources, // sources
	   targets, // targets
	   capabilities,
	   null,    // assessment 
	   data, 
	   ident );
    this.operation_type=operationtype;
    this.Type=type;
    this.AgentName=agentName;
  }
    
  /**
   * Creates an empty message for a sensor to register its capabilities.
   * Can only be create through IdmefMessageFactory
   */
  RegistrationAlert(){
    super();
    this.operation_type=IdmefMessageFactory.newregistration;
  }
  
  public int getOperation_type() {
    return operation_type;
  }
  public String  getType() {
    return this.Type;
  }
  public void setType(String type) {
    this.Type=type;
  }
  
    public String  getAgentName() {
    return this.AgentName;
  }
}
