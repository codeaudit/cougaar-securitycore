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




import org.cougaar.core.util.XMLizable;
import org.cougaar.core.util.XMLize;
/**
 * Registration subclasses Alert, and is used to distinguish
 * the difference been an Alert message and a Registration message
 * avoiding the need to determine the message type via the AdditionalData
 * object.
 */
public class ConsolidatedCapabilities extends Alert implements AgentRegistration, XMLizable{
    
  private  String Type =null;
  private String AgentName=null;
  /**
   * Creates a message for an analyzer to register its capabilities.
   * Can only be create through IdmefMessageFactory
   */
  ConsolidatedCapabilities( Analyzer analyzer,
			    Source []sources,
			    Target []targets,
			    Classification []capabilities,
			    AdditionalData []data,
			    String ident,String type,String agentName ){
    super( analyzer, 
	   null, 
	   null,  // detection time
	   null,  // don't think we need AnalyzerTime
	   sources, // sources
	   targets, // targets
	   capabilities,
	   null,    // assessment 
	   data, 
	   ident );  // ident 
    this.Type=type;
    this.AgentName=agentName;
  }
  public org.w3c.dom.Element getXML(org.w3c.dom.Document document) {
     return XMLize.getPlanObjectXML(this, document);
  }
   
  public String toString() {
    StringBuffer buff=new StringBuffer();
    buff.append(" ConsolidatedCapabilities are :\n");
    if(getAnalyzer()!=null)
      buff.append(" Analyzer :"+getAnalyzer().getAnalyzerid());
    if(getClassifications()!=null) {
      Classification classs[]=getClassifications();
      Classification classi=null;
      buff.append(" Classifications are :\n");
      for( int i=0;i<classs.length;i++) {
	classi=classs[i];
	buff.append("Classification Name:"+classi.getName());
      }
    }
     return buff.toString();
  }
 
  public void setType(String type) {
    this.Type=type;
  }
   public String getType() {
    return this.Type;
  }

  public String getAgentName() {
    return this.AgentName;
  } 
  

}
