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

import edu.jhuapl.idmef.IDMEF_Message;

// Cougaar core services
import org.cougaar.core.util.UniqueObject;
import org.cougaar.core.util.UID;
import org.cougaar.core.blackboard.Publishable;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.planning.servlet.XMLize;

/** Event implementation
 */
public class ConsolidatedEventImpl implements ConsolidatedEvent
{
  protected IDMEF_Message theMessage;
  protected MessageAddress theAgent;
  protected UID parentUID;

  public ConsolidatedEventImpl(UID aUID)
    {
      setparentUID(aUID);
    }

  public ConsolidatedEventImpl(UID aUID,
                               MessageAddress aSource,
                               IDMEF_Message aMessage)
    {
      setparentUID(aUID);
      setSource(aSource);
      setEvent(aMessage);
    }

  
  private void setEvent(IDMEF_Message aMessage)
    {
      theMessage = aMessage;
    }
  private void setSource(MessageAddress aSource) {
    theAgent = aSource;
  }

  public IDMEF_Message getEvent()
    {
      return theMessage;
    }

  public MessageAddress getSource() {
    return theAgent;
  }

 
  public void setparentUID(UID uid) {
    parentUID = uid;
  }
  
  public UID getparentUID() { 
    return parentUID;
  }

  /** ******************************************************************
   *  Publishable interface
   */

  public boolean isPersistable() {
    return true;
  }

  /** ******************************************************************
   *
   */

  public String toString() {
    StringBuffer buff=new StringBuffer("Consolidated Event : \n");
    if(theAgent!=null){
      buff.append(" Source :"+ theAgent+"\n");
    }
    if(parentUID!=null) {
       buff.append(" Parent id :"+ parentUID+"\n");
    }
    String s = null;
    if (theMessage != null) {
      s = theMessage.toString();
      buff.append("Message : "+ s+ "\n");
    }


    return buff.toString();
  }
  
  public String getDocument() {
    return toString();
  }
  
  public org.w3c.dom.Element getXML(org.w3c.dom.Document document) {
    return XMLize.getPlanObjectXML(this, document);
  }
  
}
