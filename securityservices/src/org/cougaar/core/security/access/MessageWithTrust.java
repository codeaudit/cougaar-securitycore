/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 * Created on May 10, 2002, 12:42 PM
 */

package org.cougaar.core.security.access;

import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;

import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.services.acl.*;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import  org.cougaar.core.security.acl.trust.TrustSet;

import java.io.*;

public class MessageWithTrust extends Message {
  private static boolean debug=false;
  private static SecurityPropertiesService secprop = null;
  private Message message=null;
  private static String SECURE_PROPERTY = 
  "org.cougaar.message.transport.secure";

  static {
     secprop = SecurityServiceProvider.getSecurityProperties(null);

    String db = secprop.getProperty(secprop.TRANSPORT_DEBUG);
    if (db!=null &&
	(db.equalsIgnoreCase("true") || db.indexOf("security")>=0) ) {
      debug=true;
    }
  }
  private TrustSet[] trustset = null;
  public MessageWithTrust() {
    super();
  }
  public MessageWithTrust(Message aMessage) {
    super(aMessage.getOriginator(),aMessage.getTarget(),aMessage.getContentsId());
    this.message=aMessage;
  }
   
  public  MessageWithTrust(Message aMessage, TrustSet[] ats)  {
    super(aMessage.getOriginator(),aMessage.getTarget(),aMessage.getContentsId());
    this.message=aMessage;
    //super(aMessage);
    trustset = new TrustSet[ats.length];
    for(int i=0; i<ats.length; i++){
      trustset[i]=ats[i];
    }
    if(debug) {
      System.out.println("Mesage access control: Building Message with trust");
    }
    
  }
  public Message getMessage() {
    return (Message)this.message;
  } 
  public TrustSet[] getTrusts() {
    if(trustset!=null)
      return trustset;
    else 
      return null;
  }
   /**
     * Public accessor method for the trust set
     * @return the trust set associated with the encapsulated message
     */
    public TrustSet getTrustSet() {
      if(trustset!=null)
	return trustset[0];
      else 
	return null;
    }

    /**
     * Public accessor for an array of trust sets. Used with a Directive
     * Message payload.
     * @return an array of trust sets 
     */
    public TrustSet[] getTrustSets() { 
      return trustset; 
    }

    /**
     * Public modifier method for a signle trust set.
     * @return the trust set associates with the encapsulate message
     */
    public void setTrustSet(TrustSet set) { 
	if(this.trustset == null)
	    this.trustset = new TrustSet[1];
	this.trustset[0] = set;
    }
    
    /**
     * Public modifier method for an array of trust sets. This should be
     * used when the payload is a DirectiveMessage but can be extended to
     * other types of Messages as well.
     * @return an array of trust sets for a message with segmented contents
     */
    public void setTrustSets(TrustSet set[]) {
	this.trustset = new TrustSet[set.length];
	for(int i = 0; i < set.length; i++)
	    this.trustset[i] = set[i];
    }
  
  public void writeExternal(ObjectOutput out) throws IOException {
    if(debug)
      System.out.println(" write external of Message with trust called :");
    out.writeObject(message);
    int length=0;
    if(trustset!=null) {
      length=trustset.length;
      out.writeInt(length);
      TrustSet set=null;
      for(int i=0;i<length;i++) {
	set=trustset[i];
	out.writeObject(set);
      }
    }
    else {
      out.writeInt(length);
    }
  }

  public void readExternal(ObjectInput in) throws ClassNotFoundException, IOException {
    if(debug)
      System.out.println(" read external called of message with trust  :");
    message=(Message)in.readObject();
    int length=0;
    length=in.readInt();
    if(length>0) {
      trustset=new TrustSet[length];
      for(int i=0;i<length;i++) {
	trustset[i]=(TrustSet)in.readObject();
      }
    }
    
  }
  public String toString() {
    StringBuffer buf=new StringBuffer();
    buf.append("MessageWithTrust toString:\n");
    if(message!=null)
      buf.append(message.toString());
    else
      buf.append("messsage was NULL:");
    return buf.toString();
  }
  
  

}
