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
 
 
 
 
 
 
 
 


package org.cougaar.core.security.access;

// Cougaar core services
import org.cougaar.core.mts.Message;
import org.cougaar.core.security.acl.trust.TrustSet;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class MessageWithTrust
  extends Message
{
  private Message message=null;

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
    buf.append("MessageWithTrust: ");

    if(message!=null) {
      buf.append("[" + message.getClass().getName() + "]");
      buf.append(" " + message.getOriginator().toAddress() + "->" + message.getTarget().toAddress());
      buf.append(message.toString());
    }
    else {
      buf.append("messsage was NULL:");
    }
    return buf.toString();
  }
  
  

}
