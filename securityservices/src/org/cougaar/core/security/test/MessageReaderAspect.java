/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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
 * Created on Feb 11, 2004, 10:55 AM
 */
 
package org.cougaar.core.security.test;

import java.util.HashSet;

import org.cougaar.core.blackboard.Directive;
import org.cougaar.core.blackboard.DirectiveMessage;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.mts.base.StandardAspect;
import org.cougaar.mts.base.ReceiveLink;
import org.cougaar.mts.base.ReceiveLinkDelegateImplBase;
import org.cougaar.mts.base.SendLink;
import org.cougaar.mts.base.SendLinkDelegateImplBase;
import org.cougaar.mts.std.AttributedMessage;
import org.cougaar.planning.ldm.plan.Task;


public class MessageReaderAspect extends StandardAspect {

  private LoggingService log;
  private HashSet        existingEvents = new HashSet();

  public void load() {
    super.load();
    log = (LoggingService)getServiceBroker().getService(this, LoggingService.class,
                                                               null);
    
  }
  
   public Object getDelegate(Object delegatee, Class type) {
     if (type == SendLink.class) {
       SendLink sln = (SendLink) delegatee;
       return new InternalMessageWriter(sln);
     } 
     else if (type == ReceiveLink.class) {
       ReceiveLink rln = (ReceiveLink) delegatee;
       return new InternalMessageReader(rln);
     }
     else {
       if(log.isDebugEnabled()){
         log.debug(" Received delegate in Message ReaderAspect  of type:"+ delegatee.getClass().getName()); 
       }
       return null;
     }
   }
  
  public class InternalMessageReader extends ReceiveLinkDelegateImplBase { 
     public InternalMessageReader(ReceiveLink link) {
      super(link);
    }

    public MessageAttributes deliverMessage(AttributedMessage msg){
      return super.deliverMessage(msg);
        //      return msg;
    }
  }

  public class InternalMessageWriter extends SendLinkDelegateImplBase {
    
    public InternalMessageWriter(SendLink link) {
      super(link);
    }

    public void sendMessage(AttributedMessage msg) {
      String sender   = msg.getOriginator().toString();
      String receiver = msg.getTarget().toString();
      String type     = msg.getRawMessage().getClass().getName();
      if (msg.getRawMessage() instanceof DirectiveMessage) {
        DirectiveMessage dm = (DirectiveMessage) msg.getRawMessage();
        Directive [] directives = dm.getDirectives();
        for (int i = 0; i < directives.length; i++) {
          if (directives[i] instanceof Task) {
            Task t = (Task) directives[i];
            logEvent(sender, receiver, t.getVerb().toString());
          } else {
            logEvent(sender, receiver, directives[i].getClass().getName());
          }
        }
      } else  {
        logEvent(sender, receiver, type);
        log.debug("Interception: Additional info: " 
                       + msg.getRawMessage().toString());
      }
      super.sendMessage(msg);
    }
  }


  public void logEvent(String sender, 
                       String receiver,
                       String type)
  {
    Event  e        = new Event(sender, receiver, type);
    if (!existingEvents.contains(e)) {
      log.debug("Interception: message :" + sender + " : -> : " +
                    receiver + ": type : " + type);
      existingEvents.add(e);
    }
  }

  private class Event 
  {
    public String _sender;
    public String _receiver;
    public String _type;

    public boolean equals(Object o)
    {
      if (! (o instanceof Event)) {
        return false;
      } else {
        Event e = (Event) o;
        return _sender.equals(e._sender) &&
          _receiver.equals(e._receiver) &&
          _type.equals(e._type);
      }
    }

    public int hashCode()
    {
      int s = _sender.hashCode();
      int r = _receiver.hashCode();
      int t = _type.hashCode();
      return s + r + t;
    }

    public Event(String s, String r, String t)
    {
      _sender = s;
      _receiver = r;
      _type = t;
    }
  }
}
