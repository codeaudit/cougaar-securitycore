/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
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
package org.cougaar.core.security.test;

import org.cougaar.mts.std.AttributedMessage;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.mts.base.DestinationLink;
import org.cougaar.mts.base.DestinationLinkDelegateImplBase;
import org.cougaar.mts.base.ReceiveLink;
import org.cougaar.mts.base.ReceiveLinkDelegateImplBase;
import org.cougaar.mts.base.SendQueue;
import org.cougaar.mts.base.SendQueueDelegateImplBase;
import org.cougaar.core.mts.SimpleMessageAttributes;
import org.cougaar.mts.base.StandardAspect;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

public class MessageInterceptorAspect extends StandardAspect {

  private static SendQueueDelegate interceptor;
  private static Vector messageMods = new Vector();
  private static Hashtable modMap = new Hashtable();

  public interface SendQueueInterceptor {
    public boolean execute(AttributedMessage msg);
  }

  public synchronized static void addInterceptor(String name, 
                                                 SendQueueInterceptor obj) {
    if (modMap.containsKey(name)) {
      messageMods.remove(modMap.get(name));
    } // end of if (modMap.contains(name))
    
    messageMods.add(obj);
    modMap.put(name, obj);
  }

  public static Enumeration getInterceptorNames() {
    return modMap.keys();
  }

  public synchronized static void deleteInterceptor(String name) {
    if (modMap.containsKey(name)) {
      messageMods.remove(modMap.get(name));
      modMap.remove(name);
    } // end of if (modMap.containsKey(name))
  }

  public static void sendMessage(AttributedMessage msg) {
    interceptor.sendMessage(msg);
  }

  public synchronized Object getDelegate(Object delegate, Class type) {
    if (type == SendQueue.class) {
      interceptor = new SendQueueDelegate((SendQueue) delegate);
      return interceptor;
    } // end of if (type == SendQueue.type)
    return null;
  }

  public synchronized Object getReverseDelegate(Object delegate, Class type) {
    if (type == ReceiveLink.class) {
      return new ReceiveLinkDelegate((ReceiveLink) delegate);
    } // end of if (type == ReceiveLink.class)
    return null;
  }

  private class ReceiveLinkDelegate extends ReceiveLinkDelegateImplBase {
    public ReceiveLinkDelegate(ReceiveLink link) {
      super(link);
    }

    public MessageAttributes deliverMessage(AttributedMessage msg) {
      Enumeration en = messageMods.elements();
      boolean sendIt = true;

      while (en.hasMoreElements()) {
        SendQueueInterceptor sqi = (SendQueueInterceptor) en.nextElement();
        if (!sqi.execute(msg)) {
          sendIt = false;
        } // end of if (sqi.execute(msg))
      } // end of while (en.hasMoreElements())
      if (sendIt) {
        return super.deliverMessage(msg);
      }

      // dump it
      MessageAttributes meta = new SimpleMessageAttributes();
      meta.setAttribute(MessageAttributes.DELIVERY_ATTRIBUTE,
                        MessageAttributes.DELIVERY_STATUS_DELIVERED);
      return meta;
    }
  }

  private class SendQueueDelegate extends SendQueueDelegateImplBase {
    public SendQueueDelegate(SendQueue queue) {
      super(queue);
    }

    public synchronized void sendMessage(AttributedMessage msg) {
      Enumeration en = messageMods.elements();
      boolean sendIt = true;

      while (en.hasMoreElements()) {
        SendQueueInterceptor sqi = (SendQueueInterceptor) en.nextElement();
        if (!sqi.execute(msg)) {
          sendIt = false;
        } // end of if (sqi.execute(msg))
      } // end of while (en.hasMoreElements())
      if (sendIt) {
        super.sendMessage(msg);
      } // end of if (sendIt)
    }
  }
}
