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

package org.cougaar.core.security.test;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.SimpleMessageAttributes;
import org.cougaar.mts.base.ReceiveLink;
import org.cougaar.mts.base.ReceiveLinkDelegateImplBase;
import org.cougaar.mts.base.SendQueue;
import org.cougaar.mts.base.SendQueueDelegateImplBase;
import org.cougaar.mts.base.StandardAspect;
import org.cougaar.mts.std.AttributedMessage;

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
