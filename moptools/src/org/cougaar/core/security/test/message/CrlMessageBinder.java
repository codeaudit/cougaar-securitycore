/*
 * <copyright>
 *  Copyright 1997-2004 Cougaar Software, Inc.
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
 * Created on May 08, 2002, 2:42 PM
 */

package org.cougaar.core.security.test.message;

import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.ContainerAPI;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceFilterBinder;
import org.cougaar.core.component.ServiceFilterBinder.FilteringServiceBroker;
import org.cougaar.core.mts.AgentState;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageTransportClient;
import org.cougaar.core.mts.Message;
import org.cougaar.core.relay.RelayDirective;
import org.cougaar.core.relay.RelayDirective.Response;
import org.cougaar.core.blackboard.Directive;
import org.cougaar.core.blackboard.DirectiveMessage;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;
import org.cougaar.core.security.crypto.CRLWrapper;

import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;
import java.util.Iterator;

/**
 * A binder to facilitate the testing of the CRL propagation mechanism.
 * This binder should NOT be used in a production environment.
 */
public class CrlMessageBinder 
  extends ServiceFilterBinder  {

  private static Logger         _log;

  static {
    _log = LoggerFactory.getInstance().createLogger(CrlMessageBinder.class);
  }

  public CrlMessageBinder (BinderFactory bf,Object child) {
    super(bf,child);
  }

  protected ContainerAPI createContainerProxy() {
    return new ServiceFilterContainerProxy();
  }

  protected ServiceBroker createFilteringServiceBroker(ServiceBroker sb) {
    return new CrlServiceBroker(sb);
  }

  /**
   * Enables or disables the queueing of CRLs.
   * If CRLs are queued, the node will not be able to process CRLs.
   */
  public static void queueCrls(boolean enqueue) {
    CrlMessageProxy.queueCrls(enqueue);
  }

  public static boolean getQueueCrls() {
    return CrlMessageProxy.getQueueCrls();
  }

  protected class CrlServiceBroker
    extends FilteringServiceBroker {
    private MessageAddress _agent;

    public CrlServiceBroker(ServiceBroker sb) {
      super(sb);
      _agent = MessageAddress.getMessageAddress(getComponentDescription().getName()); 
    }

    protected Object getServiceProxy(Object service, Class serviceclass, Object client)  {
      if(service instanceof MessageTransportService) {
	if (_log.isDebugEnabled()) {
	  _log.debug("Creating Msg proxy. Requestor:" + client.getClass().getName()
		     + ". Service: " + serviceclass.getName() + " Agent: " + _agent);
	}
      	return new CrlMessageProxy((MessageTransportService)service, client,
				   getServiceBroker(), _agent);
      }
      return null;
    }

    public void releaseService(Object requestor, Class serviceClass, Object service) {
      if(service instanceof MessageTransportService) {
	if (_log.isDebugEnabled()) {
	  _log.debug("releaseService. requestor:" + requestor
		     + " service: " + service + " serviceClass: " +  serviceClass +
		     " agent: " + _agent);
	}
      }
      super.releaseService(requestor, serviceClass, service);
    }

    /** 
     * Called to release the CrlMessageProxy previously constructed by the binder.
     * This method is called before the real service is released.
     **/
    protected void releaseServiceProxy(Object serviceProxy, Object service, Class serviceClass) {
      if(service instanceof MessageTransportService) {
	if (_log.isDebugEnabled()) {
	  _log.debug("releaseServiceProxy. serviceProxy:" + serviceProxy
		     + " service: " + service + " serviceClass: " +  serviceClass +
		     " agent: " + _agent);
	}
      }
      super.releaseServiceProxy(serviceProxy, service, serviceClass);
    }
  }

  protected static class CrlMessageProxy
    implements MessageTransportService, MessageTransportClient {

    private MessageTransportService   mts;
    private Object                    object;
    private ServiceBroker             serviceBroker;
    private MessageTransportClient    mtc;
    private List                      _crlMessages = new ArrayList();
    private MessageAddress            _agent;
    private static boolean            _isCrlQueued = false;
    private static Set                _messageProxies = new HashSet();

    public CrlMessageProxy(MessageTransportService mymts, Object myobj,
			   ServiceBroker sb, MessageAddress agent) {
      this.mts = mymts;
      this.object = myobj;
      this.serviceBroker = sb;
      this._agent = agent;
    }

    /**
     * Enables or disables the queueing of CRLs.
     * If CRLs are queued, the node will not be able to process CRLs.
     */
    public static void queueCrls(boolean enqueue) {
      _isCrlQueued = enqueue;
      if (_log.isDebugEnabled()) {
	_log.debug("queueCrls: " + enqueue);
      }
      if (!_isCrlQueued) {
	synchronized (_messageProxies) {
	  Iterator it = _messageProxies.iterator();
	  while (it.hasNext()) {
	    CrlMessageProxy cmp = (CrlMessageProxy)it.next();
	    cmp.deliverCrlMessages();
	  }
	}
      }
    }

    public static boolean getQueueCrls() {
      return _isCrlQueued;
    }

    private void deliverCrlMessages() {
      // Check if there are messages in the queue. If so, deliver them.
      synchronized(_crlMessages) {
	while (_crlMessages.size() > 0) {
	  Message m = (Message) _crlMessages.remove(0);
	  if (_log.isDebugEnabled()) {
	    _log.debug("Deliver enqueued CRL message: " + m + " for agent " + _agent);
	  }
	  if (mtc != null) {
	    mtc.receiveMessage(m);
	  }
	}
      }
    }

    /***************************************************************************
     * BEGIN MessageTransportService implementation
     */

    /**
     * Send a message to the Message transport layer.
     * 
     * @param message -
     *          The message to send.
     */
    public void sendMessage(Message message) {
      mts.sendMessage(message);
    }

    public void registerClient(MessageTransportClient client) {
      if (mts != null) {
	mtc = client;
	mts.registerClient(this);
	synchronized (_messageProxies) {
	  _messageProxies.add(this);
	}
      }
    }

    public void unregisterClient(MessageTransportClient client) {
      if (mts != null) {
	mts.unregisterClient(this);
	mtc = null;
	synchronized (_messageProxies) {
	  _messageProxies.remove(this);
	}
      }
    }

    public ArrayList flushMessages() {
      ArrayList returndata = null;
      if (mts != null) {
	returndata = mts.flushMessages();
      }
      return returndata;
    }

    public String getIdentifier() {
      String identifier = null;
      if (mts != null) {
	identifier = mts.getIdentifier();
      }
      return identifier;
    }

    public boolean addressKnown(MessageAddress a) {
      boolean addressKnown = false;
      if (mts != null) {
	addressKnown = mts.addressKnown(a);
      }
      return addressKnown;
    }

    public AgentState getAgentState() {
      AgentState as = null;
      if (mts != null) {
	as = mts.getAgentState();
      }
      return as;
    }

    /***************************************************************************
     * END MessageTransportService implementation
     */
    public MessageAddress getMessageAddress() {
      MessageAddress messageaddress = null;
      if (mtc != null) {
	messageaddress = mtc.getMessageAddress();
      }
      return messageaddress;
    }

    public void receiveMessage(Message m) {
      if (mtc == null) {
	_log.warn("Message Transport Client is null for: " + m);
	return;
      }
      if (_log.isDebugEnabled()) {
	_log.debug("receiveMessage: " + getMessageAddress().toString()
		  + " : " + m.toString());
      }
      if (_isCrlQueued && m instanceof DirectiveMessage) {
	Directive directives[] = ((DirectiveMessage)m).getDirectives();
	boolean containsCrlMessage = false;
	boolean containsNonCrlMessage = false;

	if (directives != null) {
	  for (int i = 0 ; i < directives.length ; i++) {
	    Directive d = directives[i];
	    if (d instanceof RelayDirective.Response) {
	      RelayDirective.Response rdr = (RelayDirective.Response) d;
	      if (rdr.getResponse() instanceof CRLWrapper) {
		containsCrlMessage = false;
	      }
	      else {
		containsNonCrlMessage = true;
	      }
	    }
	    else {
	      containsNonCrlMessage = true;
	    }
	  }
	}
	if (containsCrlMessage) {
	  if (containsNonCrlMessage) {
	    if (_log.isWarnEnabled()) {
	      _log.warn("DirectiveMessage contains both CRL and non CRL messages!" + m);
	    }
	  }
	  // Queue messages
	  if (_log.isInfoEnabled()) {
	    _log.info("Queueing CRL message for agent " + _agent);
	  }
	  synchronized(_crlMessages) {
	    _crlMessages.add(m);
	  }
	  return;
	}
      }
      synchronized(_crlMessages) {
	mtc.receiveMessage(m);
      }
    }
  }
}
