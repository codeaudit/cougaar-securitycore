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


package org.cougaar.core.security.crypto;

import java.security.PrivilegedAction;
import java.security.AccessController;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.mts.base.DestinationLink;
import org.cougaar.mts.base.DestinationLinkDelegateImplBase;
import org.cougaar.mts.base.RMILinkProtocol;
import org.cougaar.mts.base.StandardAspect;
import org.cougaar.mts.std.AttributedMessage;

/**
 * Intercept the "cost()" call to each of the LinkProtocol's.
 *
 * The interface between the DestinationQueue and the DestinationLink asks
 * each LinkProtocol for the "cost" to send to an Agent and then picks
 * the smallest cost. The LinkProtocols use this call to lookup the Agent's
 * address in the WP. If Agent address is not available, it returns a cost
 * of "infinite". If all the DestinationLinks have "infinite" cost,
 * the message is retried later. The retry is silent.

 * We do the check for the RMI policy at this point
 */
public class LinkProtocolAspect
  extends StandardAspect
{
  private static final String HTTP_PROTOCOL
    = "org.cougaar.core.security.mts.HTTPLinkProtocol";
  private static final int COST_DELTA = 2000;
  private LoggingService _log;
  private CryptoPolicyService _cps;


  public void load() {
    super.load();
    final ServiceBroker sb = getServiceBroker();
    _log = (LoggingService) sb.getService(this, LoggingService.class, null);
    AccessController.doPrivileged(new PrivilegedAction() {
        public Object run() {
          _cps = (CryptoPolicyService) 
            sb.getService(this, CryptoPolicyService.class, null);
          return null;
        }
      });
    if (_cps == null) {
      _log.error("Unable to get crypto policy service");
      throw new RuntimeException("No crypto policy service");
    }
    _log.debug("load completed");
  }

  public Object getDelegate(Object delegatee, Class type) {
    if (_log.isDebugEnabled()) {
      _log.debug("Delegatee " + delegatee
                 + " type " + type.getName());
    }
    if (type == DestinationLink.class) {
      DestinationLink link = (DestinationLink) delegatee;
      return new ProtectedDestinationLink(link);
    } else {
      return null;
    }
  }

  private class ProtectedDestinationLink
    extends DestinationLinkDelegateImplBase
  {

    ProtectedDestinationLink(DestinationLink delegatee) {
      super(delegatee);
    }


    /**
     * This method returns a simple measure of the cost of sending the
     * given message via the associated transport. Only called during
     * processing of messages in DestinationQueueImpl. */
    public int cost(AttributedMessage message) {
      if (!super.getProtocolClass().equals(RMILinkProtocol.class)
          && !super.getProtocolClass().getName().equals(HTTP_PROTOCOL)) {
        return super.cost(message);
      }

      int cost = super.cost(message);
      if (cost == Integer.MAX_VALUE) { return cost; }

      String source = message.getOriginator().toAddress();
      String target = message.getTarget().toAddress();

      SecureMethodParam smp = _cps.getSendPolicy(source, target);
      if (_log.isDebugEnabled()) {
        _log.debug("Policy = " + smp);
      }

      if (smp.secureMethod != SecureMethodParam.PLAIN) {
        if (_log.isDebugEnabled()) {
          _log.debug("Boosting cost by " + COST_DELTA);
        }
        return cost + COST_DELTA;
      } else {
        return cost;
      }
    }      
  }
}
