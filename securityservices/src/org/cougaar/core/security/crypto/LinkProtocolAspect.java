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

import org.cougaar.core.service.LoggingService;
import org.cougaar.mts.base.DestinationLink;
import org.cougaar.mts.base.DestinationLinkDelegateImplBase;
import org.cougaar.mts.base.LoopbackLinkProtocol;
import org.cougaar.mts.std.SSLRMILinkProtocol;
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
  private LoggingService _log;
  public void load() {
    super.load();
    _log = (LoggingService)
      getServiceBroker().getService(this, LoggingService.class, null);
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

  public Object getReverseDelegate(Object object, Class type) {
    if (_log.isDebugEnabled()) {
      _log.debug("ReverseDelegate " + object
                 + " type " + type.getName());
    }
    if (type == DestinationLink.class) {
      DestinationLink link = (DestinationLink) object;
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
      int ret = 0;
      boolean drop = false;
      String targetAddress = message.getTarget().toAddress();
      String originatorAddress = message.getOriginator().toAddress();

      if (super.getProtocolClass().equals(LoopbackLinkProtocol.class)) {
        ret = super.cost(message);
      }
      else if (super.getProtocolClass().equals(RMILinkProtocol.class)) {
        // check policy
      }      
      else if (super.getProtocolClass().equals(SSLRMILinkProtocol.class)) {
      }
      else {
        // HTTP?
        ret = super.cost(message);
      }

      if (_log.isDebugEnabled()) {
        String s = " ["
          + originatorAddress + " -> "
          + targetAddress + "  - cost: " + ret
          + " - " + super.getProtocolClass().getName() + "]";
        if (drop == true) {
          s = "Dropping " + message + s;
        }
        else {
          if (ret == Integer.MAX_VALUE) {
            s = super.getProtocolClass().getName() +
              " cannot send message to " + targetAddress;
          }
          else {
            s = "OK" + s;
          }
        }
        _log.debug(s);
      }
      return ret;
    }

  }
}
