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



package org.cougaar.core.security.test.wp;


import java.net.InetAddress;
import java.net.URI;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.wp.AddressEntry;
import org.cougaar.core.service.wp.WhitePagesService;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.util.UnaryPredicate;


/**
 * Test Plugin.  Will take parameter, should be "BAD" or "GOOD" Bad  = this
 * plugin will try to bind a fake agent "FAKEAGENT" to the WP. Good = this
 * plugin will try to rebind itself normally.
 *
 * @author ttschampel
 */
public class WPTestPlugin extends ComponentPlugin {
  private LoggingService logging;
  boolean good = false;
  private WhitePagesService wp;
  private IncrementalSubscription testSubs = null;
  private UnaryPredicate testPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof Task) {
        Task t = (Task) o;
        return (t.getVerb() != null) && t.getVerb().toString().equals("WPTEST");

      }

      return false;
    }
  };

  /**
   * Set Logging Service
   *
   * @param s LogginService
   */
  public void setLoggingService(LoggingService s) {
    this.logging = s;

  }


  /**
   * Get parameter
   */
  public void load() {
    super.load();
    Collection parameters = this.getParameters();
    Iterator iterator = parameters.iterator();
    if (iterator.hasNext()) {
      String parameter = (String) iterator.next();
      if (parameter.toUpperCase().equals("GOOD")) {
        good = true;
      }
    } else {
      if (logging.isWarnEnabled()) {
        logging.warn("WPTestPlugin has not parameter, so will act as malicious plugin");
      }
    }

    if (logging.isDebugEnabled()) {
      logging.debug("WPTEstPlugin acting as a Legitimate Plugin:" + good);
    }
  }


  /**
   * Sets the WhitePagesService
   *
   * @param s WhitePagesService
   */
  public void setWhitePagesService(WhitePagesService s) {
    this.wp = s;

  }


  /**
   * Just get info from wp of other agent, then try to rebind my entry in wp.
   */
  protected void setupSubscriptions() {
    if (logging.isDebugEnabled()) {
      logging.debug("Setting up WPTestPlugin");
    }

    testSubs = (IncrementalSubscription) getBlackboardService().subscribe(testPredicate);
  }


  /**
   * Blank implementation
   */
  protected void execute() {
    Enumeration enumeration = testSubs.getAddedList();
    while (enumeration.hasMoreElements()) {
      Task t = (Task) enumeration.nextElement();
      long timeout = 100000;

      //try to rebind as self
      try {
        InetAddress localAddr = InetAddress.getLocalHost();
        String localHost = localAddr.getHostName();
        NodeIdentificationService nodeIdService = (NodeIdentificationService) this.getServiceBroker().getService(this, NodeIdentificationService.class, null);

        URI nodeURI = null;
        nodeURI = URI.create("node://" + localHost + "/" + nodeIdService.getMessageAddress().getAddress());

        AddressEntry nodeEntry = null;
        if (good) {
          nodeEntry = AddressEntry.getAddressEntry(this.getAgentIdentifier().getAddress(), "topology", nodeURI);
          if (logging.isDebugEnabled()) {
            logging.debug("Trying to rebind agent to same location");
          }
        } else {
          //try to re-bind ca agent here
          if (logging.isDebugEnabled()) {
            logging.debug("Trying to rebind the caAgent to this node");
          }

          nodeEntry = AddressEntry.getAddressEntry("caAgent", "topology", nodeURI);
        }

        wp.rebind(nodeEntry, timeout);
      } catch (Exception exception) {
        if (logging.isErrorEnabled()) {
          logging.error("Error rebinding ", exception);
        }
      }

      getBlackboardService().publishRemove(t);
    }
  }
}
