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

package org.cougaar.core.security.services.wp;

import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.Component;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceProvider;
import org.cougaar.core.node.NodeControlService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.wp.WhitePagesProtectionService;
import org.cougaar.util.GenericStateModelAdapter;

/**
 * Advertives the <code>WhitePagesProtectionService</code> in the root
 * <code>ServiceBroker</code>  Add to each node using:
 * Node.AgentManager.Agent.WPProtect(HIGH) =
 * org.cougaar.core.security.access.WPProtectionComponent
 *
 * @author mabrams
 */
public class WPProtectionComponent extends GenericStateModelAdapter implements Component {
  private ServiceBroker sb;
  private ServiceBroker rootsb;
  private LoggingService logger;
  private ProtectSP protectSP;

  /**
   * sets the binding site
   *
   * @param bs the <code>BindingSite</code>
   */
  public void setBindingSite(BindingSite bs) {
    this.sb = bs.getServiceBroker();
  }


  /**
   * sets the logging service
   *
   * @param logger the <code>LoggingService</code>
   */
  public void setLoggingService(LoggingService logger) {
    this.logger = logger;
  }


  /**
   * Advertises the <code>WhitePagesProtectionService</code> in the root
   * <code>ServiceBroker</code> since the WPServer can be configured to run in
   * a regular agent instead of the NodeAgent.
   *
   * @throws RuntimeException
   */
  public void load() {
    super.load();

    if (logger.isDebugEnabled()) {
      logger.debug("Loading test protect");
    }

    // get the node-level service broker
    NodeControlService ncs = (NodeControlService) sb.getService(this, NodeControlService.class, null);
    if (ncs == null) {
      throw new RuntimeException("NodeControlService is null");
    }

    sb.releaseService(this, NodeControlService.class, ncs);
    rootsb = ncs.getRootServiceBroker();

    // advertize our service
    protectSP = new ProtectSP();
    rootsb.addService(WhitePagesProtectionService.class, protectSP);

    if (logger.isInfoEnabled()) {
      logger.info("Loaded white pages protection service");
    }
  }


  /**
   * Unloads the <code>WhitePagesProtectionService</code>
   */
  public void unload() {
    super.unload();

    // revoke our service
    if (protectSP != null) {
      rootsb.revokeService(WhitePagesProtectionService.class, protectSP);
      protectSP = null;
    }

    if (logger != null) {
      sb.releaseService(this, LoggingService.class, logger);
      logger = null;
    }
  }

  private class ProtectSP implements ServiceProvider {
    WhitePagesProtectionServiceImpl impl = new WhitePagesProtectionServiceImpl(sb);

    public Object getService(ServiceBroker sb, Object requestor, Class serviceClass) {
      if (WhitePagesProtectionService.class.isAssignableFrom(serviceClass)) {
        return impl;
      } else {
        return null;
      }
    }


    public void releaseService(ServiceBroker sb, Object requestor, Class serviceClass, Object service) {
    }
  }
}
