/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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

package org.cougaar.core.security.policy.enforcers.init;

import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.policy.enforcers.WPEnforcer;
import org.cougaar.core.service.LoggingService;

public class WPEnforcerPlugin extends ComponentPlugin {

  private LoggingService _log;
  private WPEnforcer _wp;

    /*
     * The WPEnforcerPlugin is responsible for initializing 
     * a WPEnforcer component which will check white board access.  
     * During this early testing phase it will also continually check access 
     * and write the answers in the log.
     */
  protected void setupSubscriptions()
  {
    try {
      BindingSite bs = getBindingSite();
      ServiceBroker sb = bs.getServiceBroker();

      _log = (LoggingService) sb.getService(this,
                                            LoggingService.class,
                                            null);

      // Create the WP Enforcer
      getBlackboardService().closeTransactionDontReset();        
      _wp = new WPEnforcer(sb);
      _wp.registerEnforcer();
      getBlackboardService().openTransaction();
    } catch (Exception e) {
      _log.fatal(".WPEnforcerPlugin: Error initializing agent policy plugin",
                 e);
    }
  }

    /*
     * After setupSubscriptions there is really nothing for this
     * component to do.
     */

  static private boolean bigLoopRunning=false;

  synchronized protected void execute()
  {
    _log.debug("WPEnforcerPlugin.execute");
    if (!bigLoopRunning) {
      bigLoopRunning=true;
      bigLoop();
    }
  }

  private void bigLoop()
  {
    (new Thread() {
        public void run() {
          boolean interrupt = false;
          while (!interrupt) {
            String agent = "testBBPolicyAgent";
            _log.debug("Add is allowed = " +
                       _wp.isActionAuthorized(agent, agent, "Add"));
            _log.debug("Remove is allowed = " +
                       _wp.isActionAuthorized(agent, agent, "Remove"));
            _log.debug("Change is allowed = " +
                       _wp.isActionAuthorized(agent, agent, "Change"));
            try {
              Thread.sleep(10000);
            } catch (Exception e) {
              interrupt = true;
            }
          }
        }
      }).start();
  }

}
