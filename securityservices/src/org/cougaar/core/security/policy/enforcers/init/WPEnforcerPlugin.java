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
            String agent1 = "RearEnclaveCrlManager";
            String agent2 = "testBBPolicyAgent";
            _log.debug("WPUpdateOk(" + agent1 +", " +  agent1 + ") = "
                       + _wp.WPUpdateOk(agent1, agent1));
            _log.debug("WPUpdateOk(" + agent1 +", " +  agent2 + ") = "
                       + _wp.WPUpdateOk(agent1, agent2));
            _log.debug("WPForwardOk(" + agent1 +", " +  agent2 + ") = "
                       + _wp.WPUpdateOk(agent1, agent2));
            _log.debug("WPLookupOk(" + agent1 + ") = " 
                       + _wp.WPLookupOk(agent1));
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
