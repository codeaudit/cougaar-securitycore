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



package org.cougaar.core.security.dataprotection;


import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.util.SharedDataRelay;
import org.cougaar.core.thread.Schedulable;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.UIDService;
import java.util.Collection;
import java.util.TimerTask;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;


/**
 * Plugin sends relay with the session key in it to the persistence manager
 *
 * @author ttschampel
 * @version $Revision: 1.7 $
 */
public class SessionKeySenderPlugin extends ComponentPlugin {
    /** Plugin name */
    private static final String pluginName = "SessionKeySenderPlugin";
    private UIDService uidService;
    private LoggingService logging;
    private ThreadService threadService;
    private static HashMap _pluginMap = new HashMap();
    private static HashMap _keyCache = new HashMap();

    /**
     * Set logging service
     *
     * @param service LoggingService
     */
    public void setLoggingService(LoggingService service) {
        this.logging = service;
    }


    /**
     * Load Thread Service
     */
    public void load() {
        super.load();
        threadService = (ThreadService) this.getServiceBroker().getService(this,
                ThreadService.class, null);
    }


    /**
     * set uid service
     *
     * @param service UIDService
     */
    public void setUIDService(UIDService service) {
        uidService = service;
    }


    /**
     * Blank Implementation
     */
    public void setupSubscriptions() {
        if (logging.isDebugEnabled()) {
            logging.debug(pluginName + " setting up");
        }

        String agent = this.getAgentIdentifier().getAddress();
        _pluginMap.put(agent, this);
        processKeyCache(agent);
/*
        RelaySessionKey.getInstance().addPlugin(this.getAgentIdentifier()
                                                    .getAddress(), this);
*/
        
    }

    private void processKeyCache(String agent) {
      logging.debug("processing keys cached");
      synchronized (_keyCache) {
        List list = (List)_keyCache.get(agent);
        if (list == null)
          return;
        for (int i = 0; i < list.size(); i++) {
          SharedDataRelay sdr = (SharedDataRelay)list.get(i);
          sendSessionKey(sdr);
        } // for
        _keyCache.remove(agent);
      } // sync
    }


    /**
     * Blank execute
     */
    public void execute() {
    }

    /**
     * Send session key via SharedDataRelay
     *
     * @param key SharedDataRelay
     * @param pmAgent PersistenceManager Agent
     */
    public static void sendSessionKey(String agent, Collection keyCollection, String pmAgent) {
        //MessageAddress source = this.getAgentIdentifier();
        MessageAddress source = MessageAddress.getMessageAddress(agent);
        MessageAddress target = MessageAddress.getMessageAddress(pmAgent);

        SharedDataRelay sdr = new SharedDataRelay(null, source,
                target, keyCollection, null);

        SessionKeySenderPlugin plugin = (SessionKeySenderPlugin)
          _pluginMap.get(agent);
        if (plugin != null) {
          plugin.sendSessionKey(sdr);
        }        
        else {
          List list = (List)_keyCache.get(agent);
          if (list == null) {
            list = new ArrayList();
            _keyCache.put(agent, list);
          }
          list.add(sdr);
        }
     }

     protected void sendSessionKey(SharedDataRelay sdr) {
        if (logging.isDebugEnabled()) {
            logging.debug("Relaying session key...." + sdr.getSource());
            DataProtectionKeyCollection keyCollection =
              (DataProtectionKeyCollection)sdr.getContent();
            logging.debug("key timestamp " + keyCollection.getTimestamp());
        }

        sdr.setUID(uidService.nextUID());
        RelayTimerTask timerTask = new RelayTimerTask(sdr);
		    Schedulable sch = threadService.getThread(this, timerTask);
        sch.schedule(1);
        sch.start();
    }

    private class RelayTimerTask extends TimerTask {
        private SharedDataRelay sdr;

        public RelayTimerTask(SharedDataRelay _sdr) {
            sdr = _sdr;
        }

        public void run() {
            //publish relay
            getBlackboardService().openTransaction();
            getBlackboardService().publishAdd(sdr);
            getBlackboardService().closeTransactionDontReset();
            if (logging.isDebugEnabled()) {
                logging.debug("Published Session key relay " + sdr.getSource());
            }
        }
    }
}
