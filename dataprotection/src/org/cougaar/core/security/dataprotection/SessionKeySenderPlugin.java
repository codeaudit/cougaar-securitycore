/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
 *  All Rights Reserved
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

import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;


/**
 * Plugin sends relay with the session key in it to the persistence manager
 *
 * @author ttschampel
 * @version $Revision: 1.3 $
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

        // mainly UIDService could be null
        if (uidService != null && threadService != null && getBlackboardService() != null) {
          servicesReady();
        }
        else {
          ServiceAvailableListener listener = new ServiceAvailableListener() {
            public void serviceAvailable(ServiceAvailableEvent ae) {
              Class sc = ae.getService();
              if (sc == ThreadService.class && threadService == null) {
                threadService = (ThreadService)
                  getServiceBroker().getService(this, 
                    ThreadService.class, null);
              }
              // uidservice and blackboard service is set explicitly by ComponentPlugin
              if (threadService != null && uidService != null && getBlackboardService() != null) {
                servicesReady();
              }
            }    
          };
          getServiceBroker().addServiceListener(listener);
        }
    }


    private void servicesReady() {
        String agent = this.getAgentIdentifier().getAddress();
        synchronized (_pluginMap) {
          _pluginMap.put(agent, this);
        }
        processKeyCache(agent);
    }
/*
        RelaySessionKey.getInstance().addPlugin(this.getAgentIdentifier()
                                                    .getAddress(), this);
*/
        

    private void processKeyCache(String agent) {
      if (logging.isDebugEnabled()) {
        logging.debug("processing keys cached");
      }
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
          synchronized (_keyCache) {
            List list = (List)_keyCache.get(agent);
            if (list == null) {
              list = new ArrayList();
              _keyCache.put(agent, list);
            }
            list.add(sdr);
          }
        }
     }

     protected void sendSessionKey(SharedDataRelay sdr) {
        if (logging.isDebugEnabled()) {
            logging.debug("Relaying session key...." + sdr.getSource());
            DataProtectionKeyCollection keyCollection =
              (DataProtectionKeyCollection)sdr.getContent();
            logging.debug("key timestamp " + keyCollection.getTimestamp());
        }

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
            sdr.setUID(uidService.nextUID());
            getBlackboardService().openTransaction();
            getBlackboardService().publishAdd(sdr);
            getBlackboardService().closeTransactionDontReset();
            if (logging.isDebugEnabled()) {
                logging.debug("Published Session key relay " + sdr.getSource());
            }
        }
    }
}
