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
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.UIDService;
import java.util.Collection;
import java.util.TimerTask;
import java.util.ArrayList;
import java.util.HashMap;


/**
 * Plugin sends relay with the session key in it to the persistence manager
 *
 * @author ttschampel
 * @version $Revision: 1.4 $
 */
public class SessionKeySenderPlugin extends ComponentPlugin {
    /** Plugin name */
    private static final String pluginName = "SessionKeySenderPlugin";
    private UIDService uidService;
    private LoggingService logging;
    private ThreadService threadService;
    //private static HashMap _pluginMap = new HashMap();
    private static SessionKeySenderPlugin _senderPlugin = null;
    private static ArrayList _keyCache = new ArrayList();

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

//        _pluginMap.put(this.getAgentIdentifier().getAddress(), this);
        _senderPlugin = this;
        processKeyCache();
/*
        RelaySessionKey.getInstance().addPlugin(this.getAgentIdentifier()
                                                    .getAddress(), this);
*/
        
    }

    private void processKeyCache() {
      logging.debug("processing keys cached");
      synchronized (_keyCache) {
        for (int i = 0; i < _keyCache.size(); i++) {
          SharedDataRelay sdr = (SharedDataRelay)_keyCache.get(i);
          sendSessionKey(sdr);
        } // for
        _keyCache.clear();
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

/*
        SessionKeySenderPlugin plugin = (SessionKeySenderPlugin)
          _pluginMap.get(agent);
        if (plugin != null) {
          plugin.sendSessionKey(sdr);
*/   
        if (_senderPlugin != null) {
          _senderPlugin.sendSessionKey(sdr);
        }        
        else {
          _keyCache.add(sdr);
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
		threadService.schedule(timerTask,1);
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
