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


/**
 * Plugin sends relay with the session key in it to the persistence manager
 *
 * @author ttschampel
 * @version $Revision: 1.2 $
 */
public class SessionKeySenderPlugin extends ComponentPlugin {
    /** Plugin name */
    private static final String pluginName = "SessionKeySenderPlugin";
    private UIDService uidService;
    private LoggingService logging;
    private ThreadService threadService;

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

        RelaySessionKey.getInstance().addPlugin(this.getAgentIdentifier()
                                                    .getAddress(), this);
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
    protected void sendSessionKey(Collection keyCollection, String pmAgent) {
        if (logging.isDebugEnabled()) {
            logging.debug("Relaying session key....");
        }

        MessageAddress source = this.getAgentIdentifier();
        MessageAddress target = MessageAddress.getMessageAddress(pmAgent);
        SharedDataRelay sdr = new SharedDataRelay(uidService.nextUID(), source,
                target, keyCollection, null);
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
                logging.debug("Published Session key relay");
            }
        }
    }
}
