/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
 *  All Rights Reserved
 * </copyright>
 */


/*
 * Created on Jun 3, 2003
 *
 *
 */
package org.cougaar.core.security.test.blackboard;


import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.LoggingService;
import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.Timer;
import java.util.TimerTask;


/**
 * DOCUMENT ME!
 *
 * @author ttschampel
 */
public class TestPlugin extends ComponentPlugin {
    LoggingService logging = null;
    private long sleepInterval = 10000;
    UnaryPredicate orgActivityPredicate = new UnaryPredicate() {
            public boolean execute(Object o) {
                return o instanceof OrgActivity;
            }
        };

    /**
     * DOCUMENT ME!
     *
     * @param service DOCUMENT ME!
     */
    public void setLoggingService(LoggingService service) {
        this.logging = service;
    }


    /**
     * DOCUMENT ME!
     */
    public void setupSubscriptions() {
        logging.error(this.getAgentIdentifier() + "TEST PLUGIN");
        QueryTimerTask queryTimer = new QueryTimerTask();
        Timer timer = new Timer();
        timer.schedule(queryTimer, sleepInterval, sleepInterval);

    }


    /**
     * DOCUMENT ME!
     */
    public void execute() {
    }

    public class QueryTimerTask extends TimerTask {
        public void run() {
            getBlackboardService().openTransaction();
            Collection orgActivities = getBlackboardService().query(orgActivityPredicate);
            if (orgActivities.size() > 0) {
                System.err.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!Found :"
                    + orgActivities.size() + " org activities");
            }

            getBlackboardService().closeTransaction();
        }
    }
}
