/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
 *  All Rights Reserved
 * </copyright>
 */


/*
 * Created on May 30, 2003
 *
 *
 */
package org.cougaar.core.security.test.blackboard;


import java.io.Serializable;
import java.util.Collection;

import edu.jhuapl.idmef.Analyzer;


/**
 * Queries the blackboard for OrgActivity objects every X seconds.  The time
 * interval is changed according to the OperatingMode by detecting changes in
 * the operating mode through a subscription.   If plugin gets any OrgActivity
 * objects from a blackboard query an IDMEF Alert is created and published to
 * the Blackboard.
 *
 * @author ttschampel
 */
public class MaliciousBlackboardPlugin extends AbstractBlackboardPlugin {
    /**
     * DOCUMENT ME!
     */
    public void load() {
        super.load();
        setPluginName("MaliciousBlackboardPlugin");
    }


    /**
     * Query for org activities and create new IDMEF Event during failure
     */
    protected void queryBlackboard() {
        Collection orgActivities = getBlackboardService().query(this.orgActivityPredicate);
        if (orgActivities.size() > 0) {
            if (logging.isInfoEnabled()) {
                logging.info(
                    "******************************************Found :"
                    + orgActivities.size() + " org activities");
            }

            this.createIDMEFEvent(new MaliciousBlackboardPluginAnalyzer(), "Was able to access OrgActivity object");
            this.totalRuns++;
            this.failures++;
        }else{
        	this.successes++;
        }

       

    }

    public class MaliciousBlackboardPluginAnalyzer extends Analyzer implements Serializable {
        public MaliciousBlackboardPluginAnalyzer() {
            this.setAnalyzerid(pluginName);

        }
    }
}
