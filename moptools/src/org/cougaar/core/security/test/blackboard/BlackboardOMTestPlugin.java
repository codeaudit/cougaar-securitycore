/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
 *  All Rights Reserved
 * </copyright>
 */


package org.cougaar.core.security.test.blackboard;


import org.cougaar.core.adaptivity.InterAgentOperatingMode;
import org.cougaar.core.adaptivity.InterAgentOperatingModePolicy;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.OMCThruRange;
import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.core.adaptivity.OperatingModeImpl;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ServiceUserPlugin;
import org.cougaar.core.service.UIDService;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.Iterator;


/**
 * Publishes an Operating Mode with a default value of 1000 msec for the
 * security blackboard test plugins.
 */
public class BlackboardOMTestPlugin extends ServiceUserPlugin {
    /** the name of the operating mode BlacboardTest plugins listen to */
    public static final String BLACKBOARD_TEST_OM = "BlackboardOMTestPlugin.BLACKBOARD_OPERATING_MODE";
    private static final Class[] requiredServices = { UIDService.class };
    private IncrementalSubscription blackboardOMSubscription;
    private IncrementalSubscription blackboardOMPSubscription;

    //private InterAgentOperatingMode remoteOM;
    private OperatingMode blackboardOM;

    //private LoggingService logger;
    private UIDService uidService;
    
    /**
     * Predicate subscribing to OperatingModes for BlackboardTest plugins
     */
    private UnaryPredicate remoteOMPredicate = new UnaryPredicate() {
            public boolean execute(Object o) {
                if (o instanceof OperatingMode) {
                    OperatingMode om = (OperatingMode) o;
                    String omName = om.getName();
                    if (BLACKBOARD_TEST_OM.equals(omName)) {
                        return true;
                    }
                }
                return false;
            }
        };

	/**
	 * Predicate subscribing to Operating mode policy
	 */
    private UnaryPredicate remoteOMPPredicate = new UnaryPredicate() {
            public boolean execute(Object o) {
                if (o instanceof InterAgentOperatingModePolicy) {
                    return true;
                }
                return false;
            }
        };

    /**
     * Creates a new BlackboardOMTestPlugin object.
     */
    public BlackboardOMTestPlugin() {
        super(requiredServices);
    }

    /**
     * Sets up subscriptions to operating modes and policies for BalckboardTest plugins
     */
    public void setupSubscriptions() {
    	// create a new OM that takes any integer (from 1 to MAX_VALUE) and defaults to 60000
        blackboardOM = new OperatingModeImpl(BLACKBOARD_TEST_OM,
                new OMCRangeList(new OMCThruRange(1, Integer.MAX_VALUE)),
                new Integer(60 * 1000));
        
        // initialize the subscriptions
        blackboardOMSubscription = (IncrementalSubscription) blackboard
            .subscribe(remoteOMPredicate);
        blackboardOMPSubscription = (IncrementalSubscription) blackboard
            .subscribe(remoteOMPPredicate);
        // publish the default OM
        blackboard.publishAdd(blackboardOM);
        if (haveServices()) {
            logger.debug("##### obtained services #####");
        }
    }


    /**
     * Executed anytime an operating mode or operating mode policy is changed
     */
    public void execute() {
        if (blackboardOMSubscription.hasChanged()) {
            Collection oms = blackboardOMSubscription.getChangedCollection();
            Iterator i = oms.iterator();
            OperatingMode om = null;
            if ((oms != null) && (oms.size() > 0)) {
                Object o = i.next();
                om = (OperatingMode) o;
                logger.debug(om.getName() + " has changed to " + om.getValue()
                    + ".");
                if (o instanceof InterAgentOperatingMode) {
                    InterAgentOperatingMode iaom = (InterAgentOperatingMode) o;
                    logger.debug(
                        "this is an inter agent operating mode with source: "
                        + iaom.getSource());
                }
            } else {
                logger.error(
                    "blackboardOMSubscription.getChangedCollection() returned collection of size 0!");
            }
        }

        if (blackboardOMPSubscription.hasChanged()) {
            Collection oms = blackboardOMPSubscription.getChangedCollection();
            Iterator i = oms.iterator();
            InterAgentOperatingModePolicy iaomp = null;

            if ((oms != null) && (oms.size() > 0)) {
                iaomp = (InterAgentOperatingModePolicy) i.next();
                logger.debug(
                    "received inter agent operating mode policy from: "
                    + iaomp.getSource());
            } else {
                logger.error(
                    "blackboardOMPSubscription.getChangedCollection() returned collection of size 0!");
            }
        }
    }


    private boolean haveServices() {
        if (uidService != null) {
            return true;
        }

        if (acquireServices()) {
            ServiceBroker sb = getServiceBroker();
            uidService = (UIDService) sb.getService(this, UIDService.class, null);
            return true;
        }

        return false;
    }
}
