/*
 * <copyright>
 *  Copyright 2000-2003 Tim Tschampel
 *  All Rights Reserved
 * </copyright>
 */


package org.cougaar.core.security.monitoring.plugin;


import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.event.BlackboardFailureEvent;
import org.cougaar.core.security.monitoring.publisher.EventPublisher;
import org.cougaar.core.security.monitoring.publisher.IdmefEventPublisher;
import org.cougaar.core.security.util.SharedDataRelay;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.UIDService;

import java.util.Enumeration;


/**
 * Monitors the Blackboard for Blackboard Compromise.
 *
 * @author ttschampel
 */
public class BlackboardCompromiseSensorPlugin extends SensorPlugin {
    private static final String pluginName = "BlackboardCompromiseSensorPlugin";
    private LoggingService logging = null;
    private ThreadService _threadService;
    private final String[] CLASSIFICATIONS = {
        CompromiseBlackboard.CLASSIFICATION
    };
    private UIDService uidService;
    private SensorInfo _sensorInfo;

    //subscription to events
    private IncrementalSubscription compromiseSubs;

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
     *
     * @param service DOCUMENT ME!
     */
    public void setUIDService(UIDService service) {
        this.uidService = service;
    }


    /**
     * DOCUMENT ME!
     *
     * @param ts DOCUMENT ME!
     */
    public void setThreadService(ThreadService ts) {
        _threadService = ts;
    }


    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    protected SensorInfo getSensorInfo() {
        if (_sensorInfo == null) {
            _sensorInfo = new BlackboardSensorInfo();
        }

        return _sensorInfo;
    }


    /**
     * DOCUMENT ME!
     */
    protected void setupSubscriptions() {
        super.setupSubscriptions();


        //initialize the EventPublisher in the following services
        // need to get the execution context for this sensor for publishing idmef event
        EventPublisher publisher = new IdmefEventPublisher(_blackboard, _scs,
                _cmrFactory, _log, getSensorInfo(), _threadService);
        setPublisher(publisher);
        publishIDMEFEvent();
        this.compromiseSubs = (IncrementalSubscription) getBlackboardService()
                                                            .subscribe(new BlackboardFailure());

    }


    /**
     * DOCUMENT ME!
     *
     * @param event DOCUMENT ME!
     */
    public static void publishEvent(BlackboardFailureEvent event) {
        String data = event.getData();
        java.util.logging.Logger utilLogger = java.util.logging.Logger.getLogger("BlackboardCompromiseSensorPlugin");
//        utilLogger.log(java.util.logging.Level.SEVERE,"PublishAgentCompromiseEvent");
	   
        //data = data + ",manager=" + myManagerAddress.getAddress();
        //BlackboardFailureEvent bEvent = new BlackboardFailreEvent(event.getSource(), event.getTarget(), event.getReason(), event.getReasonIdentifier(), data,event.getDataIdentifier());
        publishEvent(BlackboardCompromiseSensorPlugin.class, event);

    }


    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    protected String[] getClassifications() {
        return CLASSIFICATIONS;
    }


    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    protected boolean agentIsTarget() {
        return true;
    }


    /**
     * DOCUMENT ME!
     *
     * @param o DOCUMENT ME!
     */
    public void execute(Object o) {
    }


    /**
     * DOCUMENT ME!
     */
    public void execute() {
        if (logging.isDebugEnabled()) {
            logging.debug(pluginName + " is executing");
        }

        Enumeration enumeration = this.compromiseSubs.getAddedList();
        while (enumeration.hasMoreElements()) {
            Event event = (Event) enumeration.nextElement();
            if(logging.isDebugEnabled()){
            	logging.debug("PublishSharedRelayEvent");
            }
            if (!(this.getAgentIdentifier().equals(this.myManagerAddress))) {
                SharedDataRelay relay = new SharedDataRelay(uidService.nextUID(),
                        this.getAgentIdentifier(), myManagerAddress, event, null);


                getBlackboardService().publishAdd(relay);
            }
        }
    }


    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    protected boolean agentIsSource() {
        return false;
    }

    private class BlackboardSensorInfo implements SensorInfo {
        /**
         * Get the name of the sensor/anaylzer.
         *
         * @return the name of the sensor
         */
        public String getName() {
            return "BlackboardSensor";
        }


        /**
         * Get the sensor manufacturer.
         *
         * @return the sensor manufacturer
         */
        public String getManufacturer() {
            return "CSI";
        }


        /**
         * Get the sensor model.
         *
         * @return the sensor model
         */
        public String getModel() {
            return "Cougaar Blackboard Failure Sensor";
        }


        /**
         * Get the sensor version.
         *
         * @return the sensor version
         */
        public String getVersion() {
            return "1.0";
        }


        /**
         * Get the class of analyzer software and/or hardware.
         *
         * @return the sensor class
         */
        public String getAnalyzerClass() {
            return "Cougaar Security";
        }
    }
}
