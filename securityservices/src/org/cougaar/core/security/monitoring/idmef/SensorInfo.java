/*
 * <copyright>
 *  Copyright 1997-2002 Network Associates
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
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
package org.cougaar.core.security.monitoring.idmef;

import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.IDMEF_Process;

/**
 * All Cougaar sensors should implement this interface to provide
 * basic information about the sensor.
 */
public interface SensorInfo { 

    /**
     * Get the name of the sensor/anaylzer.
     *
     * @return the name of the sensor
     */
    public String getName();

    /**
     * Get the sensor manufacturer.
     *
     * @return the sensor manufacturer
     */
    public String getManufacturer();
    
     /**
     * Get the sensor model.
     *
     * @return the sensor model
     */
    public String getModel();
    
    /**
     * Get the sensor version.
     *
     * @return the sensor version
     */
    public String getVersion();
    
    /**
     * Get the class of analyzer software and/or hardware.
     *
     * @return the sensor class
     */
    public String getAnalyzerClass();
}
