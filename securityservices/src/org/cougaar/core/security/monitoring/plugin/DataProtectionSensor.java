/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
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

package org.cougaar.core.security.monitoring.plugin;

import org.cougaar.core.plugin.ComponentPlugin;

/** 
 * DataProtectionSensor detects failures that occur in the 
 * DataProtectionService and publishes IDMEF events.
 *
 * NOTE: this class has been added to elimate exceptions when
 * trying to load this component.
 */
public class DataProtectionSensor extends  ComponentPlugin
{
  protected void setupSubscriptions() { }
  protected void execute() { }
  
  private class DPSensorInfo implements SensorInfo {
    public String getName(){
      return "DataProtectionSensor";
    }
    public String getManufacturer(){
      return "NAI Labs";
    }
    public String getModel(){
      return "Cougaar Data Protection Failure Sensor";
    }
    public String getVersion(){
      return "1.0";
    }
    public String getAnalyzerClass(){
      return "Cougaar Security";
    }
  }
}
