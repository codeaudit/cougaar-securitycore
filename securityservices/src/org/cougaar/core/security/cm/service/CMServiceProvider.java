/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 *
 * </copyright>
 *
 * CHANGE RECORD
 * -
 */


package org.cougaar.core.security.cm.service;


import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceProvider;


/**
 * DOCUMENT ME!
 *
 * @version $Revision: 1.1 $
 * @author $author$
 */
public class CMServiceProvider implements ServiceProvider {
  CMServiceImpl cmImplRef = null;
  String queryFile = null;

  /**
   * Constructor
   *
   * @param sb The service broker for the service.
   */
  public CMServiceProvider(ServiceBroker sb) {
    cmImplRef = new CMServiceImpl(sb);
  }

  /**
   * Returns a reference to CMService
   *
   * @param sb Service broker
   * @param requestor The requestor
   * @param serviceClass The service class
   *
   * @return The Service
   */
  public Object getService(ServiceBroker sb, Object requestor,
    Class serviceClass) {
    if (CMService.class.isAssignableFrom(serviceClass)) {
      if (cmImplRef == null) {
        cmImplRef = new CMServiceImpl(sb);
      } else {
        cmImplRef.setServiceBroker(sb);
      }

      return cmImplRef;
    } else {
      return cmImplRef;
    }
  }


  /**
   * Releases the GUI service
   *
   * @param sb
   * @param requestor The object requesting the service
   * @param serviceClass Class of the requested service
   * @param service The Service
   */
  public void releaseService(ServiceBroker sb, Object requestor,
    Class serviceClass, Object service) {
  }
}
