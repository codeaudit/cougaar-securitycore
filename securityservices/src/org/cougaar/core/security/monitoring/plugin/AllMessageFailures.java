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

import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Alert;

import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.constants.IdmefClassifications;
import org.cougaar.util.UnaryPredicate;

public class AllMessageFailures 
  implements UnaryPredicate, QueryClassificationProvider {
  private static final String[] CLASSIFICATIONS = {
    IdmefClassifications.MESSAGE_FAILURE
  };
  /**
   * UnaryPredicate API requires this. Selects the
   * objects that we're interested in on the remote Blackboard.
   */
  public boolean execute(Object obj) {
    if (obj instanceof Event) {
      Event event = (Event) obj;
      IDMEF_Message msg = event.getEvent();
      if (msg instanceof RegistrationAlert) {
        return false;
      }
      if (msg instanceof Alert) {
        Classification[] c = ((Alert) msg).getClassifications();
        if (c != null) {
          for (int i = 0; i < c.length; i++) {
            if (c[i].getName().equals(IdmefClassifications.MESSAGE_FAILURE)) {
              return true;
            } // end of if (c.getName().equals('foo'))
          } // end of for (int i = 0; i < c.length; i++)
        } // end of if (c != null)
      } // end of if (msg instanceof Alert)
    }
    return false;
  }
  
  /**
   * QueryClassificationProvider requires this to get a list of sensors
   * that support MESSAGE_FAILUREs.
   */
  public String[] getClassifications() {
    return CLASSIFICATIONS;
  }
}


