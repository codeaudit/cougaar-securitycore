/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
 *  All Rights Reserved
 * </copyright>
 */


package org.cougaar.core.security.monitoring.plugin;


import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.util.UnaryPredicate;

import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Classification;


/**
 * DOCUMENT ME!
 *
 * @version $Revision: 1.1 $
 * @author $author$
 */
public class BlackboardFailure implements UnaryPredicate,
    QueryClassificationProvider {
    private static final String[] CLASSIFICATIONS = {
        CompromiseBlackboard.CLASSIFICATION
    };

    /**
     * UnaryPredicate API requires this. Selects the objects that we're
     * interested in on the remote Blackboard.
     *
     * @param o DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean execute(Object o) {
        if (o instanceof Event) {
            Event event = (Event) o;
            if ((event.getEvent() != null) && event.getEvent() instanceof Alert) {
                Alert alert = (Alert) event.getEvent();
                if (alert.getClassifications() != null) {
                    Classification[] classifications = alert.getClassifications();
                    for (int i = 0; i < classifications.length; i++) {
                        if ((classifications[i].getName() != null)
                            && classifications[i].getName().equals(CompromiseBlackboard.CLASSIFICATION)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;


    }
    
    


    /**
     * QueryClassificationProvider requires this to get a list of sensors that
     * support LOGIN_FAILUREs.
     *
     * @return DOCUMENT ME!
     */
    public String[] getClassifications() {
        return CLASSIFICATIONS;
    }
}
