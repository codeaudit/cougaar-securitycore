/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
 *  All Rights Reserved
 * </copyright>
 */


package org.cougaar.core.security.monitoring.event;


import org.cougaar.core.security.monitoring.plugin.CompromiseBlackboard;


/**
 * DOCUMENT ME!
 *
 * @version $Revision: 1.1 $
 * @author $author$
 */
public class BlackboardFailureEvent extends FailureEvent {
    /**
     * DOCUMENT ME!
     *
     * @param source
     * @param target
     * @param reason
     * @param reasonId
     * @param data
     * @param dataId
     */
    public BlackboardFailureEvent(String source, String target, String reason,
        String reasonId, String data, String dataId) {
        super(CompromiseBlackboard.CLASSIFICATION, source, target, reason,
            reasonId, data, dataId);

    }
}
