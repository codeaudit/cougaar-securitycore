/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
 *  All Rights Reserved
 * </copyright>
 */


package org.cougaar.core.security.test.message;


import java.util.Collection;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.AllocationResult;
import org.cougaar.planning.ldm.plan.NewNotification;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.NotificationImpl;
import org.cougaar.planning.ldm.plan.Verb;

import com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent;


/**
 * This is a servlet that sends a legitimate message to test the security
 * infastructure
 *
 * @author mabrams
 */
public class LegitimateMessageServlet extends AdvancedSimpleServletComponent {
    /** the legitimate verb */
    public static final String VERB = "LegitimateTestVerb";

   
    protected String getPath() {
        return "/legitimateMessageServlet";
    }


    protected void execute(HttpServletRequest arg0, HttpServletResponse arg1) {
        Collection parameters = getParameters();
        Iterator iter = parameters.iterator();
        String address = "";
        if (iter.hasNext()) {
            address = (String) iter.next();
        }

        if (!address.equals("")) {
            blackboardService.openTransaction();
            PlanningFactory pf = (PlanningFactory) domainService.getFactory(
                    "planning");
            NewTask task = pf.newTask();
            task.setVerb(Verb.getVerb(VERB));
            AllocationResult estAR = null;
            NewNotification notification = new NotificationImpl(task, estAR,
                    task.getPlan());
            MessageAddress messageAddress = MessageAddress.getMessageAddress(address);
            notification.setDestination(messageAddress);
            blackboardService.publishAdd(task);
            blackboardService.publishAdd(notification);
            blackboardService.closeTransaction();
        }
    }
}
