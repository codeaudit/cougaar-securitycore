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
import org.cougaar.planning.ldm.plan.Verb;

import com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent;


/**
 * This is a servlet that sends a malicious message to test the security
 * infastructure
 *
 * @author mabrams
 */
public class MaliciousMessageServlet extends AdvancedSimpleServletComponent {   
    /** the malicious verb */
    public static final String VERB = "MaliciousTestVerb";

    /* (non-Javadoc)
     * @see com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent#getPath()
     */
    protected String getPath() {
        return "/maliciousMessageServlet";
    }


    /* (non-Javadoc)
     * @see com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent#execute(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
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
      
			NewNotification notification = pf.newNotification();
			notification.setPlan(task.getPlan());
			notification.setAllocationResult(estAR);
			notification.setTaskUID(task.getUID());
    
            MessageAddress messageAddress = MessageAddress.getMessageAddress(address);
            notification.setDestination(messageAddress);           	
           	blackboardService.publishAdd(task);
            blackboardService.publishAdd(notification);
            blackboardService.closeTransaction();
        }
    }
}
