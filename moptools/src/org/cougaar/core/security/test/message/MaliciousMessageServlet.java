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

import org.cougaar.glm.ldm.asset.Organization;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.asset.ClusterPG;
import org.cougaar.planning.ldm.plan.Allocation;
import org.cougaar.planning.ldm.plan.AllocationResult;
import org.cougaar.planning.ldm.plan.AspectType;
import org.cougaar.planning.ldm.plan.AspectValue;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.Role;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.planning.ldm.plan.Verb;
import org.cougaar.util.UnaryPredicate;

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
    private static UnaryPredicate orginizationPredicate = new UnaryPredicate() {
            public boolean execute(Object o) {
                if (o instanceof Organization) {
                    return true;
                }

                return false;
            }
        };

    /**
     * returns the path for the servlet
     *
     * @return servlet path
     */
    protected String getPath() {
        return "/maliciousMessageServlet";
    }


    /**
     * attempts to allocate a task to another agent.  This allocation causes a
     * message to be sent to the servlet.
     *
     * @param arg0 
     * @param arg1 
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

            Collection c = blackboardService.query(orginizationPredicate);
            Iterator i = c.iterator();
            Organization org = null;

            while (i.hasNext()) {
                org = (Organization) i.next();
                ClusterPG clusterPG = org.getClusterPG();
                if (clusterPG.getMessageAddress().getAddress().equals(address)) {
                    break;
                }
            }

            if (org != null) {
                Allocation alloc = this.allocateTo(org, task, pf);
                blackboardService.publishAdd(alloc);
                blackboardService.publishAdd(task);
            }

            blackboardService.closeTransaction();

        }
    }


    /**
     * Allocate the task to the asset
     *
     * @param org The organization to allocate the task to
     * @param task the task to allocate
     * @param pf DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    private Allocation allocateTo(Organization org, Task task,
        PlanningFactory pf) {
        AllocationResult estAR = null;

        if (logging.isDebugEnabled()) {
            logging.debug("Allocating to asset: "
                + org.getItemIdentificationPG().getItemIdentification());
        }


        AspectValue[] aspectValues = new AspectValue[2];

        aspectValues[0] = AspectValue.newAspectValue(AspectType.START_TIME,
                (double) currentTimeMillis());
        aspectValues[1] = AspectValue.newAspectValue(AspectType.END_TIME,
                (double) currentTimeMillis());
        AllocationResult result = pf.newAllocationResult(1.0, true, aspectValues);

        //    		AllocationResult estAR = null;
        Allocation alloc = pf.createAllocation(task.getPlan(), task, org,
                result, Role.ASSIGNED);


        return alloc;
    }
}
