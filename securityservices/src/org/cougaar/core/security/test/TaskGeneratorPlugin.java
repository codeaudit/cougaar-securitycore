/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
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
package org.cougaar.core.security.test;

import java.io.*;
import java.lang.*;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.DomainService;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.Verb;
import org.cougaar.planning.ldm.PlanningFactory;

/** This Plugin repeatedely sends tasks to an agent.
 * Parameters:
 * - agent: the name of the agent to which tasks will be sent.
 * - verb:  the task verb.
 */

public class TaskGeneratorPlugin extends ComponentPlugin
{
    String theVerb;
    String theAgent;
    ServiceBroker sb;
    public TaskGeneratorPlugin() {}

    protected void setupSubscriptions() {
        sb = getServiceBroker();
	// Send N malicious tasks to the agent
	int n = 10;
	for (int i = 0 ; i < n ; i++) {
	    publishTask();
	}
    }

    protected void execute() {
    }

    protected void publishTask() {
	NewTask task = createTask();
	blackboard.publishAdd(task);
    }

    protected NewTask createTask() {
	Verb verb = new Verb(theVerb);
        DomainService ds = (DomainService)
         sb.getService(this, DomainService.class, null);
        PlanningFactory pf = (PlanningFactory)ds.getFactory(PlanningFactory.class);
	NewTask task = pf.newTask();
	task.setVerb(verb);

	return task;
    }
}
