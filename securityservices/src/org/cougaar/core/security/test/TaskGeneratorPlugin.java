/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 

package org.cougaar.core.security.test;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.DomainService;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.Verb;

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
	Verb verb = Verb.getVerb(theVerb);
        DomainService ds = (DomainService)
         sb.getService(this, DomainService.class, null);
        PlanningFactory pf = (PlanningFactory)ds.getFactory(PlanningFactory.class);
	NewTask task = pf.newTask();
	task.setVerb(verb);

	return task;
    }
}
