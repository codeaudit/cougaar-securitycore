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
package org.cougaar.core.security.coordinator;

import java.util.Set;
import org.cougaar.coordinator.*;
import org.cougaar.coordinator.techspec.TechSpecNotFoundException;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.coordinator.AgentCompromiseInfo;

public class AgentCompromiseAction extends Action
{
    public static final String RESTART = "Restart";
    public static final String DONOTHING = "DoNothing";

    private AgentCompromiseInfo info = null;

    public AgentCompromiseAction(String assetName, ServiceBroker serviceBroker)
	throws TechSpecNotFoundException {
        super(assetName, serviceBroker);
    }
    
    public AgentCompromiseAction(String assetName, Set initialValuesOffered, ServiceBroker serviceBroker)
	throws IllegalValueException, TechSpecNotFoundException {
	super(assetName, initialValuesOffered, serviceBroker);
    }

    public AgentCompromiseAction(AgentCompromiseAction action) {
	super(action);
    }

    public void setValuesOffered(Set values) throws IllegalValueException {
	super.setValuesOffered(values);
    }

    public void start(Object actionValue) throws IllegalValueException {  
	super.start(actionValue);
    }

    public void stop() throws NoStartedActionException {  
	super.stop();
    }
    
    public void stop(CompletionCode completionCode) 
	throws IllegalValueException, NoStartedActionException  {
	super.stop(completionCode);
    }

    public void setCompromiseInfo(AgentCompromiseInfo info) {
      this.info = info;
    }

    public AgentCompromiseInfo getCompromiseInfo() {
      return info;
    }
} 
