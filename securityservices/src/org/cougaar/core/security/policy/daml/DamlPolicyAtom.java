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

package org.cougaar.core.security.policy.daml;

import com.hp.hpl.jena.daml.common.DAMLModelImpl;
import com.hp.hpl.mesa.rdf.jena.model.Model;
// The locator stuff does not compile.  According to the documentation it 
// should be found in javax.agent.Locator.  But our compilation environment 
// can't find this and I also couldn't find documentation for this class.
// I will just use Object and Object.equals.
//import javax.agent.Locator;

import org.cougaar.core.security.policy.daml.Forgetful;
import org.cougaar.core.service.LoggingService;

public class DamlPolicyAtom {
    private static LoggingService            _log;

    public Model          policy;
    //    public Object         locator;

    public DamlPolicyAtom(Model policy
			  // ,Object locator
			  ) {
	this.policy   = policy;
	//	this.locator = locator;
    }

    public static void setlog(LoggingService log) {
	_log = log;
    }

    public boolean equals(DamlPolicyAtom a) {
	try {
	    return (policy.equals(a.policy) ||
		    Forgetful.copy(policy).equals(Forgetful.copy(a.policy))
		//		  && locator.equals(a.locator)
		    );
	} catch (Exception e) {
	    _log.error("Exception comparing daml policies for equality", e);
	}
	return policy.equals(a.policy); // might not work?
    }
}
