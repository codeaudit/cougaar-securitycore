/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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


package org.cougaar.core.security.test.blackboard;


import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;
import org.cougaar.glm.ldm.oplan.OplanFactory;
import org.cougaar.glm.ldm.oplan.OrgActivity;


/**
 * Just injects OrgActivities for testing purposes.
 *
 * @author ttschampel
 */
public class TestInjectPlugin extends ComponentPlugin {
  private UIDService uidService;

  /**
   * DOCUMENT ME!
   *
   * @param service DOCUMENT ME!
   */
  public void setUIDService(UIDService service) {
    uidService = service;
  }


  /**
   * DOCUMENT ME!
   */
  public void load() {
    super.load();
  }


  /**
   * DOCUMENT ME!
   */
  public void execute() {
  }


  /**
   * DOCUMENT ME!
   */
  public void setupSubscriptions() {
  	UID oplanId=uidService.nextUID();
  	UID orgID = uidService.nextUID();
  	TestObject oplan =new TestObject(oplanId);
  	TestObject org = new TestObject(orgID);
  	getBlackboardService().publishAdd(oplan);
  	getBlackboardService().publishAdd(org);
    for (int i = 1; i < 5; i++) {
      OrgActivity orgActivity = OplanFactory.newOrgActivity(orgID.getUID(), oplanId);
      orgActivity.setActivityName("ACTIVITY " + i);
      orgActivity.setUID(uidService.nextUID());
      getBlackboardService().publishAdd(orgActivity);
    }
  }
  
  public class TestObject implements UniqueObject{
		private UID uid;
		public TestObject(UID u){
			this.uid = u;
		}
		/* (non-Javadoc)
		 * @see org.cougaar.core.util.UniqueObject#getUID()
		 */
		public UID getUID() {
			// TODO Auto-generated method stub
			return uid;
		}

		/* (non-Javadoc)
		 * @see org.cougaar.core.util.UniqueObject#setUID(org.cougaar.core.util.UID)
		 */
		public void setUID(UID arg0) {
			uid = arg0;
			
		}
  	
  }
}
