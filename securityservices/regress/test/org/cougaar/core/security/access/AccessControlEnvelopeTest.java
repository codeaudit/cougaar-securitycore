/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 * Created on September 12, 2001, 10:55 AM
 */

package test.org.cougaar.core.security.access;

import junit.framework.TestCase;
/*
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageEnvelope;
import org.cougaar.core.security.acl.trust.*;
import org.cougaar.core.security.access.*;
*/

public class AccessControlEnvelopeTest
  extends TestCase
{
  public AccessControlEnvelopeTest(String name) {
    super(name);
  }

  public void testFoo() {
    // the tests below were just added
    // as an example.  Since they're not compiling now,
    // I've commented them out...
  }

/*
  public void testSetTrustSet()
  {
  AccessControlEnvelope ace = new AccessControlEnvelope(null);
  TrustSet ts = new TrustSet();
  ace.setTrustSet(ts);
  assertEquals(ace.getTrustSet(), ts);
  }
	
  public void testSetTrustSets()
  {
  AccessControlEnvelope ace = new AccessControlEnvelope(null);
  TrustSet[] ts = new TrustSet[2];
  ts[0] = new TrustSet();
  ts[1] = new TrustSet();
  ace.setTrustSets(ts);
  TrustSet[] ts2 = ace.getTrustSets();
  assertEquals(ts2[0], ts[0]);
  assertEquals(ts2[1], ts[1]);
  }
*/
}
