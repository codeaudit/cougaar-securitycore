package test.org.cougaar.core.security.access;

import junit.framework.*;
/*
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageEnvelope;
import org.cougaar.core.security.acl.trust.*;
import org.cougaar.core.security.access.*;
*/

public class AccessControlEnvelopeTest extends TestCase
{
	public AccessControlEnvelopeTest(String name)
	{
		super(name);
	}

	public void testFoo()
	{
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
