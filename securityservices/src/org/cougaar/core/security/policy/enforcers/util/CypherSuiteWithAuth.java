package org.cougaar.core.security.policy.enforcers.util;

import dummy.util.CypherSuite;

import java.util.*;

/**
 * This class extends the CypherSuite class to include an
 * authentication method.  A distinction that this class has over its
 * superclass is that it always represents a single set of cypher algorithms.
 *
 * This class also exports some public constants representing how the
 * user authenticates himself (e.g. password, certificate or nothing).
 */

public class CypherSuiteWithAuth extends CypherSuite
{
    public final static int authCertificate = 2;
    public final static int authPassword    = 1;
    public final static int authNoAuth      = 0;
    public final static int authInvalid     = -1;

    private int _auth;
    public CypherSuiteWithAuth(String symmetric,
			       String assymmetric,
			       String checksum,
			       int auth)
    {
	super(symmetric,
	      assymmetric,
	      checksum);
	_auth = auth;
    }

    public int getAuth() { return _auth; }
}

