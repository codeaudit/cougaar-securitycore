package org.cougaar.core.security.policy.enforcers.util;

import java.util.Set;

/**
 * This class represents a suite of crypto algorithms including symmetric, 
 * assymmetric and checksum algorithms.  
 */


public class CypherSuite {
    private String _symmetric;
    private String _assymetric;
    private String  _checksum;

    /**
     * Construct a Cypher Suite.
     *
     * The arguments are vectors of strings.  Each string represents
     * an algorithm.  Thus I could use a vector containing "3DES" for
     * symmetric, etc.
     *
     */
    public CypherSuite(String symmetric,
		       String assymetric,
		       String checksum) {
	_symmetric  = symmetric;
	_assymetric = assymetric;
	_checksum   = checksum;
    }

    /**
     * Returns the vector of symmetric algorithms in the suite as a
     * vector of strings.
     */
    public String getSymmetric()   { return _symmetric;  }
    /**
     * Returns the vector of assymmetric algorithms in the suite as a
     * vector of strings.
     */
    public String getAssymmetric() { return _assymetric; }
    /**
     * Returns the vector of checksum algorithms in the suite as a
     * vector of strings.
     */
    public String getChecksum()    { return _checksum;   }
}
