package org.cougaar.core.security.policy.enforcers.util;

import kaos.core.util.SubjectListedPolicyMsg;
import kaos.policy.information.PolicyInformation;

public class Policylet
{
  private PolicyInformation _pi;
  private String _id;
  private int _priority;
  public Policylet(SubjectListedPolicyMsg p) {
    _id = p.getId();
        
  }
}
