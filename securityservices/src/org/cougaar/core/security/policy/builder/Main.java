package org.cougaar.core.security.policy.builder;

import java.util.*;

import kaos.core.util.UniqueIdentifier;
import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.policy.information.PolicyInformation;

import org.apache.log4j.Logger;

import org.cougaar.core.security.policy.webproxy.WebProxyInstaller;

public class Main
{
  private static WebProxyInstaller   _proxyInstaller;
  private static Logger              _log;

  static {
    _proxyInstaller = new WebProxyInstaller();
    _proxyInstaller.install();
    _log = Logger.getLogger("org.cougaar.core.security.policy.builder");
  }

  public static void main(String [] args)
  {
    try {
      PolicyBuilder pb = new PolicyBuilder();        
      pb.setPolicyIDAndModalityType("#policy-" 
                                     + UniqueIdentifier.GenerateUID(), 
                                     kaos.ontology.jena.PolicyConcepts.
                                     _PosAuthorizationPolicy_);
      pb.setPolicyName("Null Policy");
      pb.setPolicyDesc("Testing a simple policy");
      pb.setPriority(2);
      KAoSClassBuilderImpl controls
        = new KAoSClassBuilderImpl(kaos.ontology.jena.ActionConcepts.
                                   _CommunicationAction_);
      controls.setPropertyRangeClass(kaos.ontology.jena.ActionConcepts.
                                     _performedBy_, 
                                     kaos.ontology.jena.ActorConcepts.
                                     _Agent_);
      controls.setPropertyRangeClass(kaos.ontology.jena.ActionConcepts.
                                     _hasDestination_, 
                                     kaos.ontology.jena.ActorConcepts.
                                     _Agent_);
      pb.setControlsActionClass(controls);
      pb.showPolicy();
      PolicyInformation pi = pb.getPolicyInformation();
      System.out.println("Policy Information Format\n" + pi);

    }
    catch (Exception xcp) {
      xcp.printStackTrace();
    }
  }

}
