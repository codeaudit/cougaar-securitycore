package org.cougaar.core.security.policy.builder;

import java.io.*;
import java.util.*;

import kaos.core.util.PolicyMsg;
import kaos.core.util.UniqueIdentifier;
import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.policy.information.PolicyInformation;

import org.apache.log4j.Logger;

import org.cougaar.core.security.policy.webproxy.WebProxyInstaller;


class Main {
  private static WebProxyInstaller   _proxyInstaller;
  private static Logger              _log;

  static {
    _proxyInstaller = new WebProxyInstaller();
    _proxyInstaller.install();
    _log = Logger.getLogger("org.cougaar.core.security.policy.builder");
  }


  public static void main(String[] args) {
    try {
      FileInputStream fis = new FileInputStream("BootPolicies");
      L lexer = new L(new DataInputStream(fis));
      P parser = new P(lexer);
      parser.policy(false);
      fis.close();
    } catch(Exception e) {
      e.printStackTrace();
    }
  }

  public static void writeServletUserAccessPolicy(boolean boot,
                                                  String policyName,
                                                  boolean modality,
                                                  String userRole,
                                                  String servlet)
  {
    String userClass = 
      org.cougaar.core.security.policy.enforcers.ontology.jena.
      ActorClassesConcepts.ActorClassesDamlURL
      + userRole;
    String servletClass = 
      org.cougaar.core.security.policy.enforcers.ontology.jena.
      EntityInstancesConcepts.EntityInstancesDamlURL
      + servlet;
    try {
      PolicyBuilder pb = new PolicyBuilder();
      pb.setPolicyIDAndModalityType("#policy-" 
                                     + UniqueIdentifier.GenerateUID(), 
                                     kaos.ontology.jena.PolicyConcepts.
                                     _PosAuthorizationPolicy_);
      pb.setPolicyName(policyName);
      pb.setPolicyDesc("A user in role " + userRole + 
                       (modality ? "can" : "cannot")
                       + " access the servlet named " + servlet);
      pb.setPriority(modality ? 2 : 3);
      KAoSClassBuilderImpl controls = 
        new KAoSClassBuilderImpl
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         ActionConcepts._AccessAction_);
      controls.setPropertyRangeClass
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         ActionConcepts._performedBy_,
         userClass);
      controls.setPropertyRangeClass
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         UltralogActionConcepts._accessedServlet_,
         servletClass);
      pb.setControlsActionClass(controls);
      pb.showPolicy();
      if (boot) {
        ;
      } else {
        PolicyMsg pm = pb.getPolicyMsg();
        System.out.println("Policy Message Format\n" + pm);
        System.out.println("Writing to file " + policyName + ".msg");
        pb.writePolicyMsg(policyName + ".msg");

      }
    } catch (Exception e) {
      System.err.println("Failed to build policy " + policyName);
      e.printStackTrace();
      System.err.println("continuing with next policy...");
    }
  }

}

