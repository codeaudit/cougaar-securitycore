package org.cougaar.core.security.policy.builder;

import java.util.*;

import kaos.ontology.repository.OntologyRepository;
import kaos.policy.information.PolicyInformationManager;


public class LocalPolicyInformationManager
  extends PolicyInformationManager
{
  private static OntologyConnection  _brains;

  public static void giveIntelligence(OntologyConnection brains)
  {
    _brains = brains;
  }

  public static Set getInstancesOf(String className)
  {
    try {
      return _brains.getInstancesOf(className);
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(-1);
      throw new RuntimeException("shouldn't get here");
    }
  }

  public static Set getSubClassesOf(String className)
  {
    try {
      return _brains.getSubClassesOf(className);
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(-1);
      throw new RuntimeException("shouldn't get here");
    }
  }
}
