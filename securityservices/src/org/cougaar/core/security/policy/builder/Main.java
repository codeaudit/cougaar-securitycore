package org.cougaar.core.security.policy.builder;

import java.io.*;
import java.util.*;

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
      List policies = PolicyCompiler.compile("BootPolicies");
      for(Iterator policyIt = policies.iterator();
          policyIt.hasNext();) {
        PolicyBuilder pb = (PolicyBuilder) policyIt.next();
        pb.showPolicy();
        pb.writePolicyMsg();
        pb.writePolicyInfo();
      }
    } catch(Exception e) {
      e.printStackTrace();
    }
  }
}

