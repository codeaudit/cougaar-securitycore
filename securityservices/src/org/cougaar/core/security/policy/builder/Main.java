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
      PolicyCompiler.loadTheBrain();
      if (args.length == 1 && args[0].equals("jtp")) {
        jtp.ui.DamlQueryAnswerer.main(args);
      } else {
        System.out.println("args.length = " + args.length);
        List policies = PolicyCompiler.compile("DamlBootPolicyList.txt");
        for(Iterator policyIt = policies.iterator();
            policyIt.hasNext();) {
          PolicyBuilder pb = (PolicyBuilder) policyIt.next();
          pb.showPolicy();
          pb.writePolicyMsg();
        }
        policies = PolicyCompiler.compile("DamlBootPolicyList.txt");
        for(Iterator policyIt = policies.iterator();
            policyIt.hasNext();) {
          PolicyBuilder pb = (PolicyBuilder) policyIt.next();
          pb.writePolicyInfo();
        }
      }
    } catch(Exception e) {
      e.printStackTrace();
    }
  }
}

