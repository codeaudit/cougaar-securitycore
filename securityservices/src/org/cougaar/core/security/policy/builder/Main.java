package org.cougaar.core.security.policy.builder;

import java.io.*;
import java.util.*;

import org.apache.log4j.Logger;

import org.cougaar.core.security.policy.webproxy.WebProxyInstaller;

import kaos.policy.util.DAMLPolicyBuilderImpl;

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
      OntologyConnection ontology = new LocalOntologyConnection();
      PolicyUtils.setOntologyConnection(ontology);
      if (args.length == 1 && args[0].equals("jtp")) {
        jtp.ui.DamlQueryAnswerer.main(args);
      } else {
        System.out.println("args.length = " + args.length);
        List policies = compile("DamlBootPolicyList.txt");
        for(Iterator policyIt = policies.iterator();
            policyIt.hasNext();) {
          ParsedPolicy pp = (ParsedPolicy) policyIt.next();
          DAMLPolicyBuilderImpl pb = pp.buildPolicy(ontology);
          PolicyUtils.writePolicyMsg(pb);
          // build again for a new policy id.
          pb = pp.buildPolicy(ontology);
          PolicyUtils.writePolicyInfo(pb);
        }
      }
    } catch(Exception e) {
      e.printStackTrace();
    }
  }

  public static List compile(String file)
    throws IOException, PolicyCompilerException
  {
    FileInputStream fis = new FileInputStream(file);
    List parsedPolicies;
    List policies = new Vector();
    try {
      PolicyLexer lexer = new PolicyLexer(new DataInputStream(fis));
      PolicyParser parser = new PolicyParser(lexer);
      parsedPolicies = parser.policies();
      for (Iterator parsedPoliciesIt = parsedPolicies.iterator();
           parsedPoliciesIt.hasNext();) {
        ParsedPolicy parsedPolicy = (ParsedPolicy) parsedPoliciesIt.next();
        policies.add(parsedPolicy);
      }
    } catch (Exception e) {
      PolicyCompilerException pce 
        = new PolicyCompilerException("Compile failed");
      pce.initCause(e);
      throw pce;
    } finally {
      fis.close();
    }
    return policies;
  }
}

