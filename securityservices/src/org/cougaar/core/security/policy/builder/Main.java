/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */
package org.cougaar.core.security.policy.builder;

import java.io.*;
import java.util.*;

import kaos.core.util.PolicyMsg;
import kaos.ontology.util.RangeIsBasedOnInstances;
import kaos.ontology.util.ValueNotSet;
import kaos.policy.util.PolicyBuildingNotCompleted;

import org.apache.log4j.Logger;

import org.cougaar.core.security.policy.webproxy.WebProxyInstaller;

import kaos.policy.util.DAMLPolicyBuilderImpl;

class Main {
  private static WebProxyInstaller   _proxyInstaller;
  private static Logger              _log;
  private static OntologyConnection  _ontology;


  static {
    _proxyInstaller = new WebProxyInstaller();
    _proxyInstaller.install();
    _log = Logger.getLogger("org.cougaar.core.security.policy.builder");
  }

  public static void usage()
  {
    int counter = 1;
    System.out.println("Arguments can take any of the following forms:");
    System.out.println("" + (counter++) + ". build policiesFile");
    System.out.println("\tTo build policies from a grammar");
    System.out.println("" + (counter++) + ". jtp");
    System.out.println("\tTo run a loaded version of jtp");
    System.out.println("" + (counter++) + ". commit URI policiesFile");
    System.out.println("\tTo commit policies using policy servlet");
    System.out.println("\tat uri = URI and getting policies from .msg files");
    System.out.println("" + (counter++) + ". commitNoDisk URI policiesFile");
    System.out.println("\tTo commit policies using policy servlet");
    System.out.println("\tat uri = URI and building policies from scratch");
    System.exit(-1);
  }

  public static void main(String[] args) {
    try {
      if (args.length == 0) {
        usage();
      }
      if (args[0].equals("commit") || args[0].equals("commitNoDisk")) {
        if (args.length < 3) {
          usage();
        }
        boolean getPoliciesFromDisk = args[0].equals("commit");
        commitPolicies(args[1], args[2], getPoliciesFromDisk);
        System.exit(0);
      } else {
        System.out.println("Loading ontologies");
        _ontology = new LocalOntologyConnection();
        System.out.println("Ontologies loaded");

        if (args[0].equals("jtp")) {
          jtp.ui.DamlQueryAnswerer.main(args);
        } else if (args[0].equals("build")) {
          if (args.length < 2) {
            usage();
          }
          writePolicies(args[1]);
        } else {
          usage();
        }
      }
    } catch(Exception e) {
      e.printStackTrace();
    }
  }

  public static void commitPolicies(String servletUri, 
                                    String policyFile,
                                    boolean disk)
    throws IOException, FileNotFoundException, PolicyCompilerException,
           ValueNotSet, ClassNotFoundException, PolicyBuildingNotCompleted,
           RangeIsBasedOnInstances
  {
    _ontology = new TunnelledOntologyConnection(servletUri);
    System.out.println("Parsing policies from grammar");
    List policies = compile(policyFile);
    System.out.println("Policies parsed");

    System.out.println("Constructing New Policy Msgs");
    List  newPolicies = new Vector();
    for(Iterator policyIt = policies.iterator();
        policyIt.hasNext();) {
      ParsedPolicy pp = (ParsedPolicy) policyIt.next();
      if (disk) {
        FileInputStream fis = new FileInputStream(pp.getPolicyName() + ".msg");
        ObjectInputStream ois = new ObjectInputStream(fis);
        newPolicies.add((PolicyMsg) ois.readObject());
        ois.close();
      } else {
        DAMLPolicyBuilderImpl pb = pp.buildPolicy(_ontology);
        newPolicies.add(PolicyUtils.getPolicyMsg(pb));
      }
    }
    System.out.println("New Policy Msgs created");
    System.out.println("Getting Existing Policies from servlet");
    List oldPolicies = _ontology.getPolicies();
    System.out.println("Policies Obtained - committing");
    _ontology.updatePolicies(newPolicies, new Vector(), oldPolicies);
    System.out.println("Policies sent...");
  }

  public static void writePolicies(String policyFile)
    throws IOException, PolicyCompilerException
  {
    List policies = compile(policyFile);
    for(Iterator policyIt = policies.iterator();
        policyIt.hasNext();) {
      ParsedPolicy pp = (ParsedPolicy) policyIt.next();
      System.out.println("Parsed Policy: " + pp.getDescription());
      DAMLPolicyBuilderImpl pb = pp.buildPolicy(_ontology);
      PolicyUtils.writePolicyMsg(pb);
      // build again for a new policy id.
      pb = pp.buildPolicy(_ontology);
      PolicyUtils.writePolicyInfo(pb);
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

