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

import com.hp.hpl.jena.daml.common.DAMLModelImpl;
import com.hp.hpl.mesa.rdf.jena.model.RDFException;

import java.io.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import kaos.core.util.AttributeMsg;
import kaos.core.util.KAoSConstants;
import kaos.core.util.Msg;
import kaos.core.util.PolicyMsg;
import kaos.core.util.SymbolNotFoundException;
import kaos.ontology.util.RangeIsBasedOnInstances;
import kaos.ontology.util.ValueNotSet;
import kaos.policy.information.DAMLPolicyContainer;
import kaos.policy.util.DAMLPolicyBuilderImpl;
import kaos.policy.util.PolicyBuildingNotCompleted;


import org.cougaar.core.security.policy.webproxy.WebProxyInstaller;

import kaos.policy.util.DAMLPolicyBuilderImpl;

class Main {
  private static WebProxyInstaller   _proxyInstaller;
  private static OntologyConnection  _ontology;

  static {
    _proxyInstaller = new WebProxyInstaller();
    _proxyInstaller.install();
    Logger rootlog = Logger.getLogger("");
    rootlog.setLevel(Level.WARNING);
  }


  private static final int BUILD_CMD   = 0;
  private static final int JTP_CMD     = 1;
  private static final int COMMIT_CMD  = 2;
  private static final int EXAMINE_CMD = 3;

  private int     _cmd;
  private boolean _quiet;
  private String  _policyFile;
  private boolean _useDomainManager;
  private boolean _cmdLineAuth;
  private String  _cmdLineUser;
  private char [] _cmdLinePassword;
  private String  _url;

  /*
   * Argument passing routines
   */

  /**
   * The constructor for Main.  A Main object encapsulates the
   * arguments passed from the command line.
   */
  public Main(String [] args)
  {
    try {
      int counter = 0;

      if (args[counter].equals("build")) {
        counter++;
        _cmd = BUILD_CMD;
        if (args[counter].equals("--quiet")) {
          counter++;
          _quiet=true;
        } else { 
          _quiet = false; 
        }
        _policyFile = args[counter++];
      } else if (args[counter].equals("jtp")) {
        counter++; 
        _cmd = JTP_CMD;
      } else if (args[counter].equals("commit")) {
        counter++;
        _cmd = COMMIT_CMD;
        _useDomainManager = false;
        _cmdLineAuth      = false;
        while (args.length - counter > 4) {
          if (args[counter].equals("--dm")) {
            counter++;
            _useDomainManager = true;
          } else if (args[counter].equals("--auth")) {
            counter++;
            _cmdLineAuth     = true;
            _cmdLineUser     = args[counter++];
            _cmdLinePassword = args[counter++].toCharArray();
          } else {
            usage();
          }
        }
        _url = "http://" + args[counter++] + ":" + args[counter++] + 
          "/$" + args[counter++] + "/policyAdmin";
        System.out.println("_url = " + _url);
        _policyFile = args[counter++];
      } else if (args[counter].equals("examine")) {
        counter++;
        _cmd = EXAMINE_CMD;
        _policyFile = args[counter++];
      } else {
        usage();
      }
      if (args.length != counter) { 
        usage();
      }
    } catch (IndexOutOfBoundsException e) {
      usage();
    }
  }

  public static void usage()
  {
    int counter = 1;
    System.out.println("Arguments can take any of the following forms:");
    System.out.println("" + (counter++) + ". build {--quiet} policiesFile");
    System.out.println("\tTo build policies from a grammar");
    System.out.println("\tThe --quiet options supresses messages");
    System.out.println("" + (counter++) + ". commit {--dm} "
                       + "{--auth username password} " +
                       "host port agent policiesFile");
    System.out.println("\tTo commit policies using policy servlet");
    System.out.println("\t--dm = use the Domain Manager to build policies");
    System.out.println("\t\tBy default policy files are read from disk");
    System.out.println("\t--auth = supply authentication on the command line");
    System.out.println("\thost  = host on which the servlet runs");
    System.out.println("\tport  = port on which the servlet listens");
    System.out.println("\tagent = agent running the servlet");
    System.out.println("\tpoliciesFile = policies to commit");
    System.out.println("" + (counter++) + ". examine policyFile");
    System.exit(-1);
  }

  /**
   * Read the command arguments and execute the command
   */
  public static void main(String[] args) {
    try {
      Main env = new Main(args);
      env.run();
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(-1);
    }
  }

  /**
   * Runs the command
   */
  public void run()
    throws Exception
  {
    switch (_cmd) {
    case BUILD_CMD:
      buildPolicies();
      break;
    case COMMIT_CMD:
      commitPolicies();
      break;
    case EXAMINE_CMD:
      examinePolicyFile();
      break;
    default:
      throw new RuntimeException("Shouldn't be here");
    }
    System.exit(0);
  }

  /**
   * Builds the policies from the policyFile.
   * Uses the _quiet flag to determine how much output to generate
   */
  public void buildPolicies()
    throws IOException, PolicyCompilerException
  {
    System.out.println("Loading ontologies");
    _ontology = new LocalOntologyConnection();
    System.out.println("Ontologies loaded");
    System.out.println("Writing Policies");

    List policies = compile(_policyFile);
    for(Iterator policyIt = policies.iterator();
        policyIt.hasNext();) {
      ParsedPolicy pp = (ParsedPolicy) policyIt.next();
      if (!_quiet) {
        System.out.println("Parsed Policy: " + pp.getDescription());
      }
      DAMLPolicyBuilderImpl pb = pp.buildPolicy(_ontology);
      PolicyUtils.writePolicyMsg(pb);
      // build again for a new policy id.
      pb = pp.buildPolicy(_ontology);
      PolicyUtils.writePolicyInfo(pb);
    }
  }

  /**
   * Commits the policies from the _policyFile to the url.
   * Uses the _useDomainManager to determine how the policies are
   * constructed. 
   */
  public void commitPolicies()
    throws IOException
  {
    try {
      if (_cmdLineAuth) {
        _ontology = new TunnelledOntologyConnection(_url,
                                                    _cmdLineUser,
                                                    _cmdLinePassword);
      } else {
        _ontology = new TunnelledOntologyConnection(_url);
      }
      System.out.println("Parsing policies from grammar");
      List policies = compile(_policyFile);
      System.out.println("Policies parsed");

      System.out.println("Constructing New Policy Msgs");
      List  newPolicies = new Vector();
      for(Iterator policyIt = policies.iterator();
          policyIt.hasNext();) {
        ParsedPolicy pp = (ParsedPolicy) policyIt.next();
        if (_useDomainManager) {
          DAMLPolicyBuilderImpl pb = pp.buildPolicy(_ontology);
          newPolicies.add(PolicyUtils.getPolicyMsg(pb));
        } else {
          FileInputStream fis = new FileInputStream(pp.getPolicyName() 
                                                    + ".msg");
          ObjectInputStream ois = new ObjectInputStream(fis);
          newPolicies.add((PolicyMsg) ois.readObject());
          ois.close();
        }
      }
      System.out.println("New Policy Msgs created");
      System.out.println("Getting Existing Policies from servlet");
      List oldPolicies = _ontology.getPolicies();
      List oldPolicyMsgs = new Vector();
      for (Iterator oldPoliciesIt = oldPolicies.iterator();
           oldPoliciesIt.hasNext();) {
        Msg oldPolicy = (Msg) oldPoliciesIt.next();
        oldPolicyMsgs.add(convertMsgToPolicyMsg(oldPolicy));
      }
      updatePolicies(newPolicies, oldPolicyMsgs);
    } catch (Exception e) {
      e.printStackTrace();
      System.out.println("Error Committing policies");
    }
  }

  /**
   * This routine sends the policies to the domain manager to
   * commit.  Think of it removing the oldPolicies and installing the
   * new Policies.
   *
   * It has the extra wrinkle that it cannot actually do things as
   * described above.  If a newPolicy and an old policy both have the
   * same id then the old policy must not be removed  and the new
   * policy must be put in the changed list.
   */
  public void updatePolicies(List newPolicies,
                             List oldPolicies)
    throws IOException
  {
    List oldIds = new Vector();
    for (Iterator policyIt = oldPolicies.iterator(); policyIt.hasNext();) {
      PolicyMsg policy = (PolicyMsg) policyIt.next();
      oldIds.add(policy.getId());
    }

    List addedPolicies   = new Vector();
    List changedPolicies = new Vector();
    List removedPolicies = new Vector();
    List commonIds       = new Vector();
    for (Iterator policyIt = newPolicies.iterator(); policyIt.hasNext();) {
      PolicyMsg policy = (PolicyMsg) policyIt.next();

      if (oldIds.contains(policy.getId())) {
        changedPolicies.add(policy);
        commonIds.add(policy.getId());
      } else {
        addedPolicies.add(policy);
      }
    }

    for (Iterator policyIt = oldPolicies.iterator(); policyIt.hasNext();) {
      PolicyMsg policy = (PolicyMsg) policyIt.next();
      if (!commonIds.contains(policy.getId())) {
        removedPolicies.add(policy);
      }
    }

    System.out.println("Policies Obtained - committing");
    _ontology.updatePolicies(addedPolicies, changedPolicies, removedPolicies);
    System.out.println("Policies sent...");
  }

  /**
   * Compiles the policy file.
   * Essentially manages the IO portion of the compile and hands the
   * work off to the policy parser routines.
   */
   public static List compile(String file)
    throws IOException, PolicyCompilerException
  {
    FileInputStream fis = new FileInputStream(file);
    List policies       = null;
    try {
      PolicyLexer lexer = new PolicyLexer(new DataInputStream(fis));
      PolicyParser parser = new PolicyParser(lexer);
      policies = parser.policies();
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

  /**
   * I don't completely understand why I need this routine but when
   * the policies come from getPolicies() they are Msg objects
   * not PolicyMsg objects.  The information contained in the fields
   * is identical but I need to duplicate it in the form of a policy msg.
   */
  private static PolicyMsg convertMsgToPolicyMsg(Msg m)
    throws SymbolNotFoundException
  {
    PolicyMsg p = new PolicyMsg((String) m.getSymbol(PolicyMsg.ID),
                                (String) m.getSymbol(PolicyMsg.NAME),
                                (String) m.getSymbol(PolicyMsg.DESCRIPTION),
                                (String) m.getSymbol(PolicyMsg.TYPE),
                                (String) m.getSymbol(PolicyMsg.ADMINISTRATOR),
                                (Vector) m.getSymbol(PolicyMsg.SUBJECTS),
                                ((String) m.getSymbol(PolicyMsg.INFORCE))
                                .equals("true"));
    try {
      p.setModality((String) m.getSymbol(PolicyMsg.MODALITY));
    } catch (SymbolNotFoundException e) {
      ;
    }
    try {
      p.setPriority((String) m.getSymbol(PolicyMsg.PRIORITY));
    } catch (SymbolNotFoundException e) {
      ;
    }
    Vector attribs = (Vector) m.getSymbol(PolicyMsg.ATTRIBUTES);
    for (int i=0; i<attribs.size(); i++) {
      Msg attrib = (Msg) attribs.elementAt(i);

      p.setAttribute
        (new AttributeMsg((String) 
                          attrib.getSymbol(KAoSConstants.POLICY_ATTR_NAME),
                          attrib.getSymbol(KAoSConstants.POLICY_ATTR_VALUE),
                          ((String)
                           attrib.getSymbol(KAoSConstants.POLICY_ATTR_IS_SEL))
                          .equals("true")));
    }
    return p;
  }


  /**
   * Provides a command line way of viewing a policy file.
   */
  public void examinePolicyFile()
    throws IOException, RDFException
  {
    FileInputStream   fis = new FileInputStream(_policyFile);
    ObjectInputStream ois = new ObjectInputStream(fis);
    PolicyMsg          pm = null;

    try {
      Object obj = ois.readObject();
      pm = (PolicyMsg) obj;
    } catch (ClassCastException e) {
      System.out.println("File is not a policy message file");
    } catch (ClassNotFoundException e) {
      System.out.println("File has unknown format");
    }
    System.out.println("Policy = " + pm);
    examineDAMLMsg(pm);
  }

  /*
   * This routine looks to see if the policy message has a daml part and if 
   * so it prints it out.  This is good for those guys who want to see DAML.
   * 
   * This currently only prints the right information for authorization 
   * policies.
   */
  static private void examineDAMLMsg(PolicyMsg pm)
    throws RDFException
  {
    Vector attribs = pm.getAttributes();
     
    for (Iterator attribsIt = attribs.iterator(); attribsIt.hasNext(); ) {
      AttributeMsg attrib = (AttributeMsg) attribsIt.next();
      
      // Check if the AttributeMsg is the DAML_CONTENT
      if (attrib.getName().equals(AttributeMsg.DAML_CONTENT)) {
        // first read the policy specific data
        DAMLPolicyContainer dpc = (DAMLPolicyContainer) attrib.getValue();
        

        System.out.println("DAML = ");
        dpc.getPolicyModel().write(new PrintWriter(System.out),
                                   "RDF/XML-ABBREV");
        dpc.getControlActionModel().write(new PrintWriter(System.out),
                                           "RDF/XML-ABBREV");
      }
    }
  }
}

