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

import com.hp.hpl.jena.ontology.impl.OntModelImpl;
import com.hp.hpl.jena.rdf.model.RDFException;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import kaos.core.util.AttributeMsg;
import kaos.core.util.ConditionalPolicyMsg;
import kaos.core.util.KAoSConstants;
import kaos.core.util.Msg;
import kaos.core.util.PolicyMsg;
import kaos.core.util.SymbolNotFoundException;
import kaos.kpat.util.OperatingModeCondition;
import kaos.ontology.repository.OntologyRepository;
import kaos.policy.information.OntologyPolicyContainer;
import kaos.policy.util.KAoSPolicyBuilderImpl;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import org.cougaar.core.security.policy.ontology.ULOntologyNames;
import org.cougaar.core.security.policy.builder.PolicyParser;
import org.cougaar.core.security.policy.webproxy.WebProxyInstaller;


class Main 
{
  private static WebProxyInstaller   _proxyInstaller;
  private static OntologyConnection  _ontology;

  static {
    _proxyInstaller = new WebProxyInstaller();
    _proxyInstaller.install();
    BasicConfigurator.configure();
    Logger.getRootLogger().setLevel(Level.WARN);
  }


  private static final int BUILD_CMD   = 0;
  private static final int JTP_CMD     = 1;
  private static final int COMMIT_CMD  = 2;
  private static final int EXAMINE_CMD = 3;
  private static final int PARSE_CMD   = 4;

  private static final String _conditionName 
    = "org.cougaar.core.security.policy.PREVENTIVE_MEASURE_POLICY";

  private int     _maxReasoningDepth = -1;
  private int     _cmd;
  private boolean _quiet;
  private boolean _buildinfo;
  private boolean _checkDepth = false;
  private String  _policyFile;
  private boolean _useDomainManager;
  private boolean _cmdLineAuth;
  private String  _cmdLineUser;
  private char [] _cmdLinePassword;
  private String  _url;
  private boolean _setPolicies;

  /*
   * Argument passing routines
   */

  /**
   * The constructor for Main.  A Main object encapsulates the
   * arguments passed from the command line.
   */
  protected Main(String [] args)
  {
    try {
      int counter = 0;

      // First process the common arguments.
      while (true) {
        if (args[counter].equals("--maxReasoningDepth")) {
          counter++;
          _maxReasoningDepth = Integer.parseInt(args[counter++]);
        } else if (args[counter].equals("--disableChecking")) {
          counter++;
          OntologyConnection.disableChecking();
        } else {
          break;
        }
      }

      if (args[counter].equals("build")) {
        counter++;
        _cmd        = BUILD_CMD;
        _quiet      = false;
        _buildinfo  = false;
        while (args.length - counter > 1) {
          if (args[counter].equals("--quiet")) {
            counter++;
            _quiet=true;
          } else if (args[counter].equals("--info")) {
            counter++;
            _buildinfo=true;
          } else if (args[counter].equals("--checkDepth")) {
            counter++;
            _checkDepth=true;
          } else {
            usage();
          }
        }
        _policyFile = args[counter++];
      } else if (args[counter].equals("jtp")) {
        counter++; 
        _cmd = JTP_CMD;
      } else if (args[counter].equals("commit") || 
                 args[counter].equals("setpolicies") ||
                 args[counter].equals("addpolicies")) {
        _setPolicies      = !(args[counter].equals("addpolicies"));
        counter++;
        _cmd = COMMIT_CMD;
        _quiet            = true;
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
      } else if (args[counter].equals("parse")) {
        counter++;
        _cmd = PARSE_CMD;
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
    System.out.println("The arguments consist of common options");
    System.out.println("followed by a command");
    System.out.println("There are two common option at the moment:");
    System.out.println("{--maxReasoningDepth num}  This controls how much");
    System.out.println("\tjtp searches for the answer to a question.");
    System.out.println("{--disableChecking}  This disables consistency checking");
    System.out.println("\tIt is not recommended unless you are in a hurry");
    System.out.println("The command then has one of the following forms:");
    System.out.println("" + (counter++) + ". build {--quiet} {--info} policiesFile");
    System.out.println("\tTo build policies from a grammar");
    System.out.println("\tThe --quiet option supresses messages");
    System.out.println("\tThe --info option builds boot policies only");
    System.out.println("\tThe --checkDepth option checks that the reasoning");
    System.out.println("\t\tdepth is sufficient");
    System.out.println("" + (counter++) + ". commit/setpolicies/addpolicies"
                       + " {--dm} {--auth username password} ");
    System.out.println("\t\thost port agent policiesFile");
    System.out.println("\tTo commit policies using policy servlet");
    System.out.println("\t--dm = use the Domain Manager to build policies");
    System.out.println("\t\tBy default policy files are read from disk");
    System.out.println("\t--auth = supply authentication on the command line");
    System.out.println("\thost  = host on which the servlet runs");
    System.out.println("\tport  = port on which the servlet listens");
    System.out.println("\tagent = agent running the servlet");
    System.out.println("\tpoliciesFile = policies to commit");
    System.out.println("" + (counter++) + ". examine policyFile");
    System.out.println("" + (counter++) + ". parse policyFile");
    System.out.println("\tParse only for debugging purposes");
    System.out.println("");
    System.out.println("commit and setpolicies are synonymous");
    System.out.println("They replace the policies on the domain manager" +
                       "with the polices in policiesFile");
    System.out.println("addpolicies leaves existing unconditional policies"
                       + "on the domain manager intact");
    System.out.println("Conditional policies on the domain manager are " +
                       "always replaced.");
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
  protected void run()
    throws Exception
  {
    setDepth();
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
    case PARSE_CMD:
      compile(_policyFile);
      break;
    default:
      throw new RuntimeException("Shouldn't be here");
    }
    System.exit(0);
  }

  /** 
   * Set the reasoning depth
   */

  protected void setDepth()
  {
    if (_maxReasoningDepth > 0) {
      OntologyRepository.setReasoningDepth(_maxReasoningDepth);
    }
  }

  /**
   * Builds the policies from the policyFile.
   * Uses the _quiet flag to determine how much output to generate
   */
  protected void buildPolicies()
    throws IOException, PolicyCompilerException
  {
    System.out.println("Parsing Policies");
    ParsedPolicyFile parsed = compile(_policyFile);
    List          ppolicies = parsed.policies();

    System.out.println("Loading ontologies & declarations");
    _ontology = new LocalOntologyConnection(parsed.declarations(), 
                                            parsed.agentGroupMap());
    System.out.println("Ontologies loaded");

    if (_checkDepth && !checkDepth(parsed.agentGroupMap())) {
      System.out.println
        ("Reasoning depth insufficient. Try setting a larger value with the");
      System.out.println
        ("--maxdepth option");
      System.out.println
        ("Policies not built as they would be incorrect");
      System.exit(-1);
    }

    System.out.println("Writing Policies");
    for(Iterator builtPolicyIt = buildUnconditionalPolicies(ppolicies)
                                                                .iterator();
        builtPolicyIt.hasNext();) {
      KAoSPolicyBuilderImpl pb = (KAoSPolicyBuilderImpl) builtPolicyIt.next();
      if (_buildinfo) {
        PolicyUtils.writePolicyInfo(pb);
      } else {
        PolicyUtils.writePolicyMsg(pb);
      }
    }
    if (!_buildinfo) {
      Vector builtConditionalPolicies = buildConditionalPolicies(ppolicies);
      for(Iterator condpmIt = builtConditionalPolicies.iterator();
          condpmIt.hasNext();) {
        ConditionalPolicyMsg condpm = (ConditionalPolicyMsg) condpmIt.next();
        PolicyUtils.writeObject(getConditionName(condpm) + ".cpmsg", condpm);
      }
    }
  }

  private boolean checkDepth(Map agentGroupMap)
  {
    try {
      System.out.println("Checking reasoning depth");
      for (Iterator agentGroupIt = agentGroupMap.keySet().iterator();
           agentGroupIt.hasNext();) {
        String agentGroup = (String) agentGroupIt.next();
        int    size =((Set) agentGroupMap.get(agentGroup)).size();
        Set    agents = _ontology.getInstancesOf(ULOntologyNames.agentGroupPrefix +
                                                 agentGroup);
        if (agents.size() < size) {
          System.out.println("Insufficient reasoning depth");
          System.out.println("for agent group " + agentGroup + 
                             " the agent set should have size "
                             + size + "  but actually has size " + 
                             +agents.size());
          return false;
        } else if (agents.size() > size) {
          System.out.println("Say what???");
          System.out.println("for agent group " + agentGroup + 
                             " the agent set should be \n\n"
                             + agentGroupMap.get(agentGroup) + 
                             "\n\n(size=" + size + ")  but actually is\n\n" 
                             + agents + "\n\n(size="+agents.size() + ")");
          return false;
        }
      }
      return true;
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }
  }

  /**
   * Commits the policies from the _policyFile to the url.
   * Uses the _useDomainManager to determine how the policies are
   * constructed. 
   *
   * This function parses the policy file and then calls
   * commit{Un}conditionalPolicies to build/read the policies and
   * commit them to the domain manager.
   */

  protected void commitPolicies()
    throws IOException
  {
    try {
      System.out.println("Parsing policies from grammar");
      ParsedPolicyFile parsed = compile(_policyFile);
      List deletePolicies = parsed.getDeletedList();
      List parsedPolicies = parsed.policies();
      System.out.println("Connecting to domain manager & loading declarations");
      if (_cmdLineAuth) {
        _ontology = new TunnelledOntologyConnection(_url,
                                                    _cmdLineUser,
                                                    _cmdLinePassword,
                                                    parsed.declarations(),
                                                    parsed.agentGroupMap());
      } else {
        _ontology = new TunnelledOntologyConnection(_url, 
                                                    parsed.declarations(),
                                                    parsed.agentGroupMap());
      }

      commitUnconditionalPolicies(parsedPolicies, deletePolicies);
      commitConditionalPolicies(parsedPolicies);
    } catch (Exception e) {
      e.printStackTrace();
      System.out.println("Error Committing policies");
    }
  }


  /**
   * This routine gathers unconditional policies - either from disk or
   * by building them itself - and then commits them.
   */
  protected void commitUnconditionalPolicies(List    parsed, List deletePolicies)
    throws Exception
  {
    System.out.println("Constructing New Unconditional Policy Msgs");
    List   newPolicies         = new Vector();

    if (_useDomainManager) {
      List builtPolicies = buildUnconditionalPolicies(parsed);
      for (Iterator builtPolicyIt = builtPolicies.iterator();
           builtPolicyIt.hasNext();) {
        KAoSPolicyBuilderImpl pb
          = (KAoSPolicyBuilderImpl) builtPolicyIt.next();
        newPolicies.add(PolicyUtils.getPolicyMsg(pb));
      }
    } else {
      for(Iterator policyIt = parsed.iterator();
          policyIt.hasNext();) {
        ParsedPolicy pp = (ParsedPolicy) policyIt.next();
        if (pp.getConditionalMode() == null) {
          FileInputStream fis = new FileInputStream(pp.getPolicyName() 
                                                    + ".msg");
          ObjectInputStream ois = new ObjectInputStream(fis);
          newPolicies.add((PolicyMsg) ois.readObject());
          ois.close();
        } 
      }
    }
    System.out.println("Getting Existing Policies from servlet");
    List oldPolicies = _ontology.getPolicies();
    List oldPolicyMsgs = new Vector();
    for (Iterator oldPoliciesIt = oldPolicies.iterator();
         oldPoliciesIt.hasNext();) {
      Msg oldPolicy = (Msg) oldPoliciesIt.next();
      oldPolicyMsgs.add(convertMsgToPolicyMsg(oldPolicy));
    }
    updatePolicies(newPolicies, oldPolicyMsgs, deletePolicies);
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
   *
   * The deletePolicies variable should only be non-empty if we are
   * not doing set-policies.  In this case the policy change is an
   * increment and we may want to delete some of the existing policies
   * from the domain manager.  For now this code assumes that we are
   * not deleting a policy that we are adding.  Later we may change
   * this by having the ParsedPolicyFile class check this as policies
   * and deletion statements are added.
   */
  protected void updatePolicies(List    newPolicies,
                             List    oldPolicies,
                             List    deletePolicies)
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

    if (_setPolicies) {
      for (Iterator policyIt = oldPolicies.iterator(); policyIt.hasNext();) {
        PolicyMsg policy = (PolicyMsg) policyIt.next();
        if (!commonIds.contains(policy.getId())) {
          removedPolicies.add(policy);
        }
      }
    } else {
      for (Iterator deletePoliciesIt = deletePolicies.iterator();
           deletePoliciesIt.hasNext();) {
        String deletePolicyName = (String) deletePoliciesIt.next();
        for (Iterator oldPoliciesIt = oldPolicies.iterator(); 
             oldPoliciesIt.hasNext();) {
          PolicyMsg existingPolicy = (PolicyMsg) oldPoliciesIt.next();
          if (existingPolicy.getName().endsWith(deletePolicyName)) {
            removedPolicies.add(existingPolicy);
          }
        }
      }
    }

    System.out.println("Unconditional Policies Obtained - committing");
    _ontology.updatePolicies(addedPolicies, changedPolicies, removedPolicies);
    System.out.println("Policies sent...");
  }


  /**
   * This function commits conditional policies - either by building
   * them itself or by obtaining them off of disk.
   */
  protected void commitConditionalPolicies(List parsed)
    throws Exception
  {
    System.out.println("Obtaining Conditional Policies");

    Vector conditionalPolicies = new Vector();

    if (_useDomainManager) {
      conditionalPolicies = buildConditionalPolicies(parsed);
    } else {
      Set modes = new HashSet();
      for(Iterator policyIt = parsed.iterator();
          policyIt.hasNext();) {
        ParsedPolicy pp = (ParsedPolicy) policyIt.next();
        if (pp.getConditionalMode() != null) {
          modes.add(pp.getConditionalMode());
        }
      }
      for (Iterator modesIt = modes.iterator(); modesIt.hasNext(); ) {
        String mode = (String) modesIt.next();
        FileInputStream fis = new FileInputStream(mode + ".cpmsg");
        ObjectInputStream ois = new ObjectInputStream(fis);
        conditionalPolicies.add((ConditionalPolicyMsg) ois.readObject());
        ois.close();
      }
    }
    System.out.println("Sending Conditional Policies");
    _ontology.setConditionalPolicies(conditionalPolicies);
    System.out.println("Conditional Policies Sent");
  }

  /**
   * Compiles the policy file.
   * Essentially manages the IO portion of the compile and hands the
   * work off to the policy parser routines.
   */
   protected static ParsedPolicyFile compile(String file)
    throws IOException, PolicyCompilerException
  {
    FileInputStream  fis = new FileInputStream(file);
    ParsedPolicyFile ppf = null;
    try {
      PolicyLexer lexer = new PolicyLexer(fis);
      PolicyParser parser = new PolicyParser(lexer);
      ppf = parser.policyFile();
    } catch (Exception e) {
      PolicyCompilerException pce 
        = new PolicyCompilerException("Compile failed");
      pce.initCause(e);
      throw pce;
    } finally {
      fis.close();
    }
    return ppf;
  }

  /**
   * I don't completely understand why I need this routine but when
   * the policies come from getPolicies() they are Msg objects
   * not PolicyMsg objects.  The information contained in the fields
   * is identical but I need to duplicate it in the form of a policy msg.
   */
  protected static PolicyMsg convertMsgToPolicyMsg(Msg m)
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
  protected void examinePolicyFile()
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
    examineOntMsg(pm);
  }

  /*
   * This routine looks to see if the policy message has a ontology part and 
   * if so it prints it out.  This is good for those guys who want to see the 
   * underlying ontology.
   * 
   * This currently only prints the right information for authorization 
   * policies.
   */
  static protected void examineOntMsg(PolicyMsg pm)
    throws RDFException
  {
    Vector attribs = pm.getAttributes();
     
    for (Iterator attribsIt = attribs.iterator(); attribsIt.hasNext(); ) {
      AttributeMsg attrib = (AttributeMsg) attribsIt.next();
      
      // Check if the AttributeMsg is the ONTOLOGY_CONTENT
      if (attrib.getName().equals(AttributeMsg.ONTOLOGY_CONTENT)) {
        // first read the policy specific data
        OntologyPolicyContainer dpc = (OntologyPolicyContainer) attrib.getValue();
        OntModelImpl       model = null;

        System.out.println("Policy Model = ");
        dpc.getPolicyModel().write(new PrintWriter(System.out),
                                   "RDF/XML-ABBREV");
        System.out.println("controls = ");
        dpc.getControlActionModel().write(new PrintWriter(System.out),
                                           "RDF/XML-ABBREV");
        if ((model = dpc.getTriggerActionModel()) != null) {
          System.out.println("trigger = ");
          model.write(new PrintWriter(System.out), "RDF/XML-ABBREV");
        }
        if ((model = dpc.getConditionActionModel()) != null) {
          System.out.println("Condition = ");
          model.write(new PrintWriter(System.out), "RDF/XML-ABBREV");
        }
      }
    }
  }

  /**
   * This routine generates a map from policy condition modes to Lists
   * of 
   */

  protected List buildUnconditionalPolicies(List parsed)
    throws PolicyCompilerException
  {
    List built = new Vector();

    for (Iterator parsedIt = parsed.iterator();
         parsedIt.hasNext();) {
      ParsedPolicy pp = (ParsedPolicy) parsedIt.next();
      if (pp.getConditionalMode() == null) {
        if (!_quiet) {
          System.out.println("Parsed Policy: " + pp.getPolicyName());
        }
        built.add(pp.buildPolicy(_ontology));
      }
    }
    return built;
  }

  /**
   * This routine generates a Vector of ConditionalPolicyMsgs from a
   * list of parsed policies.
   *
   * I think that the Vector part is important because it is what the 
   * ConditionalPolicyMsg constructor takes as an argument.
   */
  protected Vector buildConditionalPolicies(List parsed)
    throws PolicyCompilerException
  {
    Vector condpms = new Vector();
    try {
      Map built = new HashMap();

      for (Iterator parsedIt = parsed.iterator();
           parsedIt.hasNext();) {
        ParsedPolicy pp    = (ParsedPolicy) parsedIt.next();
        String       mode  = pp.getConditionalMode();

        if (mode != null) {
          if (!_quiet) {
            System.out.println("Parsed Policy: " + pp.getPolicyName());
          }
          Vector existingPoliciesForMode = (Vector) built.get(mode);
          if (existingPoliciesForMode == null) {
            existingPoliciesForMode = new Vector();
          }
          KAoSPolicyBuilderImpl pb = pp.buildPolicy(_ontology);
          existingPoliciesForMode.add(PolicyUtils.getPolicyMsg(pb));
          built.put(mode, existingPoliciesForMode);
        }
      }
  
      for (Iterator modesIt = built.keySet().iterator(); modesIt.hasNext();) {
        String condition = (String) modesIt.next();
        ConditionalPolicyMsg condpm
          = new ConditionalPolicyMsg(new OperatingModeCondition(_conditionName,
                                                                condition),
                                     (Vector) built.get(condition));
        condpms.add(condpm);
      }
    } catch (PolicyCompilerException pce) {
      throw pce;
    } catch (Exception e) {
      PolicyCompilerException pce
        = new PolicyCompilerException("trouble building conditional polcies");
      pce.initCause(e);
      throw pce;
    }
    return condpms;
  }


  /**
   * this routine gets the name of a ConditionalPolicyMsg assuming
   * that the condition part is an OperatingModeCondition object.
   */
  protected String getConditionName(ConditionalPolicyMsg condpm)
  {
    OperatingModeCondition omc=(OperatingModeCondition) condpm.getCondition();
    return (String) omc.getValue();
  }
}

