/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 

package org.cougaar.core.security.policy.builder;

import com.hp.hpl.jena.ontology.impl.OntModelImpl;
import com.hp.hpl.jena.rdf.model.RDFException;

import java.io.FileInputStream;
import java.io.InputStream;
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
import kaos.policy.information.OntologyConditionContainer;
import kaos.policy.information.OntologyPolicyContainer;
import kaos.policy.util.KAoSPolicyBuilderImpl;


import org.cougaar.core.security.policy.ontology.ULOntologyNames;
import org.cougaar.core.security.policy.builder.PolicyParser;
import org.cougaar.core.security.util.webproxy.WebProxyInstaller;
import org.cougaar.util.ConfigFinder;
import org.cougaar.util.log.LoggerFactory;
import org.cougaar.util.log.Logger;

public class Main 
{
  private static WebProxyInstaller   _proxyInstaller;
  private static OntologyConnection  _ontology = null;
  private static Logger              _log;
  static {
    _log = LoggerFactory.getInstance().createLogger(Main.class);
  }
  
  private static final int BUILD_CMD   = 0;
  private static final int JTP_CMD     = 1;
  private static final int COMMIT_CMD  = 2;
  private static final int EXAMINE_CMD = 3;
  private static final int GET_CMD     = 4;
  private static final int PARSE_CMD   = 5;

  private static final String _conditionName 
    = "org.cougaar.core.security.policy.PREVENTIVE_MEASURE_POLICY";

  private static  boolean _stdout = true;

  private int     _maxReasoningDepth = -1;
  private int     _cmd;
  private boolean _quiet;
  private boolean _buildinfo;
  private boolean _checkDepth = false;
  private String  _policyFile;
  private boolean _useConfig = false;
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
    _proxyInstaller = new WebProxyInstaller();
    _proxyInstaller.install();

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
        } else if (args[counter].equals("--useConfig")) {
          counter++;
          _useConfig=true;
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
                 args[counter].equals("setpolicies")) {
        counter++;
        _cmd = COMMIT_CMD;
        _setPolicies = true;
        counter = getConnectionArgs(args, counter);
        _policyFile = args[counter++];
      } else if (args[counter].equals("addpolicies")) {
        counter++;
        _cmd = COMMIT_CMD;
        _setPolicies = false;
        counter = getConnectionArgs(args, counter);
        _policyFile = args[counter++];
      } else if (args[counter].equals("examine")) {
        counter++;
        _cmd = EXAMINE_CMD;
        _policyFile = args[counter++];
      } else if (args[counter].equals("parse")) {
        counter++;
        _cmd = PARSE_CMD;
        _policyFile = args[counter++];
      } else if (args[counter].equals("get")) {
        counter++;
        _cmd = GET_CMD;
        counter = getConnectionArgs(args, counter);
      } else {
        usage();
      }
      if (args.length != counter) { 
        usage();
      }
    } catch (IndexOutOfBoundsException e) {
      printMessage("Too many arguments");
      usage();
    }
  }

  public int getConnectionArgs(String [] args, int counter)
  {
    _quiet            = true;
    _useDomainManager = false;
    _cmdLineAuth      = false;
    while (args.length - counter > 3) {
      if (args[counter].equals("--dm")) {
        counter++;
        _useDomainManager = true;
      } else if (args[counter].equals("--auth")) {
        counter++;
        _cmdLineAuth     = true;
        _cmdLineUser     = args[counter++];
        _cmdLinePassword = args[counter++].toCharArray();
      } else if (args[counter].equals("--checkDepth")) {
        counter++;
        _checkDepth=true;
      } else {
        break;
      }
    }
    String hostname = args[counter++];
    String port     = args[counter++];
    String agent    = args[counter++];
    _url = "http://" + hostname + ":" + port + "/$" + agent + "/policyAdmin";
    printMessage("_url = " + _url);
    return counter;
  }

  public static void usage()
  {
    int counter = 1;
    StringBuffer sb = new StringBuffer();
    
    sb.append("The arguments consist of common options\n");
    sb.append("followed by a command\n");
    sb.append("There are three common option at the moment:\n");
    sb.append("{--maxReasoningDepth num}  This controls how much\n");
    sb.append("\tjtp searches for the answer to a question.\n");
    sb.append("{--disableChecking}  This disables consistency checking\n");
    sb.append("\tIt is not recommended unless you are in a hurry\n");
    sb.append("{--useConfig} Read the policy file from configs rather than disk\n");
    sb.append("The command then has one of the following forms:\n");
    sb.append("" + (counter++) + ". build {--quiet} {--info} policiesFile\n");
    sb.append("\tTo build policies from a grammar\n");
    sb.append("\tThe --quiet option supresses messages\n");
    sb.append("\tThe --info option builds boot policies only\n");
    sb.append("\tThe --checkDepth option checks that the reasoning\n");
    sb.append("\t\tdepth is sufficient\n");
    sb.append("" + (counter++) + ". commit/setpolicies/addpolicies\n"
                       + " {--dm} {--auth username password} \n");
    sb.append("\t\thost port agent policiesFile\n");
    sb.append("\tTo commit policies using policy servlet\n");
    sb.append("\t--dm = use the Domain Manager to build policies\n");
    sb.append("\t\tBy default policy files are read from disk\n");
    sb.append("\t--auth = supply authentication on the command line\n");
    sb.append("\thost  = host on which the servlet runs\n");
    sb.append("\tport  = port on which the servlet listens\n");
    sb.append("\tagent = agent running the servlet\n");
    sb.append("\tpoliciesFile = policies to commit\n");
    sb.append("" + (counter++) + ". examine policyFile\n");
    sb.append("" + (counter++) + ". get {--auth username password} "
                          + "host port agent\n");
    sb.append("\tDownloads the policies from the domain manager\n");
    sb.append("" + (counter++) + ". parse policyFile\n");
    sb.append("\tParse only for debugging purposes\n");
    sb.append("\n");
    sb.append("commit and setpolicies are synonymous\n");
    sb.append("They replace the policies on the domain manager" +
                       "with the polices in policiesFile\n");
    sb.append("addpolicies leaves existing unconditional policies"
                       + "on the domain manager intact\n");
    sb.append("Conditional policies on the domain manager are " +
                       "always replaced.\n");
    printMessage(sb.toString());
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
      printMessage("Unable to parse security policy");
      if (_log.isWarnEnabled()) {
        _log.warn("", e);
      }
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
      commitPolicies(true);
      break;
    case EXAMINE_CMD:
      examinePolicyFile();
      break;
    case GET_CMD:
      downloadPolicies();
      break;
    case PARSE_CMD:
      compile(_policyFile);
      break;
    default:
      throw new RuntimeException("Shouldn't be here");
    }
    System.exit(0);
  }

  public void connectDomainManager()
    throws IOException
  {
    if (_cmdLineAuth) {
      _ontology = new TunnelledOntologyConnection(_url,
                                                  _cmdLineUser,
                                                  _cmdLinePassword);

    } else {
      _ontology = new TunnelledOntologyConnection(_url);
    }
  }

  public void setOntologyConnection(OntologyConnection o)
  {
    _ontology = o;
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
    printMessage("Parsing Policies");
    ParsedPolicyFile parsed = compile(_policyFile);
    List          ppolicies = parsed.policies();
    if (_log.isDebugEnabled()) {
      _log.debug("listing the policies parsed");
      for (Iterator polIt = ppolicies.iterator(); polIt.hasNext();) {
        ParsedPolicy pp = (ParsedPolicy) polIt.next();
        _log.debug("policy = " + pp.getPolicyName());
      }
    }

    printMessage("Loading ontologies & declarations");
    _ontology = new LocalOntologyConnection(parsed.declarations(), 
                                            parsed.agentGroupMap());
    printMessage("Ontologies loaded");

    if (_checkDepth && !checkDepth(parsed.agentGroupMap())) {
      String s = "Reasoning depth insufficient. Try setting a larger value with the\n"
        + "--maxdepth option\n"
        + "Policies not built as they would be incorrect";

      printMessage(s);
      System.exit(-1);
    }

    printMessage("Writing Policies");
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
      printMessage("Checking reasoning depth");

      for (Iterator agentGroupIt = agentGroupMap.keySet().iterator();
           agentGroupIt.hasNext();) {
        String agentGroup = (String) agentGroupIt.next();
        int    size =((Set) agentGroupMap.get(agentGroup)).size();
        Set    agents = _ontology.getInstancesOf(ULOntologyNames.agentGroupPrefix +
                                                 agentGroup);
        if (agents.size() < size) {
          printMessage("Insufficient reasoning depth");
          printMessage("for agent group " + agentGroup + 
                       " the agent set should have size "
                       + size + "  but actually has size " + 
                       +agents.size());
          return false;
        } else if (agents.size() > size) {
          printMessage("Say what???");
          printMessage("for agent group " + agentGroup + 
                       " the agent set should be \n\n"
                       + agentGroupMap.get(agentGroup) + 
                       "\n\n(size=" + size + ")  but actually is\n\n" 
                       + agents + "\n\n(size="+agents.size() + ")");
          return false;
        }
      }
      return true;
    } catch (Exception e) {
      printMessage("" + e.getStackTrace());
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

  public void commitPolicies(boolean needsConnect)
    throws IOException
  {
    try {
      printMessage("Parsing policies from grammar");
      ParsedPolicyFile parsed = compile(_policyFile);
      List deletePolicies = parsed.getDeletedList();
      List parsedPolicies = parsed.policies();
      if (needsConnect) {
        printMessage("Connecting to domain manager & loading declarations");
        connectDomainManager();
        PolicyUtils.verbsLoaded();
        PolicyUtils.autoGenerateGroups(parsed.declarations(), 
                                       parsed.agentGroupMap());

        if (_checkDepth && !checkDepth(parsed.agentGroupMap())) {
          printMessage("Reasoning depth insufficient. Try setting a larger value with the");
          printMessage("--maxdepth option");
          printMessage("Policies not built as they would be incorrect");
          System.exit(-1);
        }
      }
      commitUnconditionalPolicies(parsedPolicies, deletePolicies);
      commitConditionalPolicies(parsedPolicies);
    } catch (Exception e) {
      printMessage("" + e.getStackTrace());
      printMessage("Error Committing policies");
    }
  }


  /**
   * This routine gathers unconditional policies - either from disk or
   * by building them itself - and then commits them.
   */
  protected void commitUnconditionalPolicies(List    parsed, List deletePolicies)
    throws Exception
  {
    printMessage("Constructing New Unconditional Policy Msgs");
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
          InputStream is = openFile(pp.getPolicyName() + ".msg");
          ObjectInputStream ois = new ObjectInputStream(is);
          newPolicies.add((PolicyMsg) ois.readObject());
          ois.close();
        } 
      }
    }
    printMessage("Getting Existing Policies from servlet");
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

    printMessage("Unconditional Policies Obtained - committing");
    _ontology.updatePolicies(addedPolicies, changedPolicies, removedPolicies);
    printMessage("Policies sent...");
  }


  /**
   * This function commits conditional policies - either by building
   * them itself or by obtaining them off of disk.
   */
  protected void commitConditionalPolicies(List parsed)
    throws Exception
  {
    printMessage("Obtaining Conditional Policies");

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
        InputStream is = openFile(mode + ".cpmsg");
        ObjectInputStream ois = new ObjectInputStream(is);
        conditionalPolicies.add((ConditionalPolicyMsg) ois.readObject());
        ois.close();
      }
    }
    printMessage("Sending Conditional Policies");
    _ontology.setConditionalPolicies(conditionalPolicies);
    printMessage("Conditional Policies Sent");
  }

  /**
   * Compiles the policy file.
   * Essentially manages the IO portion of the compile and hands the
   * work off to the policy parser routines.
   */
   protected ParsedPolicyFile compile(String file)
    throws IOException, PolicyCompilerException
  {
    InputStream is = openFile(file);
    ParsedPolicyFile ppf = null;
    try {
      PolicyLexer lexer = new PolicyLexer(is);
      PolicyParser parser = new PolicyParser(lexer);
      ppf = parser.policyFile();
    } catch (Exception e) {
      PolicyCompilerException pce 
        = new PolicyCompilerException("Compile failed");
      pce.initCause(e);
      throw pce;
    } finally {
      is.close();
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
    InputStream       is  = openFile(_policyFile);
    ObjectInputStream ois = new ObjectInputStream(is);
    PolicyMsg         pm  = null;

    try {
      Object obj = ois.readObject();
      pm = (PolicyMsg) obj;
    } catch (ClassCastException e) {
      printMessage("File is not a policy message file");
    } catch (ClassNotFoundException e) {
      printMessage("File has unknown format");
    } finally {
      ois.close();
    }
    printMessage("Policy = " + pm);
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
        OntologyConditionContainer condition = null;
        OntModelImpl               model     = null;

        printMessage("Policy Model = ");
        dpc.getPolicyModel().write(new PrintWriter(System.out),
                                   "RDF/XML-ABBREV");
        printMessage("controls = ");
        dpc.getControlActionModel().write(new PrintWriter(System.out),
                                           "RDF/XML-ABBREV");
        if ((model = dpc.getTriggerActionModel()) != null) {
          printMessage("trigger = ");
          model.write(new PrintWriter(System.out), "RDF/XML-ABBREV");
        }
        if (((condition = dpc.getCondition()) != null) &&
            (model = condition.getConditionModel()) != null) {
          printMessage("Condition = ");
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
        built.add(pp.buildPolicy(_ontology));
        if (!_quiet) {
          printMessage("Built Policy: " + pp.getPolicyName());
        }
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
            printMessage("Parsed Policy: " + pp.getPolicyName());
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

  private void downloadPolicies()
    throws IOException
  {
    try {
      connectDomainManager();
      List policies = _ontology.getPolicies();
      for (Iterator policiesIt = policies.iterator(); 
           policiesIt.hasNext();) {
        PolicyMsg policy = convertMsgToPolicyMsg((Msg) policiesIt.next());
        String name = policy.getName();
        printMessage("Policy " + name + " found");
        PolicyUtils.writeObject(name + ".msg", policy);
      }
    } catch (SymbolNotFoundException snfe) {
      IOException ioe = new IOException("Symbol not found");
      ioe.initCause(snfe);
      throw ioe;
    }
  }

  private static void printMessage(String s)
  {
    if (_log.isInfoEnabled()) {
      _log.info(s);
    }
  }

  private InputStream openFile(String file)
    throws IOException
  {
    if (_useConfig) {
      ConfigFinder cf = ConfigFinder.getInstance();
      return cf.open(file);
    } else {
      return new FileInputStream(file);
    }
  }

  /*
   * Non-command line support
   *   Historically the command line interface came first or this would 
   *   have been designed differently.  Support for this is needed for the 
   *   coordinator work.
   */

  /*
   * this constructor is not used from the command line tool
   */
  public Main()
  {
    _stdout            = false;
    _useConfig         = true;
  }

  public void setPolicyFile(String p)
  {
    _policyFile = p;
  }

}

