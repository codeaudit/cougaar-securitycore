package org.cougaar.core.security.policy.builder;


import com.hp.hpl.jena.daml.DAMLClass;
import com.hp.hpl.jena.daml.DAMLList;
import com.hp.hpl.jena.daml.common.DAMLModelImpl;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import jtp.ReasoningException;
import kaos.core.service.directory.KAoSDirectoryService;
import kaos.core.util.AttributeMsg;
import kaos.core.util.KAoSConstants;
import kaos.core.util.PolicyMsg;
import kaos.core.util.SubjectMsg;
import kaos.ontology.jena.ActionConcepts;
import kaos.ontology.jena.ActorConcepts;
import kaos.ontology.util.JTPStringFormatUtils;
import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.ontology.util.RangeIsBasedOnAClass;
import kaos.ontology.util.RangeIsBasedOnInstances;
import kaos.ontology.util.SerializableDAMLModelImpl;
import kaos.ontology.util.ValueNotSet;
import kaos.policy.information.DAMLPolicyContainer;
import kaos.policy.information.PolicyInformation;
import kaos.policy.util.DAMLPolicyBuilderImpl;
import kaos.policy.util.PolicyBuildingNotCompleted;

import org.cougaar.core.security.policy.PolicyBootstrapper;
import org.cougaar.core.security.policy.enforcers.ontology.jena.EntityInstancesConcepts;
import org.cougaar.core.security.policy.enforcers.ontology.jena.GroupInstancesConcepts;
import org.cougaar.core.security.policy.enforcers.ontology.jena.UltralogActorConcepts;
import org.cougaar.core.security.policy.enforcers.ontology.jena.UltralogEntityConcepts;
import org.cougaar.core.security.policy.enforcers.ontology.jena.UltralogGroupConcepts;

public class PolicyUtils
{
  public static OntologyConnection _ontology;

  public static final String pluginsInRoleClassPrefix
    = "http://ontology.coginst.uwf.edu/Ultralog/PluginsInRole#";
  public static final String personActorClassPrefix 
    = "http://ontology.coginst.uwf.edu/Ultralog/UsersInRole#";
  public static final String agentGroupPrefix
    = "http://ontology.coginst.uwf.edu/AgentsInGroup#";

  public static void setOntologyConnection(OntologyConnection ontology)
  {
    _ontology = ontology;
  }


  /**
   * Turns a DAMLPolicyBuilderImpl into a PolicyInformation object.
   * Uses the utility provided by the PolicyInformationManager class.
   */
  public static  
    PolicyInformation getPolicyInformation(DAMLPolicyBuilderImpl policy)
  {
    return LocalPolicyInformationManager.readPolicyFromBuilder(policy);
  }


  /*
   * A policy message has several items in common regardless of
   * whether it is a policy information message or a daml policy
   * message.  This routine builds the common part based on a
   * DAMLPolicyBuilderImpl object.
   */
  private static PolicyMsg startPolicyMsg(DAMLPolicyBuilderImpl policy)
    throws ValueNotSet, PolicyBuildingNotCompleted, RangeIsBasedOnInstances,
           RangeIsBasedOnAClass
  {
    KAoSClassBuilderImpl controls = policy.getControlsActionClass();
    Vector subjects = new Vector();
    String subjectClass = null;
    if (controls.
        isPropertyRangeBasedOnClass(ActionConcepts._performedBy_)) {
      subjectClass = controls.
        getBasePropertyRangeClass(kaos.ontology.jena.ActionConcepts.
                                  _performedBy_);
    } else {
      //      subjectClass = controls.
      //  getCurrentPropertyRangeClass(kaos.ontology.jena.ActionConcepts.
      //                                     _performedBy_);
      subjectClass = controls.
        getPropertyRangeInstance(kaos.ontology.jena.ActionConcepts.
                                 _performedBy_)[0];
    } 
    SubjectMsg subject = new SubjectMsg(subjectClass, 
                                        null, 
                                        KAoSConstants.ACTOR_CLASS_SCOPE);
    subjects.addElement(subject);
    String action = controls.getClassName();
    PolicyMsg policyMsg = new PolicyMsg(policy.getPolicyID(),
                                        policy.getPolicyName(),
                                        policy.getPolicyDesc(),
                                        action,
                                        "", // admin
                                        subjects,
                                        true);
    policyMsg.setModality(policy.getModalityType());
    policyMsg.setPriority("" + policy.getPriority());
    return policyMsg;
  }


  /**
   * This routine makes a PolicyMsg (with a PolicyInformation object
   * inside) from a DAMLPolicyBuilderImpl object.
   */
  public static PolicyMsg getPolicyInformationMsg(DAMLPolicyBuilderImpl policy)
    throws ValueNotSet, PolicyBuildingNotCompleted, RangeIsBasedOnInstances,
           RangeIsBasedOnAClass
  {
    PolicyMsg policyMsg = startPolicyMsg(policy);
    policyMsg.setAttribute(new AttributeMsg(AttributeMsg.POLICY_INFORMATION,
                                            getPolicyInformation(policy),
                                            true));
    return policyMsg;
  }


  /**
   * This routine makes a PolicyMsg (with a DAML object
   * inside) from a DAMLPolicyBuilderImpl object.
   */
  public static PolicyMsg getPolicyMsg(DAMLPolicyBuilderImpl policy)
    throws ValueNotSet, PolicyBuildingNotCompleted, RangeIsBasedOnInstances,
           RangeIsBasedOnAClass
  {
    PolicyMsg policyMsg = startPolicyMsg(policy);
    DAMLPolicyContainer damlPolicy = policy.getPolicy();
    policyMsg.setAttribute(new AttributeMsg(AttributeMsg.DAML_CONTENT,
                                            damlPolicy,
                                            true));
    return policyMsg;
  }


  /**
   * This routine writes a PolicyMsg (with a DAML object
   * inside) from a DAMLPolicyBuilderImpl object.  It chooses the name
   * of the file to write from the name of the policy.
   */
  public static void writePolicyMsg(DAMLPolicyBuilderImpl policy)
    throws IOException
  {
    PolicyMsg pm = null;
    String filename = null;
    try {
      filename = policy.getPolicyName() + ".msg";
    } catch (ValueNotSet e) {
      IOException ex = new IOException("Failed to get file name for output");
      ex.initCause(e);
      throw ex;
    }
    try {
      pm = getPolicyMsg(policy);
    } catch (Exception e) {
      IOException ioerror = new IOException("Failed to obtain policy");
      ioerror.initCause(e);
      throw ioerror;
    }
    writeObject(filename, pm);
  }


  /**
   * This routine writes a PolicyMsg (with a PolicyInformation object
   * inside) from a DAMLPolicyBuilderImpl object.  It chooses the name
   * of the file to write from the name of the policy.
   */
  public static void writePolicyInfo(DAMLPolicyBuilderImpl policy)
    throws IOException
  {
    PolicyMsg pm = null;
    String filename = null;
    try {
      filename = policy.getPolicyName() + ".info";
    } catch (ValueNotSet e) {
      IOException ex = new IOException("Failed to get file name for output");
      ex.initCause(e);
      throw ex;
    }
    try {
      pm = getPolicyInformationMsg(policy);
    } catch (Exception e) {
      IOException ioerror = new IOException("Failed to obtain policy");
      ioerror.initCause(e);
      throw ioerror;
    }
    writeObject(filename, pm);
  }

  /*
   * Utility routine to write a single object
   */
  protected static void writeObject(String filename, Object o)
    throws IOException
  {
    FileOutputStream fos = new FileOutputStream(filename);
    ObjectOutputStream oos = new ObjectOutputStream(fos);
    try {
      oos.writeObject(o);
    } finally {
      oos.close(); 
    }
  }

  /**
   * This routine automatically generates actor classes from their
   * instances.  This significantly simplifies the changes that people
   * will make to ontologies to support system specific data;
   * administrators do not have to construct the actor classes
   * themselves they are automatically generated.
   *
   * This routine is called by the domain manager in a running society
   * and in the standalone tools to get the right ontologies forthe
   * policies.
   *
   * This should probably be changed so that it uses the PolicyBootstrapper 
   * service rather than a static variable.  This will work because the first
   * version of autoGenerateGroups is only called from the domain manager in 
   * safe (where a service broker can presumably be found).  The second version
   * is called from a standalone setting where no services are available, but
   * in that case the declarations have already been found.
   */

  public static void autoGenerateGroups(KAoSDirectoryService kds)
    throws Exception
  {
    ParsedPolicyFile ppf = PolicyBootstrapper.getParsedPolicyFile();
    setOntologyConnection(new KAoSOntologyConnection(kds));
    autoGenerateGroups(ppf.declarations(), ppf.agentGroupMap());
  }

  public static void autoGenerateGroups(Map declarations,
                                        Map agentGroupMap)
    throws Exception
  {
    loadDeclarations(declarations);
    loadAgentGroups(agentGroupMap);
    generateUserActorClasses();
    generateBlackboardActorClasses();
  }

  public static void loadDeclarations(Map declarations)
    throws ReasoningException
  {
    for (Iterator instanceIt = declarations.keySet().iterator(); 
         instanceIt.hasNext();) {
      String instanceName = (String) instanceIt.next();
      String className    = (String) declarations.get(instanceName);
      _ontology.declareInstance(instanceName, className);
    }
  }


  public static void loadAgentGroups(Map agentGroupMap)
    throws Exception
  {
    for (Iterator agentGroupIt = agentGroupMap.keySet().iterator();
         agentGroupIt.hasNext();) {
      String agentGroup = (String) agentGroupIt.next();
      SerializableDAMLModelImpl model = new SerializableDAMLModelImpl();

      DAMLList agentList        = model.createDAMLList(null);
      DAMLClass agentClass = model.createDAMLClass(ActorConcepts._Agent_);
      DAMLClass agentGroupClass
        = model.createDAMLClass(agentGroupPrefix + agentGroup);

      agentGroupClass.prop_subClassOf().add(agentClass);
      
      for (Iterator agentIt = ((Set) agentGroupMap.get(agentGroup)).iterator();
           agentIt.hasNext();) {
        String agent = (String) agentIt.next();
        _ontology.verifyInstanceOf(agent, ActorConcepts._Agent_);
        agentList.add(model.createDAMLInstance(agentClass,  "#" + agent));
      }
      agentGroupClass.prop_oneOf().add(agentList);
      // model.write(new PrintWriter(System.out), "RDF/XML-ABBREV");
      _ontology.loadOntology(model, false);
    }
  }

  /**
   * This function
   * <ul>
   * <li> gets all instances of the class 
   *        http://ontology.coginst.uwf.edu/Ultralog/UltralogGroup.daml#Role
   * <li> checks to see if they are in the ontology 
   *       http://ontology.coginst.uwf.edu/Ultralog/Names/GroupInstances.daml
   * <li> checks to see if they end in the string "Role"
   * <li> if so creates an actor class consisting of all the actors
   *      in this role
   * </ul> 
   * 
   * The namespace used for the actors needs to be exported so that
   * it can be used by the semantic matcher.
   *
   * The generate*ActorClasses() functions are very similar to one
   * another but a common function would be very complex.  Fix?
   * 
   * A small hack in OntologyRepository.getAllNamespaces() ensures
   * that theses namespaces show up in KPAT.
   */
  public static void generateUserActorClasses()
  {
    String ulRoleGroupJena = UltralogGroupConcepts._Role_;
    String ulRoleGroupJtp
      = JTPStringFormatUtils.convertStringToJTPFormat(ulRoleGroupJena);
    String ulRoleGroupInstanceJena
      = GroupInstancesConcepts.GroupInstancesDamlURL;

    try {
      Set userRoles;
      userRoles = _ontology.getIndividualTargets(ulRoleGroupJtp);
      for (Iterator userRolesIt = userRoles.iterator();
           userRolesIt.hasNext();) {
        String userRole = (String) userRolesIt.next();
        userRole = 
          JTPStringFormatUtils.convertJTPFormatToString(userRole);
        String shortRole = userRole;

        if (shortRole.startsWith(ulRoleGroupInstanceJena) 
            && shortRole.endsWith("Role")) {
          shortRole = shortRole.substring(ulRoleGroupInstanceJena.length(), 
                                        shortRole.length()-4);
        } else {
          continue;
        }
        String myClassName = personActorClassPrefix + shortRole;
        KAoSClassBuilderImpl classBuilder
          = new KAoSClassBuilderImpl(myClassName);

        classBuilder.addBaseClass(kaos.ontology.jena.ActorConcepts._Person_);
        classBuilder.addRequiredValueOnProperty(kaos.ontology.jena.GroupConcepts._isMemberOf_, 
                                                userRole);
						
          // Load the class into the JTP context
        _ontology.loadOntology(classBuilder.getDAMLClass(), false);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  /**
   * This function
   * <ul>
   * <li> gets all instances of the class 
   *  http://ontology.coginst.uwf.edu/Ultralog/UltralogEntity.daml#PlugInRoles
   * <li> checks to see if they are in the ontology 
   *       http://ontology.coginst.uwf.edu/Ultralog/Names/EntityInstances.daml
   * <li> checks to see if they end in the string "Role"
   * <li> if so creates an actor class consisting of all the actors
   *      in this role
   * </ul> 
   * 
   * The namespace used for the actors needs to be exported so that
   * it can be used by the semantic matcher.
   *
   * The generate*ActorClasses() functions are very similar to one
   * another but a common function would be very complex.
   * 
   * A small hack in OntologyRepository.getAllNamespaces() ensures
   * that theses namespaces show up in KPAT.
   */
  public static void generateBlackboardActorClasses()
  {
    String ulRoleGroupJena = UltralogEntityConcepts._PlugInRoles_;
    String ulRoleGroupJtp
      = JTPStringFormatUtils.convertStringToJTPFormat(ulRoleGroupJena);
    String ulRoleGroupInstanceJena 
      = EntityInstancesConcepts.EntityInstancesDamlURL;

    try {
      Set bbRoles;
      bbRoles = _ontology.getIndividualTargets(ulRoleGroupJtp);
      for (Iterator bbRolesIt = bbRoles.iterator();
           bbRolesIt.hasNext();) {
        String bbRole = (String) bbRolesIt.next();
        bbRole = JTPStringFormatUtils.convertJTPFormatToString(bbRole);
        String shortRole = bbRole;

        if (shortRole.startsWith(ulRoleGroupInstanceJena) 
            && shortRole.endsWith("Role")) {
          shortRole = shortRole.substring(ulRoleGroupInstanceJena.length(), 
                                        shortRole.length()-4);
        } else {
          continue;
        }
        String myClassName = pluginsInRoleClassPrefix + shortRole;
        KAoSClassBuilderImpl classBuilder 
          = new KAoSClassBuilderImpl(myClassName);

        classBuilder.addBaseClass(UltralogActorConcepts._UltralogPlugins_);
        classBuilder.addRequiredValueOnProperty(UltralogActorConcepts._roleOfPlugin_,
                                                bbRole);
						
          // Load the class into the JTP context
        _ontology.loadOntology(classBuilder.getDAMLClass(), false);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }


}
