package org.cougaar.core.security.policy.builder;

import com.hp.hpl.jena.ontology.OntClass;

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
import kaos.ontology.vocabulary.ActionConcepts;
import kaos.ontology.vocabulary.ActorConcepts;
import kaos.ontology.vocabulary.GroupConcepts;
import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.ontology.util.RangeIsBasedOnAClass;
import kaos.ontology.util.RangeIsBasedOnInstances;
import kaos.ontology.util.SerializableOntModelImpl;
import kaos.ontology.util.ValueNotSet;
import kaos.policy.information.OntologyPolicyContainer;
import kaos.policy.information.PolicyInformation;
import kaos.policy.information.PolicyInformationManager;
import kaos.policy.util.KAoSPolicyBuilderImpl;
import kaos.policy.util.PolicyBuildingNotCompleted;

import org.cougaar.core.security.policy.PolicyBootstrapper;
import org.cougaar.core.security.policy.ontology.EntityInstancesConcepts;
import org.cougaar.core.security.policy.ontology.GroupInstancesConcepts;
import org.cougaar.core.security.policy.ontology.ULOntologyNames;
import org.cougaar.core.security.policy.ontology.UltralogActorConcepts;
import org.cougaar.core.security.policy.ontology.UltralogEntityConcepts;
import org.cougaar.core.security.policy.ontology.UltralogGroupConcepts;

public class PolicyUtils
{
  private static boolean _verbsAlreadyLoaded=false;
  public static OntologyConnection _ontology;


  public static void setOntologyConnection(OntologyConnection ontology)
  {
    _ontology = ontology;
  }


  /**
   * Turns a KAoSPolicyBuilderImpl into a PolicyInformation object.
   * Uses the utility provided by the PolicyInformationManager class.
   */
  public static  
    PolicyInformation getPolicyInformation(KAoSPolicyBuilderImpl policy)
  {
    PolicyInformation pi = PolicyInformationManager.readPolicyFromBuilder(policy);
    return pi;
  }


  /*
   * A policy message has several items in common regardless of
   * whether it is a policy information message or a owl policy
   * message.  This routine builds the common part based on a
   * KAoSPolicyBuilderImpl object.
   */
  private static PolicyMsg startPolicyMsg(KAoSPolicyBuilderImpl policy)
    throws ValueNotSet, PolicyBuildingNotCompleted, RangeIsBasedOnInstances,
           RangeIsBasedOnAClass
  {
    KAoSClassBuilderImpl controls = policy.getControlsActionClass();
    Vector subjects = new Vector();
    String subjectClass = null;
    if (controls.
        isPropertyRangeBasedOnClass(ActionConcepts.performedBy())) {
      subjectClass = controls.
        getBasePropertyRangeClass(ActionConcepts.performedBy());
    } else {
      subjectClass = 
        controls.getPropertyRangeInstance(ActionConcepts.performedBy())[0];
    } 
    SubjectMsg subject = new SubjectMsg(subjectClass, 
                                        null, 
                                        KAoSConstants.ACTOR_CLASS_SCOPE);
    subjects.addElement(subject);
    String action = controls.getImmediateBaseClass();
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
   * inside) from a KAoSPolicyBuilderImpl object.
   */
  public static PolicyMsg getPolicyInformationMsg(KAoSPolicyBuilderImpl policy)
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
   * This routine makes a PolicyMsg (with a ontology  object
   * inside) from a KAoSPolicyBuilderImpl object.
   */
  public static PolicyMsg getPolicyMsg(KAoSPolicyBuilderImpl policy)
    throws ValueNotSet, PolicyBuildingNotCompleted, RangeIsBasedOnInstances,
           RangeIsBasedOnAClass
  {
    PolicyMsg policyMsg = startPolicyMsg(policy);
    OntologyPolicyContainer policyContainer = policy.getPolicy();
    policyMsg.setAttribute(new AttributeMsg(AttributeMsg.ONTOLOGY_CONTENT,
                                            policyContainer,
                                            true));
    return policyMsg;
  }


  /**
   * This routine writes a PolicyMsg (with a Ontology object
   * inside) from a KAoSPolicyBuilderImpl object.  It chooses the name
   * of the file to write from the name of the policy.
   */
  public static void writePolicyMsg(KAoSPolicyBuilderImpl policy)
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
   * inside) from a KAoSPolicyBuilderImpl object.  It chooses the name
   * of the file to write from the name of the policy.
   */
  public static void writePolicyInfo(KAoSPolicyBuilderImpl policy)
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
    loadVerbs();
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

  public static void verbsLoaded()
  {
    _verbsAlreadyLoaded = true;
  }

  public static void loadVerbs()
    throws ReasoningException
  {
    if (_verbsAlreadyLoaded) { return; }
    for (Iterator verbIt = VerbBuilder.hasSubjectValues().iterator();
         verbIt.hasNext();) {
      String verb = (String) verbIt.next();
      _ontology.declareInstance(verb, UltralogEntityConcepts.ULContentValue());
    }
    _verbsAlreadyLoaded = true;
  }

  public static void loadAgentGroups(Map agentGroupMap)
    throws Exception
  {
    for (Iterator agentGroupIt = agentGroupMap.keySet().iterator();
         agentGroupIt.hasNext();) {
      String agentGroup = (String) agentGroupIt.next();
      SerializableOntModelImpl model = new SerializableOntModelImpl();

      OntClass agentClass = model.createClass(ActorConcepts.Agent());
      OntClass agentGroupClass
        = model.createClass(ULOntologyNames.agentGroupPrefix + agentGroup);

      agentGroupClass.setSuperClass(agentClass);
      
      for (Iterator agentIt = ((Set) agentGroupMap.get(agentGroup)).iterator();
           agentIt.hasNext();) {
        String agent =  ULOntologyNames.agentPrefix + (String) agentIt.next();
        _ontology.verifyInstanceOf(agent, ActorConcepts.Agent());
        model.createIndividual(agent, agentGroupClass);
      }
      //      model.write(new PrintWriter(System.out), "RDF/XML-ABBREV");
      _ontology.loadOntology(model, false);
    }
  }

  /**
   * This function
   * <ul>
   * <li> gets all instances of the class 
   *        http://www.ihmc.us/Ultralog/UltralogGroup.owl#Role
   * <li> checks to see if they are in the ontology 
   *       http://www.ihmc.us/Ultralog/Names/GroupInstances.owl
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
    String ulRoleGroup = UltralogGroupConcepts.Role();
    String ulRoleGroupInstanceJena 
      = GroupInstancesConcepts.GroupInstancesOwlURL();

    try {
      Set userRoles;
      userRoles = _ontology.getIndividualTargets(ulRoleGroup);
      for (Iterator userRolesIt = userRoles.iterator();
           userRolesIt.hasNext();) {
        String userRole = (String) userRolesIt.next();
        String shortRole = userRole;

        if (shortRole.startsWith(ulRoleGroupInstanceJena) 
            && shortRole.endsWith("Role")) {
          shortRole = shortRole.substring(ulRoleGroupInstanceJena.length(), 
                                        shortRole.length()-4);
        } else {
          continue;
        }
        String myClassName = ULOntologyNames.personActorClassPrefix 
                                       + shortRole;
        KAoSClassBuilderImpl classBuilder
          = new KAoSClassBuilderImpl(myClassName);

        classBuilder.addImmediateBaseClass(ActorConcepts.Person());
        classBuilder.addBaseClass(ActorConcepts.Person());
        classBuilder.addRequiredValueOnProperty(GroupConcepts.isMemberOf(), 
                                                userRole);
						
          // Load the class into the JTP context
        _ontology.loadOntology(classBuilder.getOntClass(), false);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  /**
   * This function
   * <ul>
   * <li> gets all instances of the class 
   *  http://ontology.ihmc.us/Ultralog/UltralogEntity.owl#PlugInRoles
   * <li> checks to see if they are in the ontology 
   *       http://ontology.ihmc.us/Ultralog/Names/EntityInstances.owl
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
    String ulRoleGroup = UltralogEntityConcepts.PlugInRoles();
    String ulRoleGroupInstanceJena 
      = EntityInstancesConcepts.EntityInstancesOwlURL();

    try {
      Set bbRoles;
      bbRoles = _ontology.getIndividualTargets(ulRoleGroup);
      for (Iterator bbRolesIt = bbRoles.iterator();
           bbRolesIt.hasNext();) {
        String bbRole = (String) bbRolesIt.next();
        String shortRole = bbRole;

        if (shortRole.startsWith(ulRoleGroupInstanceJena) 
            && shortRole.endsWith("Role")) {
          shortRole = shortRole.substring(ulRoleGroupInstanceJena.length(), 
                                        shortRole.length()-4);
        } else {
          continue;
        }
        String myClassName = ULOntologyNames.pluginsInRoleClassPrefix 
                                        + shortRole;
        KAoSClassBuilderImpl classBuilder 
          = new KAoSClassBuilderImpl(myClassName);
        classBuilder.addImmediateBaseClass(UltralogActorConcepts.UltralogPlugins());
        classBuilder.addBaseClass(UltralogActorConcepts.UltralogPlugins());
        classBuilder.addRequiredValueOnProperty(UltralogActorConcepts.roleOfPlugin(),
                                                bbRole);
						
          // Load the class into the JTP context
        _ontology.loadOntology(classBuilder.getOntClass(), false);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

}
