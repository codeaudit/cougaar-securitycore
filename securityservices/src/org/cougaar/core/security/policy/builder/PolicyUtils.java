package org.cougaar.core.security.policy.builder;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.*;

import kaos.core.service.directory.KAoSDirectoryService;
import kaos.core.util.AttributeMsg;
import kaos.core.util.KAoSConstants;
import kaos.core.util.PolicyMsg;
import kaos.core.util.SubjectMsg;
import kaos.ontology.repository.OntologyLoader;
import kaos.ontology.util.JTPStringFormatUtils;
import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.policy.util.PolicyBuildingNotCompleted;
import kaos.ontology.util.RangeIsBasedOnInstances;
import kaos.ontology.util.ValueNotSet;
import kaos.policy.information.DAMLPolicyContainer;
import kaos.policy.information.PolicyInformation;
import kaos.policy.information.PolicyInformationManager;
import kaos.policy.util.DAMLPolicyBuilderImpl;

import org.cougaar.core.security.policy.enforcers.ontology.jena.*;

public class PolicyUtils
{
  public static OntologyConnection _ontology;

  public static final String pluginsInRoleClassPrefix
    = "http://ontology.coginst.uwf.edu/Ultralog/PluginsInRole#";
  public static final String personActorClassPrefix 
    = "http://ontology.coginst.uwf.edu/Ultralog/UsersInRole#";

  public static void setOntologyConnection(OntologyConnection ontology)
  {
    _ontology = ontology;
  }

  public static  
    PolicyInformation getPolicyInformation(DAMLPolicyBuilderImpl policy)
  {
    return LocalPolicyInformationManager.readPolicyFromBuilder(policy);
  }

  private static PolicyMsg startPolicyMsg(DAMLPolicyBuilderImpl policy)
    throws ValueNotSet, PolicyBuildingNotCompleted, RangeIsBasedOnInstances
  {
    KAoSClassBuilderImpl controls = policy.getControlsActionClass();
    Vector subjects = new Vector();
    if (!controls.
        isPropertyRangeBasedOnClass(kaos.ontology.jena.ActionConcepts.
                                    _performedBy_)) {
      throw new RuntimeException("Standalone tool failed to find actors");
    }
    String subjectClass = controls.
      getBasePropertyRangeClass(kaos.ontology.jena.ActionConcepts.
                                _performedBy_);
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

  public static PolicyMsg getPolicyInformationMsg(DAMLPolicyBuilderImpl policy)
    throws ValueNotSet, PolicyBuildingNotCompleted, RangeIsBasedOnInstances
  {
    PolicyMsg policyMsg = startPolicyMsg(policy);
    policyMsg.setAttribute(new AttributeMsg(AttributeMsg.POLICY_INFORMATION,
                                            getPolicyInformation(policy),
                                            true));
    return policyMsg;
  }


  public static PolicyMsg getPolicyMsg(DAMLPolicyBuilderImpl policy)
    throws ValueNotSet, PolicyBuildingNotCompleted, RangeIsBasedOnInstances
  {
    PolicyMsg policyMsg = startPolicyMsg(policy);
    DAMLPolicyContainer damlPolicy = policy.getPolicy();
    policyMsg.setAttribute(new AttributeMsg(AttributeMsg.DAML_CONTENT,
                                            damlPolicy,
                                            true));
    return policyMsg;
  }

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

  private static void writeObject(String filename, Object o)
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

  public static void autoGenerateGroups(KAoSDirectoryService kds)
    throws Exception
  {
    generateUserActorClasses(kds);
    generateBlackboardActorClasses(kds);
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
  public static void generateUserActorClasses(KAoSDirectoryService kds)
  {
    String ulRoleGroupJena = UltralogGroupConcepts._Role_;
    String ulRoleGroupJtp
      = JTPStringFormatUtils.convertStringToJTPFormat(ulRoleGroupJena);
    String ulRoleGroupInstanceJena
      = GroupInstancesConcepts.GroupInstancesDamlURL;

    try {
      Set userRoles;
      if (kds != null) {
        userRoles = kds.getIndividualTargets(ulRoleGroupJtp);
      } else {
        LocalOntologyConnection ont = (LocalOntologyConnection) _ontology;
        userRoles = ont.getResourcesWithValueForProperty
                                           (kaos.ontology.RDFConcepts._type_, 
                                            ulRoleGroupJtp); 
      }
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
        if (kds != null) {
          kds.loadOntology(classBuilder.getDAMLClass(), false);
        } else {
          _ontology.loadOntology(classBuilder.getDAMLClass(), false);
        }
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
  public static void generateBlackboardActorClasses(KAoSDirectoryService kds)
  {
    String ulRoleGroupJena = UltralogEntityConcepts._PlugInRoles_;
    String ulRoleGroupJtp
      = JTPStringFormatUtils.convertStringToJTPFormat(ulRoleGroupJena);
    String ulRoleGroupInstanceJena 
      = EntityInstancesConcepts.EntityInstancesDamlURL;

    try {
      Set bbRoles;
      if (kds != null) {
        bbRoles = kds.getIndividualTargets(ulRoleGroupJtp);
      } else {
        LocalOntologyConnection ont = (LocalOntologyConnection) _ontology;
        bbRoles = ont.getResourcesWithValueForProperty
                                           (kaos.ontology.RDFConcepts._type_, 
                                            ulRoleGroupJtp); 
      }
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
        if (kds != null) {
          kds.loadOntology(classBuilder.getDAMLClass(), false);
        } else {
          _ontology.loadOntology(classBuilder.getDAMLClass(), false);
        }
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }


}
