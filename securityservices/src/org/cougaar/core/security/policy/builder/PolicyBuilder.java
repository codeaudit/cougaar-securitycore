package org.cougaar.core.security.policy.builder;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.*;

import kaos.core.util.AttributeMsg;
import kaos.core.util.KAoSConstants;
import kaos.core.util.PolicyMsg;
import kaos.core.util.SubjectMsg;
import kaos.core.util.UniqueIdentifier;
import kaos.ontology.repository.OntologyLoader;
import kaos.ontology.util.JTPStringFormatUtils;
import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.policy.util.PolicyBuildingNotCompleted;
import kaos.ontology.util.RangeIsBasedOnInstances;
import kaos.ontology.util.ValueNotSet;
import kaos.policy.information.DAMLPolicyContainer;
import kaos.policy.information.PolicyInformation;
import kaos.policy.information.PolicyInformationManager;
import kaos.policy.util.DAMLPolicyBuilder;
import kaos.policy.util.DAMLPolicyBuilderImpl;
import kaos.policy.util.SpecifiedModalityTypeNotExists;

public class PolicyBuilder extends DAMLPolicyBuilderImpl
{

  public void setPolicyModality(boolean modality)
  {
    try {
      setPolicyIDAndModalityType("#policy-grammarGenerated-" 
                                 + UniqueIdentifier.GenerateUID(), 
                                 (modality ?
                                  kaos.ontology.jena.PolicyConcepts.
                                  _PosAuthorizationPolicy_               : 
                                  kaos.ontology.jena.PolicyConcepts.
                                  _NegAuthorizationPolicy_));
    } catch (SpecifiedModalityTypeNotExists e) {
      RuntimeException fatal 
        = new RuntimeException("This should be impossible - CODING ERROR");
      fatal.initCause(e);
      throw fatal;
    }
  }

  public PolicyInformation getPolicyInformation()
  {
    PolicyCompiler.loadTheBrain();
    return LocalPolicyInformationManager.readPolicyFromBuilder(this);
  }

  private PolicyMsg startPolicyMsg()
    throws ValueNotSet, PolicyBuildingNotCompleted, RangeIsBasedOnInstances
  {
    KAoSClassBuilderImpl controls = getControlsActionClass();
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
    PolicyMsg policyMsg = new PolicyMsg(getPolicyID(),
                                        getPolicyName(),
                                        getPolicyDesc(),
                                        action,
                                        "", // admin
                                        subjects,
                                        true);
    policyMsg.setModality(getModalityType());
    policyMsg.setPriority("" + getPriority());
    return policyMsg;
  }

  public PolicyMsg getPolicyInformationMsg()
    throws ValueNotSet, PolicyBuildingNotCompleted, RangeIsBasedOnInstances
  {
    PolicyMsg policyMsg = startPolicyMsg();
    policyMsg.setAttribute(new AttributeMsg(AttributeMsg.POLICY_INFORMATION,
                                            getPolicyInformation(),
                                            true));
    return policyMsg;
  }


  public PolicyMsg getPolicyMsg()
    throws ValueNotSet, PolicyBuildingNotCompleted, RangeIsBasedOnInstances
  {
    PolicyMsg policyMsg = startPolicyMsg();
    DAMLPolicyContainer damlPolicy = getPolicy();
    policyMsg.setAttribute(new AttributeMsg(AttributeMsg.DAML_CONTENT,
                                            damlPolicy,
                                            true));
    return policyMsg;
  }

  public void writePolicyMsg()
    throws IOException
  {
    PolicyMsg pm = null;
    String filename = null;
    try {
      filename = getPolicyName() + ".msg";
    } catch (ValueNotSet e) {
      IOException ex = new IOException("Failed to get file name for output");
      ex.initCause(e);
      throw ex;
    }
    try {
      pm = getPolicyMsg();
    } catch (Exception e) {
      IOException ioerror = new IOException("Failed to obtain policy");
      ioerror.initCause(e);
      throw ioerror;
    }
    writeObject(filename, pm);
  }

  public void writePolicyInfo()
    throws IOException
  {
    PolicyMsg pm = null;
    String filename = null;
    try {
      filename = getPolicyName() + ".info";
    } catch (ValueNotSet e) {
      IOException ex = new IOException("Failed to get file name for output");
      ex.initCause(e);
      throw ex;
    }
    try {
      pm = getPolicyInformationMsg();
    } catch (Exception e) {
      IOException ioerror = new IOException("Failed to obtain policy");
      ioerror.initCause(e);
      throw ioerror;
    }
    writeObject(filename, pm);
  }

  private void writeObject(String filename, Object o)
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
}