package org.cougaar.core.security.policy.builder;

import kaos.core.util.PolicyMsg;
import kaos.ontology.DefaultOntologies;
import kaos.ontology.repository.KAoSContext;
import kaos.ontology.repository.OntologyRepository;
import kaos.ontology.repository.OntologyLoader;
import kaos.policy.information.PolicyInformation;
import kaos.policy.information.PolicyInformationManager;
import kaos.policy.util.DAMLPolicyBuilder;
import kaos.policy.util.DAMLPolicyBuilderImpl;


public class PolicyBuilder extends DAMLPolicyBuilderImpl
{
  private static OntologyRepository  _brains;

  static {
    KAoSContext kaosReasoner 
      = new KAoSContext(DefaultOntologies.ultralogOntologiesDaml);
    _brains = new OntologyRepository();
    try {
      _brains.loadOntology("http://ontology.coginst.uwf.edu/Policy.daml",
                           true);
      _brains.loadOntology
        ("http://ontology.coginst.uwf.edu/Ultralog/UltralogOntologies.daml",
         true);
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(-1);
    }
    LocalPolicyInformationManager.giveIntelligence(_brains);
  }

  public PolicyInformation getPolicyInformation()
  {
    return LocalPolicyInformationManager.readPolicyFromBuilder(this);
  }

  /*
  public PolicyMsg getPolicyMsg()
  {
    DAMLPolicyContainer damlPolicy = damlPolicyBuilder.getPolicy();
    Vector subjects = new Vector();
    subjects.addElement(_subject);
    PolicyMsg policyMsg = new PolicyMsg(_idValueLbl.getText(),
                                        name,
                                        description,
                                        action,
                                        "", // admin
                                        subjects,
                                        true);
    policyMsg.setModality(modality);
    policyMsg.setPriority(_priorityFld.getText());
    policyMsg.setAttribute(new AttributeMsg(AttributeMsg.DAML_CONTENT,
                                            damlPolicy,
                                            true));

  }
  */
}