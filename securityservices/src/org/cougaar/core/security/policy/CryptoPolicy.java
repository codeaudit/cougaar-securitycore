package org.cougaar.core.security.policy;

import org.cougaar.planning.ldm.policy.*;
//import com.nai.security.policy.*;

public class CryptoPolicy extends TypedPolicy {


  public CryptoPolicy() {
    super("com.nai.security.policy.CryptoPolicy");
    
//    Vector options[] = new Vector();
//    modes[0] = Ground; modes[1] = Sea; modes[2] = Air;
//    EnumerationRuleParameter erp  = new EnumerationRuleParameter(ShipMode, modes);
//    try {
//      erp.setValue(Ground);
//    } catch (RuleParameterIllegalValueException ex) {
//      System.out.println(ex);
//    }
//    Add(erp);
  }


/******** public int getShipDays() {
    IntegerRuleParameter param = (IntegerRuleParameter)Lookup(ShipDays);
    return ((Integer)(param.getValue())).intValue();
  }

  public void setShipDays(int days) {
    IntegerRuleParameter param = (IntegerRuleParameter)Lookup(ShipDays);
    try {
      param.setValue(new Integer(days));
    } catch(RuleParameterIllegalValueException ex) {
      System.out.println(ex);
    }
  }

  public String getShipMode() {
    EnumerationRuleParameter param = (EnumerationRuleParameter)Lookup(ShipMode);
    return ((String)param.getValue());
  }
    
  public void setShipMode(String mode) {
    EnumerationRuleParameter param = (EnumerationRuleParameter)Lookup(ShipMode);
    try {
      param.setValue(mode);
    } catch(RuleParameterIllegalValueException ex) {
      System.out.println(ex);
    }
  }
********/

}
