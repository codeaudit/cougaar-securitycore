/**
 * Created on May 17, 2005
 * 
 * @author srosset
 * @version $Revision: 1.3 $
 */
package org.cougaar.core.security.policy.enforcers.match;

import java.util.Iterator;

import org.apache.log4j.Logger;

import kaos.ontology.matching.InstanceClassifier;
import kaos.ontology.matching.InstanceClassifierClassCastException;
import kaos.ontology.matching.InstanceClassifierInitializationException;

/**
 * @author srosset
 */
public abstract class DefaultInstanceClassifier implements InstanceClassifier {

  private static Logger log = Logger.getLogger(DefaultInstanceClassifier.class);

  public void init() throws InstanceClassifierInitializationException {
    if (log.isDebugEnabled()) {
      log.debug("Initializing the Actor Instance Classifier");
    }
    return;
  }

  protected String removeHashChar(String s) {
    if (s.startsWith("#")) {
      return s.substring(1);
    }
    return s;
  }
  
  /**
   * @see kaos.ontology.matching.InstanceClassifier#classify(java.lang.Object, java.lang.Object, java.lang.Object, java.lang.Object)
   */
  public boolean classify(Object className, Object instance, Object classDesc,
      Object instDesc) throws InstanceClassifierInitializationException,
      InstanceClassifierClassCastException {
    if (log.isDebugEnabled()) {
      log.debug("Classifying + (" + className + ", " + instance + ", "
          + classDesc + ", " + instDesc + ")");
    }
    if (className instanceof String) {
      boolean ret = classify((String) className, instance);

      if (log.isDebugEnabled()) {
        log.debug("Returning " + ret);
      }
      return ret;
    } else {
      return false;
    }
  }

  public abstract boolean classify(String className, Object instance)
      throws InstanceClassifierInitializationException;
}
