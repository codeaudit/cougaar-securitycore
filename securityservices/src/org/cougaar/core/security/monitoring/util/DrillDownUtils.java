/*
 * <copyright>
 *  Copyright 1997-2003 CougaarSoftware Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
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

package org.cougaar.core.security.monitoring.util;

import edu.jhuapl.idmef.IDMEF_Message;

// Cougaar core services
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.util.UID;



import edu.jhuapl.idmef.IDMEFTime;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Alert;



import java.io.Serializable;

public class DrillDownUtils {

  public static boolean matchParentUID(IDMEF_Message message,UID givenUID){
    boolean matches =false;
    if(!(message instanceof Alert)){
      return matches;
    }
    Alert alert=(Alert)message;
    AdditionalData [] additionalDataArray=alert.getAdditionalData();
    if(additionalDataArray==null || additionalDataArray.length==0) {
      return matches;
    }
    AdditionalData additionalData=null;
    for(int i=0;i<additionalDataArray.length;i++) {
      additionalData=additionalDataArray[i];
      if(additionalData.getMeaning().equals(DrillDownQueryConstants.PARENT_UID)) {
        if(additionalData.getAdditionalData().equals(givenUID.toString())){
          matches=true;
          return matches;
        }
      }
    }
    return matches; 
  }

  public static  UID getUID (IDMEF_Message message, String meaning){
    UID uid=null;
    if(!(message instanceof Alert)){
      return uid;
    }
    Alert alert=(Alert)message;
    AdditionalData [] additionalDataArray=alert.getAdditionalData();
    if(additionalDataArray==null || additionalDataArray.length==0) {
      return uid;
    }
    AdditionalData additionalData=null;
    String stringid=null;
    boolean found=false;
    for(int i=0;((i<additionalDataArray.length)&&(!found));i++) {
      additionalData=additionalDataArray[i];
      if(additionalData.getMeaning().equals(meaning)) {
        stringid=additionalData.getAdditionalData();
        found=true;
      }
    }
    if(stringid==null) {
       return uid;
    }
    uid=UID.toUID(stringid);
    return uid;
    
    
  }

  
}
