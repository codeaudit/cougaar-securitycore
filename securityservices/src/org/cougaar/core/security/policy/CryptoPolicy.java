/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 *
 * </copyright>
 *
 * CHANGE RECORD
 * -
 */

package org.cougaar.core.security.policy;

import java.util.HashMap;
import java.util.Vector;
import java.util.Collection;
import java.util.Iterator;

import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.service.community.CommunityService;

public class CryptoPolicy extends SecurityPolicy {
  /**
   * to whom this policy is applied to.
   */
  public String Name = "UNKNOWN";

  public static final int AGENT = 1;
  public static final int COMMUNITY = 2;
  public static final int SOCIETY = 3;
  public int Type = AGENT;

  public static final int INCOMING = 1;
  public static final int OUTGOING = 2;
  public static final int BOTH = 3;
  public static final int DATAPROTECTION = 4;
  public int Direction = BOTH;
  private HashMap commList = new HashMap();
 
  private HashMap secuMethod = new HashMap();
  public void setSecuMethod(String key, String method){
    Object o = secuMethod.get(key);
    if(o==null){
      Vector sm = new Vector();
      sm.add(method);
      secuMethod.put(key, sm);
    }else{
      Vector sm = (Vector)o;
      if(!sm.contains(method))
        sm.add(method);
    }
  }
  private HashMap secuMethodCom = new HashMap();
  public void setComSecuMethod(String key, String method){
    Object o = secuMethodCom.get(key);
    if(o==null){
      Vector sm = new Vector();
      sm.add(method);
      secuMethodCom.put(key, sm);
      commList.put(key,null); //put in null for now, fill in setCommunityService.
    }else{
      Vector sm = (Vector)o;
      if(!sm.contains(method))
        sm.add(method);
    }
  }

  private HashMap symmSpec = new HashMap();
  public void setSymmSpec(String key, String spec){
    Object o = symmSpec.get(key);
    if(o==null){
      Vector sp = new Vector();
      sp.add(spec);
      symmSpec.put(key, sp);
    }else{
      Vector sp = (Vector)o;
      if(!sp.contains(spec))
        sp.add(spec);
    }
  }
  private HashMap symmSpecCom = new HashMap();
  public void setComSymmSpec(String key, String spec){
    Object o = symmSpecCom.get(key);
    if(o==null){
      Vector sp = new Vector();
      sp.add(spec);
      symmSpecCom.put(key, sp);
      commList.put(key,null); //put in null for now, fill in setCommunityService.
    }else{
      Vector sp = (Vector)o;
      if(!sp.contains(spec))
        sp.add(spec);
    }
  }

  private HashMap signSpec = new HashMap();
  public void setSignSpec(String key, String spec){
    Object o = signSpec.get(key);
    if(o==null){
      Vector sp = new Vector();
      sp.add(spec);
      signSpec.put(key, sp);
    }else{
      Vector sp = (Vector)o;
      if(!sp.contains(spec))
        sp.add(spec);
    }
  }
  private HashMap signSpecCom = new HashMap();
  public void setComSignSpec(String key, String spec){
    Object o = signSpecCom.get(key);
    if(o==null){
      Vector sp = new Vector();
      sp.add(spec);
      signSpecCom.put(key, sp);
      commList.put(key,null); //put in null for now, fill in setCommunityService.
    }else{
      Vector sp = (Vector)o;
      if(!sp.contains(spec))
        sp.add(spec);
    }
  }

  private HashMap asymmSpec = new HashMap();
  public void setAsymmSpec(String key, String spec){
    Object o = asymmSpec.get(key);
    if(o==null){
      Vector sp = new Vector();
      sp.add(spec);
      asymmSpec.put(key, sp);
    }else{
      Vector sp = (Vector)o;
      if(!sp.contains(spec))
        sp.add(spec);
    }
  }
  private HashMap asymmSpecCom = new HashMap();
  public void setComAsymmSpec(String key, String spec){
    Object o = asymmSpecCom.get(key);
    if(o==null){
      Vector sp = new Vector();
      sp.add(spec);
      asymmSpecCom.put(key, sp);
      commList.put(key,null); //put in null for now, fill in setCommunityService.
    }else{
      Vector sp = (Vector)o;
      if(!sp.contains(spec))
        sp.add(spec);
    }
  }

  public Vector getSecuMethod(String key){ 
    Vector v = (Vector)secuMethod.get(key);
    //try community policy if null
    if(v==null && secuMethodCom.size()>0){
      //find which community the agent belongs to and get the policy
      String c = commLookup(key);
      if(c!=null){
        v = (Vector)secuMethodCom.get(c);
      }
    }
    //last try
    if(v==null) v = (Vector)secuMethod.get("DEFAULT");
    return v; 
  }
  public Vector getSymmSpec(String key) { 
    Vector v = (Vector)symmSpec.get(key);
    //try community policy if null
    if(v==null && symmSpecCom.size()>0){
      //find which community the agent belongs to and get the policy
      String c = commLookup(key);
      if(c!=null){
        v = (Vector)symmSpecCom.get(c);
      }
    }
    //last try
    if(v==null) v = (Vector)symmSpec.get("DEFAULT");
    return v; 
  }
  public Vector getAsymmSpec(String key) { 
    Vector v = (Vector)asymmSpec.get(key);
    //try community policy if null
    if(v==null && asymmSpecCom.size()>0){
      //find which community the agent belongs to and get the policy
      String c = commLookup(key);
      if(c!=null){
        v = (Vector)asymmSpecCom.get(c);
      }
    }
    //last try
    if(v==null) v = (Vector)asymmSpec.get("DEFAULT");
    return v; 
  }
  public Vector getSignSpec(String key) { 
    Vector v = (Vector)signSpec.get(key);
    //try community policy if null
    if(v==null && signSpecCom.size()>0){
      //find which community the agent belongs to and get the policy
      String c = commLookup(key);
      if(c!=null){
        v = (Vector)signSpecCom.get(c);
      }
    }
    //last try
    if(v==null) v = (Vector)signSpec.get("DEFAULT");
    return v; 
  }

  //for backward compatiblity
  public SecureMethodParam getSecureMethodParam(String key){
    SecureMethodParam smp = new SecureMethodParam();

    Vector v = (Vector)secuMethod.get(key);
    //if not found use "DEFAULT"
    if(v==null) v=(Vector)secuMethod.get("DEFAULT");
    String method = "invalid";
    if(v!=null) method = (String)(v.firstElement());

    if(method.equalsIgnoreCase("plain")){
      smp.secureMethod = SecureMethodParam.PLAIN;
    }else if(method.equalsIgnoreCase("sign")){
      smp.secureMethod = SecureMethodParam.SIGN;
    }else if(method.equalsIgnoreCase("encrypt")){
      smp.secureMethod = SecureMethodParam.ENCRYPT;
    }else if(method.equalsIgnoreCase("signAndEncrypt")){
      smp.secureMethod = SecureMethodParam.SIGNENCRYPT;
    }else{
      smp.secureMethod = SecureMethodParam.INVALID;
    }

    v = (Vector)symmSpec.get(key);
    if(v==null) v=(Vector)symmSpec.get("DEFAULT");
    if(v!=null) smp.symmSpec = (String)(v.firstElement());

    v = (Vector)asymmSpec.get(key);
    if(v==null) v=(Vector)asymmSpec.get("DEFAULT");
    if(v!=null) smp.asymmSpec = (String)(v.firstElement());

    v = (Vector)signSpec.get(key);
    if(v==null) v=(Vector)signSpec.get("DEFAULT");
    if(v!=null) smp.signSpec = (String)(v.firstElement());

    return smp;
  }

  public void setCommunityService(CommunityService cs){
    //fill community info
    Iterator iter = commList.keySet().iterator();
    while(iter.hasNext()){
      String comName = (String)iter.next();
      Collection c = cs.listEntities(comName);
      commList.put(comName, c);
    }
  }
  //lookup community name
  private String commLookup(String agent){
    Iterator iter = commList.keySet().iterator();
    while(iter.hasNext()){
      String comName = (String)iter.next();
      Collection v = (Collection)commList.get(comName);
      if (v != null){
        if(v.contains(agent)){
          return comName;
        }
      }
    }
    //fall through
    return null;
  }
  
  public String toString() {
  return "crypto policy--NAME:" + Name +
        " TYPE:" + Type +
        " DIRECTION:" + Direction
  ;
  }
}
