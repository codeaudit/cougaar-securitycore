/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

package org.cougaar.core.security.monitoring.plugin;

// Cougaar core services
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.*;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.Entity;
import org.cougaar.core.util.UID;
import org.cougaar.util.UnaryPredicate;

//Security services
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;
import org.cougaar.core.security.util.CommunityServiceUtil;

//IDMEF
import edu.jhuapl.idmef.*;

//java api;
import java.util.Enumeration;
import java.util.Collection;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.Iterator;

import EDU.oswego.cs.dl.util.concurrent.Semaphore;

public abstract class MnRQueryBase extends ComponentPlugin {
  protected DomainService domainService;
  protected CommunityService communityService;
  protected LoggingService loggingService;
  protected CommunityServiceUtil _csu;
  protected MessageAddress myAddress;
 
  private Boolean _isRoot;
 
  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService ds) {
    domainService = ds;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return domainService;
  }
  
  /**
   * Used by the binding utility through reflection to set my CommunityService
   */
  public void setCommunityService(CommunityService cs) {
    communityService = cs;
  }

  /**
   * Used by the binding utility through reflection to get my CommunityService
   */
  public CommunityService getCommunityService() {
    return communityService;
  }
  
  public void setLoggingService(LoggingService ls) {
    loggingService = ls; 
  }
  
  public LoggingService getLoggingService() {
    return loggingService; 
  }
  
  protected void setupSubscriptions() {
    myAddress = getAgentIdentifier();
    if(loggingService == null) {
      loggingService = (LoggingService)
        getServiceBroker().getService(this, LoggingService.class, null); 
    }
    _csu = new CommunityServiceUtil(getServiceBroker());
    
  }

  protected synchronized boolean amIRoot() {
    if (_isRoot == null) {
      _isRoot = new Boolean(_csu.amIRoot(myAddress.toString()));
    }
    return _isRoot.booleanValue();
  } 

/*
  protected Community getMySecurityCommunity() {   
    Community mySecurityCommunity= _csu.getSecurityCommunity(myAddress.toString());
    if(mySecurityCommunity==null) {
      loggingService.warn(" Canot get my role as Manager in any Security Community :"+myAddress.toString() );
    }
    return mySecurityCommunity;
  }
*/
  
  /**
   * @param query
   * @param caps
   * @param sensors - true when the search is performed on the local sensors.
   *                  false when the search is performed on the subordinate managers.
   */
  protected List findAgent(MRAgentLookUp query, CapabilitiesObject caps, boolean sensors) {
  
    if(query==null) {
      loggingService.error("Query was null in findAgent. Sensor type :"+sensors);
      return new ArrayList();
    }
    if(caps==null) {
      loggingService.error("Capabilities was null returning");
      return  new ArrayList();
    }
    if(sensors){
      loggingService.debug("Looking for Local Sensors");
    }
    else {
      loggingService.debug("Looking for Managers");
    }
    
    //printhash(caps);
    Enumeration keys=caps.keys();
    Classification queryClassification=query.classification;
    Source querySource=query.source;
    Target queryTarget=query.target;
    String community=query.community;
    String role=query.role;
    String sourceOfAttack=query.source_agent;
    String targetOfAttack=query.target_agent;
    loggingService.debug("Query receive in  findAgent is :"+ query.toString());
    ArrayList commagents=new ArrayList();
    if((community!=null) && (role!=null)) {
      //  loggingService.debug("Searching with community and role combination :");
      commagents=(ArrayList)searchByCommunityAndRole(community,role);
    }
    else if((community==null)&&(role!=null))  {
      //loggingService.debug("Searching with  role Only :");
      commagents=(ArrayList)searchByRole(role); 
      
    }
    else if((role==null)&&(community!=null) ) {
      //loggingService.debug("Searching with  community Only :");
      commagents=(ArrayList)searchByCommunity(community); 
    }
    loggingService.debug("Printing result of community and role combination :");
    for(int i=0;i<commagents.size();i++) {
      //loggingService.debug("Community and Role result at i:" + i
      //    +". Agent is :" +(String)commagents.get(i));  
    }
    ArrayList classagents;
    ArrayList sourceagents;
    ArrayList targetagents;
    ArrayList sourceofAttackAgents;
    ArrayList targetofAttackAgents;
    ArrayList commonAgents=null;
    classagents=(ArrayList)searchByClassification(queryClassification,caps,sensors);
    // loggingService.debug("Size of result with classification is " +classagents.size() );
    
   
    sourceagents=(ArrayList)searchBySource(querySource,caps,sensors);
    // loggingService.debug("Size of result with source  is :" +sourceagents.size() );
   
    targetagents=(ArrayList)searchByTarget(queryTarget,caps,sensors);
    // loggingService.debug("Size of result with target is :" +targetagents.size() );
    
    //loggingService.debug("Size of result with target is :" +targetagents.size() );
    sourceofAttackAgents=(ArrayList)searchBySourceOfAttack(sourceOfAttack,caps,sensors);
    //loggingService.debug("Size of result with source of ATTACK  is :" +sourceofAttackAgents.size() );
   
    targetofAttackAgents=(ArrayList)searchByTargetOfAttack(targetOfAttack,caps,sensors);
    // loggingService.debug("Size of result with target of ATTACK  is :" +targetofAttackAgents.size() );
    
    if(((community!=null) || (role!=null))&& (commagents.isEmpty())) {
      loggingService.debug(" Community Rol combination is empty :");
      commonAgents=new ArrayList();
    }
    else {
      boolean iscomagentset=false;
      if((community!=null) || (role!=null)) {
        iscomagentset=true;
      }
      //if(queryClassification!=null) {
      //loggingService.debug("Query for classification was not null:");
      if(!iscomagentset) {
        commonAgents=classagents;
        iscomagentset=true;
      }
      else {
        commonAgents=(ArrayList)findCommanAgents(commagents,classagents);
      }
      if(!iscomagentset) {
        commonAgents=sourceagents;
        iscomagentset=true;
      }
      else{
        commonAgents=(ArrayList)findCommanAgents(commonAgents,sourceagents);
      }
      if(!iscomagentset) {
        commonAgents=targetagents;
        iscomagentset=true;
      }
      else {
        commonAgents=(ArrayList)findCommanAgents(commonAgents,targetagents);
      }
      if(!iscomagentset) {
        commonAgents=sourceofAttackAgents;
        iscomagentset=true;
      }
      else {
        commonAgents=(ArrayList)findCommanAgents(commonAgents,sourceofAttackAgents);
      }
      if(!iscomagentset) {
        commonAgents=targetofAttackAgents;
        iscomagentset=true;
      }
      else {
        commonAgents=(ArrayList)findCommanAgents(commonAgents,targetofAttackAgents);
      }
    }
    /*
      loggingService.debug("Printing result of query:" + sensors);
      for(int i=0;i<commonAgents.size();i++) {
      loggingService.debug("result at i:"+i +" agent is :"+(String)commonAgents.get(i));  
      }
     */
    return commonAgents;
    
  }
  
  
  private List findCommanAgents(List list1,List list2) {
    ArrayList commonList=new ArrayList();
    /*
      if(list1.isEmpty()) {
      return list2;
      }
      if(list2.isEmpty()){
      return list1;
      }
     */
    Iterator iter=list1.iterator();
    String agentname;
    while(iter.hasNext()) {
      agentname=(String)iter.next();
      if(list2.contains(agentname)) {
        commonList.add(agentname);
      } 
    }
    return commonList;
  }
  
  private List searchByClassification(Classification searchClassification,CapabilitiesObject caps, boolean sensors) {
   
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    ArrayList agentlist=new ArrayList();
    /*if(searchClassification==null) {
      return agentlist;
      }
     */
    if (loggingService.isDebugEnabled()) {
      if(searchClassification!=null){
        loggingService.debug("In find agent FUNCTION  query is :"+searchClassification.getName()+
            "Origin  "+searchClassification.getOrigin() );
      }
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
        //loggingService.debug("In capabilities object : Key is "+ key  );
      }
      Classification [] classifications=reg.getClassifications();
      if(classifications==null) {
        return agentlist;
      }
      if(searchClassification==null) {
        //loggingService.debug("got search classification as null will return all sensors :");
        if(sensors) {
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //  loggingService.debug("Analyzer id is :"+ reg.getAgentName());
            //loggingService.debug("Adding sensor key when classification is null :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  manager when classification is null :");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("Adding security manager  key when classification is null :"+key);
            agentlist.add(key);
          }
        }
        continue;
      }
      if(isClassificationPresent(searchClassification,classifications)) {
        //loggingService.debug("Got calssification equal:" + key);
        if(sensors) {
          //loggingService.debug("Looking for sensors agents :");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug("Analyzer id is :"+ reg.getAgentName());
            //loggingService.debug("Adding sensor key :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  manager :");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("Adding security manager  key :"+key);
            agentlist.add(key);
          }
        }
      }
    }
    return agentlist;
  }
  
  private List searchBySource(Source searchSource,CapabilitiesObject caps, boolean sensors) {
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    Source [] sources=null;
    ArrayList agentlist=new ArrayList();
    /*
      if(searchSource==null) {
      return agentlist;
      }
     */
    if (loggingService.isDebugEnabled()) {
      //loggingService.debug("In  searchBySources FUNCTION  query is :"+searchSource);
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
        //loggingService.debug(" in capabilities object : Key is "+ key );
      }
      sources=reg.getSources();
      if(searchSource==null) {
        if(sensors) {
          //loggingService.debug("Looking for sensors agents when query source is null :");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug(" adding sensor key when query source is null :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  managerwhen query source is null :");
          if(reg.getType().equals( IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("adding security manager  key when query source is null :"+key);
            agentlist.add(key);
          }
        }
        continue;
      }
      if(sources==null) {
        return agentlist;
      }
      if(isSourceORTargetPresent(searchSource,sources)) {
        //loggingService.debug("Got source equal:" + reg.getType());
        if(sensors) {
          //loggingService.debug("Looking for sensors agents :");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug(" adding sensor key :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  manager :");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("adding security manager  key :"+key);
            agentlist.add(key);
          }
	  
        }
      }
    }
    return agentlist;
    
  }
  
  private List searchByTarget(Target searchTarget,CapabilitiesObject caps, boolean sensors) {
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    Target [] targets=null;
    ArrayList agentlist=new ArrayList();
    /*if(searchTarget==null) {
      return agentlist;
      }
     */
    if (loggingService.isDebugEnabled()) {
      //loggingService.debug(" in  searchByTargets FUNCTION  query is :"+searchTarget);
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
        //loggingService.debug(" in capabilities object : Key is "+ key );
      }
      targets=reg.getTargets();
      if(searchTarget==null) {
        if(sensors) {
          //loggingService.debug("Looking for sensors agents when query target is null:");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug(" adding sensor key when query target is null :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  manager when query target is null:");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("Adding security manager  key when query target is null :"+key);
            agentlist.add(key);
          }
        }
        continue;
      }
      if(targets==null) {
        return agentlist;
      } 
      if(isSourceORTargetPresent(searchTarget,targets)) {
        //loggingService.debug(" Got source equal:" + reg.getType());
        if(sensors) {
          //loggingService.debug("Looking for sensors agents :");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug(" adding sensor key :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  manager :");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("Adding security manager  key :"+key);
            agentlist.add(key);
          }
	  
        }
      }
    }
    return agentlist;
  }
  
  private List searchBySourceOfAttack(String agentname,CapabilitiesObject caps, boolean sensors) {
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    Source []sources =null;
    AdditionalData [] additionaldatas=null;
    AdditionalData data=null;
    ArrayList agentlist=new ArrayList();
    /*if(agentname==null) {
      return agentlist;
      }
     */
    if (loggingService.isDebugEnabled()) {
      //loggingService.debug(" in  searchBySourcesofattack  FUNCTION  query is :"+agentname);
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
        //loggingService.debug(" in capabilities object : Key is "+ key );
      }
      sources=reg.getSources();
      additionaldatas=reg.getAdditionalData();
      if(agentname==null) {
        if(sensors) {
          //loggingService.debug("Looking for sensors agents when source of attack is null  :");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug(" adding sensor key when source of attack is null:"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  managerwhen source of attack is null :");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug(" adding security manager  keywhen source of attack is null  :"+key);
            agentlist.add(key);
          }
        }
        continue;
      }
      if(sources==null) {
        return agentlist;
      }
      if(additionaldatas==null) {
        return agentlist;
      }
      for(int i=0;i<additionaldatas.length;i++) {
        data=additionaldatas[i];
        org.cougaar.core.security.monitoring.idmef.Agent agentinfo=null;
        if((data.getType().equalsIgnoreCase("xml"))&&(data.getXMLData()!=null)) {
          if(data.getXMLData() instanceof org.cougaar.core.security.monitoring.idmef.Agent){ 
            agentinfo=( org.cougaar.core.security.monitoring.idmef.Agent)data.getXMLData();
          }
        }
        if(agentinfo!=null) {
          if(agentname.trim().equals(agentinfo.getName())) {
            String [] ref=agentinfo.getRefIdents();
            if(ref!=null) {
              String refstring=null;
              boolean found=true;
              for(int x=0;x<ref.length;x++) {
                refstring=ref[x];
                for(int z=0;z<sources.length;z++) {
                  if(refstring.trim().equals(sources[z].getIdent().trim())) {
                    found=true;
                    break;
                  }
                }
                if(found)
                  break;
              }
              if(found) {
                if(sensors) {
                  //    loggingService.debug("Looking for sensors agents :");
                  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
                    //loggingService.debug(" adding sensor key :"+key);
                    agentlist.add(reg.getAgentName());
                  }
                }
                else {
                  //loggingService.debug("Looking for Security  manager :");
                  if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
                    //loggingService.debug(" adding security manager  key :"+key);
                    agentlist.add(key);
                  }
                }
		
              }
            }
          }
        }
      }
    }
    return agentlist;
  }
  
  private List searchByTargetOfAttack(String agentname,CapabilitiesObject caps, boolean sensors) {
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    Target [] targets =null;
    AdditionalData [] additionaldatas=null;
    AdditionalData data=null;
    ArrayList agentlist=new ArrayList();
    /*if(agentname==null) {
      return agentlist;
      }
     */
    if (loggingService.isDebugEnabled()) {
      //loggingService.debug(" in  searchByTargetofattack  FUNCTION  query is :"+agentname);
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
        //loggingService.debug(" in capabilities object : Key is "+ key );
      }
      targets=reg.getTargets();
      additionaldatas=reg.getAdditionalData();
      if(agentname==null) {
        if(sensors) {
          //loggingService.debug("Looking for sensors agents when target of attack is null  :");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug(" adding sensor key when target of attack is null :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  manager when target of attack is null :");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("Adding security manager  key when target of attack is null:"+key);
            agentlist.add(key);
          }
        }
        continue;
      }
      if(targets==null) {
        return agentlist;
      }
      if(additionaldatas==null) {
        return agentlist;
      }
      for(int i=0;i<additionaldatas.length;i++) {
        data=additionaldatas[i];
        org.cougaar.core.security.monitoring.idmef.Agent agentinfo=null;
        if((data.getType().equalsIgnoreCase("xml"))&&(data.getXMLData()!=null)) {
          if(data.getXMLData() instanceof org.cougaar.core.security.monitoring.idmef.Agent){ 
            agentinfo=( org.cougaar.core.security.monitoring.idmef.Agent)data.getXMLData();
          }
        }
        if(agentinfo!=null) {
          if(agentname.trim().equals(agentinfo.getName())) {
            String [] ref=agentinfo.getRefIdents();
            if(ref!=null) {
              String refstring=null;
              boolean found=true;
              for(int x=0;x<ref.length;x++) {
                refstring=ref[x];
                for(int z=0;z<targets.length;z++) {
                  if(refstring.trim().equals(targets[z].getIdent().trim())) {
                    found=true;
                    break;
                  }
                }
                if(found)
                  break;
              }
              if(found) {
                if(sensors) {
                  //loggingService.debug("Looking for sensors agents :");
                  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
                    //loggingService.debug(" adding sensor key :"+key);
                    agentlist.add(reg.getAgentName());
                  }
                }
                else {
                  // loggingService.debug("Looking for Security  manager :");
                  if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
                    //loggingService.debug("Adding security manager  key :"+key);
                    agentlist.add(key);
                  }
                }
		
              }
            }
          }
        }
      }
    }
    return agentlist;
    // return new ArrayList();
  }

  private class Status {
    public Object value;
  }

  protected List searchByCommunity (String community) {
    ArrayList list=new ArrayList();
    if(communityService==null) {
      //loggingService.error(" Community Service is null in searchByCommunity " +myAddress.toString()); 
      return list;
    }
    if(community==null) {
      //loggingService.error("Community is null in searchByCommunity " +myAddress.toString()); 
      return list;
    }

    final Status status = new Status();
    final Semaphore s = new Semaphore(0);
    CommunityResponseListener crl = new CommunityResponseListener() {
	public void getResponse(CommunityResponse resp) {
	  Object response = resp.getContent();
	  if (!(response instanceof Community)) {
	    String errorString = "Unexpected community response class:"
	      + response.getClass().getName() + " - Should be a Community";
	    loggingService.error(errorString);
	    throw new RuntimeException(errorString);
	  }
	  status.value = (Community) response;
	  s.release();
	}
      };
    // TODO: do this truly asynchronously.
    communityService.getCommunity(community, crl);
    try {
      s.acquire();
    } catch (InterruptedException ie) {
      loggingService.error("Error in searchByCommunity:", ie);
    }

    Collection agents=((Community)status.value).getEntities();
    Iterator agentiter=agents.iterator();
    MessageAddress agent;
    while(agentiter.hasNext()) {
      agent=(MessageAddress)agentiter.next();
      list.add(agent.toString());
    }
    
    return list;
  }

  protected List searchByRole(String role) {
    ArrayList list=new ArrayList();
    if(communityService==null) {
      //loggingService.error(" Community Service is null in searchByRole " +myAddress.toString()); 
      return list;
    }
    if(role==null) {
      loggingService.error(" Role  is null in searchByRole " +myAddress.toString()); 
      return list;
    }
    
    // This used to be:
    //     Collection communities =communityService.listAllCommunities();
    // However, listAllCommunities is no longer supported.
    loggingService.warn("Query with empty community is no longer supported."
      + " The community must be specified in the security console.");

    final Status status = new Status();
    final Semaphore s = new Semaphore(0);
    CommunityResponseListener crl = new CommunityResponseListener() {
	public void getResponse(CommunityResponse resp) {
	  Object response = resp.getContent();
	  if (!(response instanceof Set)) {
	    String errorString = "Unexpected community response class:"
	      + response.getClass().getName() + " - Should be a Set";
	    loggingService.error(errorString);
	    throw new RuntimeException(errorString);
	  }
	  status.value = (Set) response;
	  s.release();
	}
      };
    // TODO: do this truly asynchronously.
    String filter = "(Role=" + role + ")";
    Collection agents =
      communityService.searchCommunity(null, filter, 
                                       true, Community.AGENTS_ONLY, crl);
    if (agents == null) {
      try {
        s.acquire();
      } catch (InterruptedException ie) {
        loggingService.error("Error in searchByCommunity:", ie);
      }
      agents=(Set)status.value;
    }

    Iterator iter=agents.iterator();
    while(iter.hasNext()) {
      Entity entity = (Entity)iter.next();
      list.add(entity.getName());
    }
    return list; 
     
  }
  protected List searchByCommunityAndRole(String community,String role) {
    ArrayList list= new ArrayList();
    if(communityService==null) {
      loggingService.error(" Community Service is null in searchByCommunityAndRole " +myAddress.toString()); 
      return list;
    }
    if(community==null) {
      loggingService.error(" community is null in searchByCommunityAndRole " +myAddress.toString()); 
      return list;
    } 
    if(role==null) {
      loggingService.error(" Role  is null in searchByCommunityAndRole " +myAddress.toString()); 
      return list;
    }

    final Status status = new Status();
    final Semaphore s = new Semaphore(0);
    CommunityResponseListener crl = new CommunityResponseListener() {
	public void getResponse(CommunityResponse resp) {
	  Object response = resp.getContent();
	  if (!(response instanceof Set)) {
	    String errorString = "Unexpected community response class:"
	      + response.getClass().getName() + " - Should be a Set";
	    loggingService.error(errorString);
	    throw new RuntimeException(errorString);
	  }
	  status.value = (Set) response;
	  s.release();
	}
      };
    // TODO: do this truly asynchronously.
    String filter = "(Role=" + role + ")";
    Collection agents =
      communityService.searchCommunity(community, filter, true,
                                       Community.AGENTS_ONLY, crl);
    if (agents == null) {
      try {
        s.acquire();
      } catch (InterruptedException ie) {
        loggingService.error("Error in searchByCommunity:", ie);
      }
      agents=(Set)status.value;
    }

    //Collection searchresult=communityService.searchByRole(community,role);
    Iterator roleiter=agents.iterator();
    while(roleiter.hasNext()) {
      Entity entity = (Entity) roleiter.next();
      list.add(entity.getName());
    }	
    return list;
  }
  
  protected boolean areClassificationsEqual(Classification existingclassification,Classification newclassification) {
    boolean equal=false;
    if((existingclassification.getOrigin().trim().equalsIgnoreCase(newclassification.getOrigin().trim()))
        &&(existingclassification.getName().trim().equalsIgnoreCase(newclassification.getName().trim()))) {
      // loggingService.debug(" returning true  :");
      return true;
    }   
    return equal;
  }
  
  protected boolean isClassificationPresent(Classification queryclassification,Classification[] classificationList) {
    Classification currentclassification;
    boolean isclassification=false;
    for(int i=0;i<classificationList.length;i++) {
      currentclassification=classificationList[i];
      /*loggingService.debug("current classification :"+ classificationtoString(currentclassification));
        loggingService.debug("query classification :"+ classificationtoString(queryclassification));
       */
      if(areClassificationsEqual(currentclassification,queryclassification)){
        isclassification=true;
        return isclassification;
      }
    }
    return isclassification  ;
  }
  
  protected boolean isSourceORTargetPresent(Object inquery,Object[] inObjectArray) {
    boolean ispresent=false;
    //loggingService.debug("Size of source or target is :"+ inObjectArray.length);
    for(int i=0;i<inObjectArray.length;i++) {
      if(areSourceORTargetEqual(inObjectArray[i],inquery)){
        ispresent=true;
        return ispresent;
      }
      else {
        //  loggingService.debug(" source or Target is not present :");
      }
    }
    return ispresent ;
  }
  
  protected boolean areSourceORTargetEqual(Object existing , Object inquery) {
    boolean equal=false;
    boolean nodeequal=false;
    boolean userequal=false;
    boolean serviceequal=false;
    boolean processequal=false;
    if(!(((existing instanceof Source) && (inquery instanceof Source))||
           ((existing instanceof Target) && (inquery instanceof Target)))) {
      return equal;
    }
    IDMEF_Node existingNode=null;
    IDMEF_Node queryNode=null;
    User existingUser=null;
    User queryUser=null;
    Service existingService=null;
    Service queryService=null;
    IDMEF_Process existingProcess=null;
    IDMEF_Process queryProcess=null;
    if((existing instanceof Source) && (inquery instanceof Source)) {
      Source existingSource=(Source)existing;
      Source inquerySource=(Source)inquery;
      existingNode=existingSource.getNode();
      queryNode=inquerySource.getNode();
      existingUser=existingSource.getUser();
      queryUser=inquerySource.getUser();
      existingService=existingSource.getService();
      queryService=inquerySource.getService();
      existingProcess=existingSource.getProcess();
      queryProcess=inquerySource.getProcess();
    }
    if((existing instanceof Target) && (inquery instanceof Target)) {
      Target existingTarget=(Target)existing;
      Target inqueryTarget=(Target)inquery;
      existingNode=existingTarget.getNode();
      queryNode=inqueryTarget.getNode();
      existingUser=existingTarget.getUser();
      queryUser=inqueryTarget.getUser();
      existingService=existingTarget.getService();
      queryService=inqueryTarget.getService();
      existingProcess=existingTarget.getProcess();
      queryProcess=inqueryTarget.getProcess();
      
    } 
    if((existingNode!=null)&&(queryNode!=null)){
      boolean nameequal=false;
      boolean addressequal=false;
      boolean categoryequal=false;
      String queryname=queryNode.getName();
      String existingname=existingNode.getName();
      Address queryAddress []=queryNode.getAddresses();
      Address existingAddress[]=existingNode.getAddresses();
      String queryCategory=queryNode.getCategory();
      String existingCategory=existingNode.getCategory();
      if(queryname==null) {
        nameequal=true;
        //loggingService.debug("In Idmef node queryname was null:");	
      }
      if((queryname!=null)&&(existingname!=null)) {
        if(queryname.trim().equals(existingname.trim())) {
          //loggingService.debug("In Idmef node queryname are equal:");
          nameequal=true;
        }
      }
      if(queryAddress==null) {
        addressequal=true;
        //loggingService.debug("In Idmef node queryAddress was null:");
      }
      if((queryAddress!=null)&&(existingAddress!=null)) {
        loggingService.debug("In Idmef queryAddress && existing address is not  null:");
        if(existingAddress.length>=queryAddress.length) {
          Address inqueryAddress=null;
          for(int i=0;i<queryAddress.length;i++) {
            inqueryAddress=queryAddress[i];
            if(!containsAddress(inqueryAddress,existingAddress)) {
              addressequal=false;
              break;
            }
          }
          addressequal=true;
          //loggingService.debug("In Idmef node address are equal :");
        }
	
      }
      if(queryCategory==null) {
        //loggingService.debug("In Idmef node queryCategory was null:");
        categoryequal=true;
      }
      if((queryCategory !=null) && (existingCategory!=null)) {
        //loggingService.debug("query category is :"+ queryCategory);
        //loggingService.debug("existing Category category is :"+ existingCategory);
        if(queryCategory.trim().equals(existingCategory.trim())) {
          loggingService.debug("In Idmef node queryCategory are equal :");
          categoryequal=true;
        }
      }
      if(existingCategory==null){
        //loggingService.debug("existing Category category is NULL :");
      }
      
      if( nameequal &&  addressequal && categoryequal) {
        //loggingService.debug("In Idmef node are equal :");
        nodeequal=true;
      }
      
    }
    else if((existingNode==null)&&(queryNode==null)){
      nodeequal=true;
      //loggingService.debug("In Idmef node are equal :");
    }
    else if(queryNode==null) {
      nodeequal=true;
    }
          
    if((existingUser!=null)&&(queryUser!=null)){
      UserId [] queryUserId=queryUser.getUserIds();
      UserId [] existingUserId=existingUser.getUserIds();
      if(queryUserId==null) {
        //loggingService.debug("In Idmef query User  is null  :");
        userequal =true;
      }
      if((queryUserId !=null) &&(existingUserId!=null)) {
        if(existingUserId.length>=queryUserId.length) {
          UserId userid=null;
          for(int i=0;i<queryUserId.length;i++) {
            userid=queryUserId[i];
            if(!containsUserId(userid,queryUserId)) {
              userequal=false;
              break;
            }
          }
          userequal=true;
          //loggingService.debug("In Idmef query User  is true  :");
        }
      }
    }
    else if((existingUser==null)&&(queryUser==null)){
      //loggingService.debug("In Idmef query User  is true  :");
      userequal=true;
    }
    else if(queryUser==null){
      userequal=true;
    }
    
    if((existingService!=null)&&(queryService!=null)){
      String existingServiceName=existingService.getName();
      String queryServiceName=queryService.getName();
      Integer existingPort=existingService.getPort();
      Integer queryPort=queryService.getPort();
      String existingPortList=existingService.getPortlist();
      String queryPortList=queryService.getPortlist();
      String existingProtocol=existingService.getProtocol();
      String queryprotocol=queryService.getProtocol();
      boolean nameequal=false;
      boolean portequal=false;
      boolean portlistequal=false;
      boolean protocolequal=false;
      if(queryServiceName==null) {
        nameequal=true;
      }
      if((existingServiceName!=null) && (queryServiceName!=null)) {
        if(existingServiceName.trim().equals(queryServiceName.trim())) {
          nameequal=true;
        }
      }
      if(queryPort==null) {
        portequal=true;
      }
      if((existingPort!=null) &&(queryPort!=null)) {
        if(existingPort.intValue()==queryPort.intValue()) {
          portequal=true;
        }
      }
      if(queryPortList==null) {
        portlistequal =true;
      }
      if((existingPortList!=null)&&(queryPortList!=null)) {
        if(existingPortList.trim().equals(queryPortList.trim())) {
          portlistequal=true;
        }
      }
      if(queryprotocol==null) {
        protocolequal=true;
      }
      if((existingProtocol!=null) &&(queryprotocol!=null)) {
        if(existingProtocol.trim().equals(queryprotocol.trim())) {
          protocolequal=true;
        }
      }
	
      if( nameequal &&  portequal &&  portlistequal &&  protocolequal) {
        serviceequal=true;
        //loggingService.debug("In Idmef serviceequal  is true  :");
      }
    }
    else if((existingService==null)&&(queryService==null)){
      //loggingService.debug("In Idmef serviceequal  is true  :");
      serviceequal=true;
    }
    else if(queryService==null) {
      serviceequal=true;
    }
    
    if((existingProcess!=null)&&(queryProcess!=null)){
      String existingPath=existingProcess.getPath();
      String queryPath=queryProcess.getPath();
      String existingName=existingProcess.getName();
      String queryName=queryProcess.getName();
      boolean processNameequal=false;
      boolean processPathequal=false;
      if(queryPath==null) {
        processPathequal=true;
      }
      if((existingPath!=null) &&(queryPath!=null)) {
        if(existingPath.trim().equals(queryPath.trim())) {
          processPathequal=true;
        }
      }
      if(queryName==null) {
        processNameequal=true;
      }
      if((existingName!=null) &&(queryName!=null)) {
        if(existingName.trim().equals(queryName.trim())) {
          processNameequal=true;
        }
      }
      if(processPathequal && processNameequal) {
        processequal=true;
        //loggingService.debug("In Idmef processequal  true :");
      }
    }
    else if((existingProcess==null)&&(queryProcess==null)){
      //loggingService.debug("In Idmef processequal  true :");
      processequal=true;
    }
    else if(queryProcess==null) {
      processequal=true;
    }
    if( nodeequal &&  userequal &&  serviceequal &&  processequal) {
      loggingService.debug("Either source or target is equal  :");
      equal=true;
    }
    return equal;
     
  }
 
  protected boolean containsUserId(UserId inUserId, UserId [] arrayUserId) {
    boolean contains=false;
    UserId userid;
    if(inUserId==null) {
      return contains;
    }
    boolean nameequal=false;
    boolean numberequal=false;
    if(arrayUserId!=null) {
      for(int i=0;i<arrayUserId.length;i++) {
        userid=arrayUserId[i];
        String inName=inUserId.getName();
        String name=userid.getName();
        Integer innumber=inUserId.getNumber();
        Integer number=userid.getNumber();
        if((inName!=null)&& (name!=null)) {
          if(inName.trim().equals(name.trim())) {
            nameequal=true;
          }
        }
        if((innumber!=null)&&(number!=null)) {
          if(innumber.intValue()==number.intValue()) {
            numberequal=true;
          }
        }
        if(nameequal && numberequal) {
          contains=true;
          return contains;
        }
	    
      }
    }
    return contains;
  }
    
  protected boolean containsAddress(Address anAddress, Address [] arrayAddress) {
    boolean contains=false;
    Address address;
    if(anAddress==null) {
      return contains;
    }
    if(arrayAddress!=null) {
      //myAddresses=this.getAddresses();
      for(int i=0;i<arrayAddress.length;i++) {
        address=arrayAddress[i];
        String stringaddress=address.getAddress();
        String inaddress=anAddress.getAddress();
        String category=address.getCategory();
        String incategory=anAddress.getCategory();
        boolean addressequal=false;
        boolean categoryequal=false;
        if((stringaddress!=null)&& (inaddress!=null)) {
          if(stringaddress.trim().equals(inaddress.trim())) {
            addressequal=true;
          }
        }
        else if((stringaddress==null)&& (inaddress==null)) {
          addressequal=true;
        }
        if((category!=null)&&(incategory!=null))  {
          if(category.trim().equals(incategory.trim())) {
            categoryequal=true;
          }
        }
        else if((category==null)&&(incategory==null))  {
          categoryequal=true;
        }
        if(addressequal && categoryequal) {
          contains=true;
          return contains;
        }
      }
    }
    return contains;
  }
  
  protected boolean isRelayQueryOriginator(UID givenUID, Collection queryMappingCol ) {
    boolean isoriginator=false;
    QueryMapping querymapping=null;
    if(!queryMappingCol.isEmpty()){
      if (loggingService.isDebugEnabled()) {
        //loggingService.debug("Going to find if this relay id is originator of query :"); 
      }
      Iterator iter=queryMappingCol.iterator();
      while(iter.hasNext()) {
        querymapping=(QueryMapping)iter.next();
        if(querymapping.getRelayUID().equals(givenUID)) {
          isoriginator=true;
          return isoriginator;
        }
      }
    }
    return isoriginator;
  }
  
  protected boolean isRelaySubQuery(UID givenUID, Collection queryMappingCol ) {
    QueryMapping foundqMapping=null;
    ArrayList relayList;
    OutStandingQuery outstandingq;
    boolean issubquery=false;
    //QueryMapping tempqMapping;
    if(!queryMappingCol.isEmpty()){
      if (loggingService.isDebugEnabled()) {
        //loggingService.debug("Going to find uid from list of Query mapping Objects on bb"+queryMappingCol.size()); 
      }
      Iterator iter=queryMappingCol.iterator();
      while(iter.hasNext()) {
        foundqMapping=(QueryMapping)iter.next();
        relayList=foundqMapping.getQueryList();
        if(relayList==null) {
          return false;
        }
        for(int i=0;i<relayList.size();i++) {
          outstandingq=(OutStandingQuery)relayList.get(i);
          if(outstandingq.getUID().equals(givenUID)) {
            if (loggingService.isDebugEnabled()) {
              //loggingService.debug(" Found given uid :"+ givenUID +" in object with UID :"+outstandingq.getUID());
            }
            issubquery=true;
            return issubquery;
          }
        }
      }
    } 
    else {
      return issubquery;
    }
    return issubquery;
  }
  
  protected QueryMapping findQueryMappingFromBB(UID givenUID, Collection queryMappingCol ) {
    QueryMapping foundqMapping=null;
    ArrayList relayList;
    OutStandingQuery outstandingq;  
    //QueryMapping tempqMapping;
    if(!queryMappingCol.isEmpty()){
      
      Iterator iter=queryMappingCol.iterator();
      while(iter.hasNext()) {
        foundqMapping=(QueryMapping)iter.next();
        if(foundqMapping.getRelayUID().equals(givenUID)) {
          return foundqMapping;
        }
        relayList=foundqMapping.getQueryList();
        if(relayList==null) {
          continue;
        }
        for(int i=0;i<relayList.size();i++) {
          outstandingq=(OutStandingQuery)relayList.get(i);
          if(outstandingq.getUID().equals(givenUID)) {
            return foundqMapping;
          }
        }
      }
      
    }
    else {
      return null;
    }
    return null;
  }
  
  protected void printhash(CapabilitiesObject cap) {
    Enumeration keys=cap.keys();
    String key=null;
    RegistrationAlert registration=null;
    loggingService.debug(" CAPABILITIES OBJECT IN ADDRESS :"+myAddress.toString());
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(" KEY IN CAPABILITIES OBJECT IS :"+key);
      }
      registration=(RegistrationAlert)cap.get(key);
      loggingService.debug(" data of  alert is :"+registration.toString());
    }
  }

  public CmrRelay findCmrRelay(UID key) {
    CmrRelay relay = null;
    final UID fKey = key;
    Collection relays = getBlackboardService().query( new UnaryPredicate() {
        public boolean execute(Object o) {
          if (o instanceof CmrRelay) {
            CmrRelay relay = (CmrRelay)o;
            return ((relay.getUID().equals(fKey)) &&
                    (relay.getContent() instanceof MRAgentLookUp));
          }
          return false;
        }
      });
    if(!relays.isEmpty()) {
      relay = (CmrRelay)relays.iterator().next();
    }
    return relay;
  } 
  
}
