/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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

package org.cougaar.core.security.policy.builder;

import java.net.*;

import antlr.Token;

import java.io.*;
import java.util.*;

import com.hp.hpl.jena.daml.DAMLModel;

import jtp.ReasoningException;

import kaos.kpat.tunnel.TunnelClient;
import kaos.ontology.DefaultOntologies;
import kaos.ontology.repository.KAoSContext;
import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.ontology.util.JTPStringFormatUtils;
import kaos.ontology.util.ValueNotSet;

import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.userauth.UserAuthenticatorImpl;

public class TunnelledOntologyConnection extends OntologyConnection
{
  /*
   * For various reasons, this class needs intelligence.  I also
   * provide a convenience method for outsiders to load intelligence.
   */

  private static TunnelClient _brains = null;



  /**
   * Opens a tunnelled connection (through the policy servlet) to the
   * KAoSDirectoryService.  
   */
  public TunnelledOntologyConnection(String uri)
    throws IOException
  {
    super();
    try {
      UserAuthenticatorImpl   userAuth  = new UserAuthenticatorImpl();
      SecurityServiceProvider secprov   = new SecurityServiceProvider();
      userAuth.init(secprov);
      _brains = new TunnelClient(uri);
    } catch (Exception e) {
      IOException ioe =  new IOException("Could not tunnel to client: " + uri);
      ioe.initCause(e);
      throw ioe;
    }
  }



  /**
   * Opens a tunnelled connection (through the policy servlet) to the
   * KAoSDirectoryService.  
   */
  public TunnelledOntologyConnection(String  uri, 
                                     String  user,
                                     char [] password)
    throws IOException
  {
    super();
    try {
      UserAuthenticatorImpl   userAuth  = new UserAuthenticatorImpl(user);
      SecurityServiceProvider secprov   = new SecurityServiceProvider();
      userAuth.init(secprov);
      userAuth.authenticateWithPassword(user, password);
      _brains = new TunnelClient(uri);
    } catch (Exception e) {
      IOException ioe =  new IOException("Could not tunnel to client: " + uri);
      ioe.initCause(e);
      throw ioe;
    }
  }

  /*
   * The following are tunnelled interfaces.
   */
  public Set getInstancesOf (String conceptName) 
    throws Exception
  {
    return _brains.getInstancesOf(conceptName);
  }

  // not in tunnelclient
  public Vector getPropertiesApplicableTo (String className)
    throws ReasoningException
  {
    try {
      return _brains.getPropertiesApplicableTo(className);
    } catch (Exception e) {
      ReasoningException re 
        = new ReasoningException("Failed to get properties for class "
                                 + className);
      re.initCause(e);
      throw re;
    }
  }

  // not in tunnelclient
  public String getRangeOnPropertyForClass(String className, 
                                           String propertyName) 
    throws ReasoningException
  {
    try {
      return _brains.getRangeOnPropertyForClass(className,propertyName);
    } catch (Exception e) {
      ReasoningException re
        = new ReasoningException("Failed to get the range for the property "
                                 + propertyName + " which has domain " +
                                 className);
      re.initCause(e);
      throw re;
    }
  }

  public Set getSubClassesOf (String className) 
    throws Exception
  {
    return _brains.getSubClassesOf(className);
  }


  public boolean testTrue (String statement) 
    throws ReasoningException
  {
    try {
      return _brains.testTrue(statement);
    } catch (Exception e) {
      ReasoningException re
        = new ReasoningException("Could not ask question " + statement);
      re.initCause(e);
      throw re;
    }
  }

  /*
   * Not implemented on the tunnelled ontology
   */

  public void loadOntology (DAMLModel myDAMLModel, 
                            boolean recursiveLoad)
    throws ReasoningException, IOException
  {
    throw new RuntimeException("loadOntology (for models) not implemented");
  }


  /*
   * Abstract methods requiring a domain manager.
   */

  public Vector getPolicies() 
    throws IOException
  {
    try {
      return _brains.getPolicies();
    } catch (Exception e) {
      IOException ioe 
        = new IOException("Exception getting current policies from Domain Manager");
      ioe.initCause(e);
      throw ioe;
    }
  }

  public void updatePolicies (List addedPolicies,
                              List changedPolicies,
                              List removedPolicies) 
    throws IOException
  {
    try {
      _brains.updatePolicies(addedPolicies, 
                             changedPolicies, 
                             removedPolicies,
                             null);
    } catch (Exception e) {
      IOException ioe = new IOException("Exception sending policy update");
      ioe.initCause(e);
      throw ioe;
    }
  }

  public void setConditionalPolicies(Vector condPols)
    throws Exception
  {
    _brains.setConditionalPolicies(condPols);
  }

}
