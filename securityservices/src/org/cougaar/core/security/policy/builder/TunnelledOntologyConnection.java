/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.policy.builder;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.agent.service.directory.DirectoryFailure;

import jtp.ReasoningException;
import kaos.kpat.tunnel.TunnelClient;
import kaos.ontology.util.QueryFailure;
import kaos.ontology.util.SerializableOntModelImpl;
import kaos.ontology.management.UnknownConceptException;

import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.userauth.UserAuthenticatorImpl;


/**
 * This class represents a connection to the reasoner (the ontology
 * repository) in the case where the reasoner is in a remote domain
 * manager.
 *
 * This class gets the reasoner by using http to communicate with a
 * servlet which tunnels the connection through to the domain
 * manager.  The Tunnel client class takes care of all of the
 * communication details; this class only needs to invoke the tunnel
 * client class.
 */

public class TunnelledOntologyConnection extends OntologyConnection
{

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
    throws UnknownConceptException, DirectoryFailure
  {
    return _brains.getInstancesOf(conceptName);
  }

  // not in tunnelclient
  public Vector getPropertiesApplicableTo (String className)
    throws UnknownConceptException, QueryFailure, DirectoryFailure
  {
    return _brains.getPropertiesApplicableTo(className);
  }

  // not in tunnelclient
  public String getRangeOnPropertyForClass(String className, 
                                           String propertyName) 
    throws UnknownConceptException, QueryFailure, DirectoryFailure
  {
    //    try {
      return _brains.getRangeOnPropertyForClass(className,propertyName);
      //    } catch (Exception e) {
      //      ReasoningException re
      //        = new ReasoningException("Failed to get the range for the property "
      //                                 + propertyName + " which has domain " +
      //                                 className);
      //      re.initCause(e);
      //      throw re;
      //    }
  }

  public Set getIndividualTargets (String baseTargetClass) 
    throws ReasoningException
  {
    try {
      return _brains.getIndividualTargets(baseTargetClass);
    } catch (Exception e) {
      ReasoningException re = new ReasoningException(e.toString());
      re.initCause(e);
      throw re;
    }
  }


  public void declareInstance(String instanceName,
                               String className)
    throws ReasoningException
  {
    try {
      _brains.declareInstance(instanceName, className);
    } catch (Exception e) {
      ReasoningException re 
        = new ReasoningException("Error making delclaration to JTP");
      re.initCause(e);
      throw re;
    }
  }


  public Set getSubClassesOf (String className) 
    throws UnknownConceptException, DirectoryFailure
  {
    return _brains.getSubClassesOf(className);
  }


  public boolean testTrue (String statement) 
    throws QueryFailure, DirectoryFailure
  {
    return _brains.testTrue(statement);
  }

  /*
   * Not implemented on the tunnelled ontology
   */

  public void loadOntology(SerializableOntModelImpl  myOntModel, 
                           boolean                    recursiveLoad)
    throws ReasoningException, IOException
  {
    try {
      _brains.loadOntology(myOntModel, recursiveLoad);
    } catch (Exception e) {
      if (e instanceof IOException) {
        throw (IOException) e;
      } else if (e instanceof ReasoningException) {
        throw (ReasoningException) e;
      } else {
        ReasoningException throwExc = new ReasoningException(e.toString());
        throwExc.initCause(e);
        throw throwExc;
      }
    }
  }

  public Set getSuperPropertiesOf (String propertyName) 
    throws UnknownConceptException, DirectoryFailure
  {
    return _brains.getSuperPropertiesOf(propertyName);
  }


  public Set getSubPropertiesOf(String propertyName) 
    throws UnknownConceptException, DirectoryFailure
  {
    return _brains.getSubPropertiesOf(propertyName);
  }



  /*
   * Abstract methods requiring a domain manager.
   */

  public List getPolicies() 
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
