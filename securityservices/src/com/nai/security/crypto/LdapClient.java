/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 * Created on September 12, 2001, 10:55 AM
 */

/**
 *
 * @author  rtripath
 * @version 
 */
package com.nai.security.crypto;

import java.util.Hashtable;
import java.util.Enumeration;

import javax.naming.*;
import javax.naming.directory.*;

import com.nai.security.certauthority.LdapEntry;

public class LdapClient 
{
  public String provider_Url;
  private DirContext  context;
  static private boolean debug = false;
  private boolean initializationOK = false;

  protected static final int NETTOOLS = 1;
  protected static final int OPENLDAP = 2;
  protected static int ldapMode = OPENLDAP;

    
    	/** Creates new LdapClient */

  public LdapClient(String aURL) 
  {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
    provider_Url=aURL;
    init();
  }

  private void init()
  {
    Hashtable env=new Hashtable();
    env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.PROVIDER_URL, provider_Url);
    if(ldapMode == OPENLDAP) {
      env.put(Context.SECURITY_PRINCIPAL,"cn=manager,dc=cougaar,dc=org");
      env.put(Context.SECURITY_CREDENTIALS,"secret");
    }
    try {
      context=new InitialDirContext(env);
      if (debug) {
	System.out.println("Using LDAP certificate directory: "
			   + provider_Url);
      }
      initializationOK = true;
    }
    catch(NamingException nexp) {
      if (debug) {
	System.err.println("Warning:can't connect to LDAP server: "
			   + provider_Url);
	System.err.println("Reason: " + nexp + ". Use local keystore only.");
	nexp.printStackTrace();
      }
    }
  }

  private boolean isInitialized() {
    return initializationOK;
  }

  public NamingEnumeration  search(String filter, String Contexturl)
  {
    if (!isInitialized()) {
      return null;
    }
    NamingEnumeration results=null;
    SearchControls constrains=new SearchControls();
    constrains.setSearchScope(SearchControls.SUBTREE_SCOPE);
    try {
      if (context != null) {
	results=context.search(Contexturl,filter,constrains);
      }
    }
    catch(NamingException searchexp) {
      if (debug) {
	System.out.println("search failed");
	searchexp.printStackTrace();
      }
      return results;
    }
		
    return results;
  }

  public NamingEnumeration search(String alias)
  {
    if (!isInitialized()) {
      if (debug) {
	System.out.println("LDAP client not initialized");
      }
      return null;
    }
    NamingEnumeration results=null;
    StringBuffer filter=new StringBuffer();
    filter.append("(cn=");
    filter.append(alias);
    filter.append(")");
    if (debug) {
      System.out.println("Search string is ::"+filter.toString());
    }
    SearchControls constrains=new SearchControls();
    constrains.setSearchScope(SearchControls.SUBTREE_SCOPE);
    try {
      if (context != null) {
	results=context.search(provider_Url,filter.toString(),constrains);
      }
    }
    catch(NamingException searchexp) {
      if (debug) {
	System.out.println("search failed");
	searchexp.printStackTrace();
      }
    }
    return results;
  }
  public NamingEnumeration searchwithfilter(String filter)
  {
    if (!isInitialized()) {
      return null;
    }
    NamingEnumeration results=null;
    SearchControls constrains=new SearchControls();
    constrains.setSearchScope(SearchControls.SUBTREE_SCOPE);
    if (debug) {
      System.out.println("Filters provided for search ..........."+filter);
      System.out.println("Provider url is  ..........."+provider_Url);
    }
    try {
      if (context != null) {
 				results=context.search(provider_Url,filter,constrains);
 			}
    }
    catch(NamingException searchexp) {
      System.out.println("search failed");
      searchexp.printStackTrace();
    }
    return results;
  }

  public String getLdapEntry(String name) {
    String pem_cert=null;
    if (debug) {
      System.out.println("look up:"+name);
    }
    synchronized(context) {
      try {
	if (debug) {
	  System.out.println("Context is:"+context.toString());
	}
	pem_cert = (String) context.lookup(name);
      }
      catch(Exception ex) {
	if(debug) {
	  System.out.print("Unable to fetch ldap entry for " + name);
	  ex.printStackTrace();
	}
      }
    }
    return pem_cert;
  }

}
