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

public class LdapClient 
{
  public String Provider_Url;
  private DirContext context;
  static private boolean debug = false;

    	/** Creates new LdapClient */

  public LdapClient(String provider_url) 
  {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
    Provider_Url=provider_url;
    init();
  }
  private void init()
  {
    Hashtable env=new Hashtable();
    env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.PROVIDER_URL,Provider_Url);
    try
      {
	context=new InitialDirContext(env);
	System.out.println("Using LDAP certificate directory: " + Provider_Url);
      }
    catch(NamingException nexp)
      {
	System.err.println("Warning:can't connect to LDAP server: " + Provider_Url);
	System.err.println("Reason: " + nexp + ". Use local keystore only.");
	//nexp.printStackTrace();
      }
  }

  public NamingEnumeration  search(String filter, String Contexturl)
  {
    NamingEnumeration results=null;
    SearchControls constrains=new SearchControls();
    constrains.setSearchScope(SearchControls.SUBTREE_SCOPE);
    try
      {
	results=context.search(Contexturl,filter,constrains);
      }
    catch(NamingException searchexp)
      {
	System.out.println("search failed");
	searchexp.printStackTrace();
	return results;
      }
		
    return results;
  }

  public NamingEnumeration search(String alias)
  {
    NamingEnumeration results=null;
    StringBuffer filter=new StringBuffer();
    filter.append("(cn=");
    filter.append(alias);
    filter.append(")");
    SearchControls constrains=new SearchControls();
    constrains.setSearchScope(SearchControls.SUBTREE_SCOPE);
    try
      {
	results=context.search(Provider_Url,filter.toString(),constrains);
      }
    catch(NamingException searchexp)
      {
	System.out.println("search failed");
	searchexp.printStackTrace();
      }
    return results;
  }
  public NamingEnumeration searchwithfilter(String filter)
  {
    NamingEnumeration results=null;
    SearchControls constrains=new SearchControls();
    constrains.setSearchScope(SearchControls.SUBTREE_SCOPE);
    System.out.println("Filters provided for search ..........."+filter);
    System.out.println("Provider url is  ..........."+Provider_Url);
    try
      {
	results=context.search(Provider_Url,filter,constrains);
      }
    catch(NamingException searchexp)
      {
	System.out.println("search failed");
	searchexp.printStackTrace();
      }
    return results;
  }

}
