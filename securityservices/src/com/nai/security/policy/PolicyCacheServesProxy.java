package com.nai.security.policy;

/**
 * A client interface for MTSPolicyCache, which is implements a two-dimensional
 * associative array of policy rule beans.
 * @see PolicyRuleBean
 */
public interface PolicyCacheServesProxy 
{

  /**
   * Accessor method intended for use by a system-level proxy.
   * For example, it could be used by the MessageTransportServiceProxy.
   */
  public PolicyRuleBean get(String name, String key);

}

