package org.cougaar.core.security.policy.enforcers.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.util.ConfigFinder;



/**
 * The purpose of this class is to facilitate the mapping between DAML
 * concepts and the UltraLog concepts.  For now I am using
 * configuration files but some of this will change later...
 */
public class DAMLMapping {

  private boolean _initialized = false;
  private LoggingService _log;
  private ConfigFinder _cf;
  private List _uriMap;

  public DAMLMapping(ServiceBroker sb)
  {
    _log = (LoggingService)
      sb.getService(this,
                    LoggingService.class, 
                    null);
    if (_log.isDebugEnabled()) {
      _log.debug("Initializing DAML Mapper");
    }
    _cf = ConfigFinder.getInstance();
  }


  public void initializeUri()
  {
    try {
      _log.debug("loading uri mappings...");
      _uriMap = mappingFromFile("DamlUriMap");
    } catch (IOException e) {
      _log.error("IO Exception reading DAML <-> uri configuration file", e);
    }
  }

  public String ulUriToKAoSUri(String uri)
  {
    try {
      _log.debug("Converting " + uri + " to KAoS uri");
      AgentUri agUri = new AgentUri(uri);
      for (Iterator uriIt = _uriMap.iterator();
           uriIt.hasNext();) {
        StringPair pair = (StringPair) uriIt.next();
        String pattern = pair._first;
        String kaosUri = pair._second;
        _log.debug("Matching against pattern " + pattern);
        AgentUri agUriPattern = new AgentUri(pattern);
        if (agUri.match(agUriPattern)) {
          _log.debug("Found Match");
          String ret = 
            org.cougaar.core.security.policy.enforcers.ontology
            .EntityInstancesConcepts.EntityInstancesDamlURL
            + (String) (kaosUri);
          _log.debug("Returning " + ret);
          return ret;
        }
      }
      return null;
    } catch (Exception e) {
      _log.warn("This is probably not good - " + 
                "some URI is malformed...", e);
      return null;
    }
  }

  /**
   * This method reads a mapping from a file.  
   *
   * We assume that the mapping is functional.
   */

  public List mappingFromFile(String filename)
    throws IOException
  {
    _log.debug("Initilizing DAML mapping using " + filename);

    List mapping = new Vector();
    File mappingFile = _cf.locateFile(filename);
    File policyFile = null;
    String line;

    _log.debug(".DAMLMapping: Reading daml policies file "
              + mappingFile);
    BufferedReader damlReader 
      = new BufferedReader(new FileReader(mappingFile));
    while ((line = damlReader.readLine()) != null) {
      if (line.startsWith("#")) { continue; }

      int spacePt;
      if ((spacePt = line.indexOf(' ')) == -1) { continue; }
      String mappingIn = line.substring(0,spacePt);
      String mappingOut = line.substring(spacePt+1);

      _log.debug(".DAMLMapping: mapping item " + mappingIn +
                " to item " + mappingOut);

      if (mappingOut == null)
        continue;

      mapping.add(new StringPair(mappingIn, mappingOut));
    }
    damlReader.close();
    _log.debug(".DAMLMapping: Finished Reading daml policies file " 
              + mappingFile);
    return mapping;
  }

  private class AgentUri 
  {
    private String _agent;
    private String _uri;

    /**
     * Constructor for AgentUri which takes a uri parameter.
     *
     * Splits a URI like /$EnclaveOneWorkerNode/myuri into the agent part
     * (EnclaveOneWorkerNode) and the rest (/myuri).
     */

    public AgentUri(String uri)
    {
      String agent;
      if (uri.startsWith("/$")) {
        int index = uri.indexOf("/", 2);
        _agent = uri.substring(2,index);
        uri = uri.substring(index);
      } else {
        _agent = null;
      }
      _uri=uri;
    }

    public String getAgent() { return _agent; }

    public String getURI() { return _uri; }

    public boolean rootURI() { return _agent == null; }

    /**
     * This function matches a uri against a uri from the policy.
     */
    public boolean match(AgentUri pattern)
    {
      _log.debug("Does the uri with agent " + _agent + " and uri " + _uri);
      _log.debug("match the pattern with agent " + pattern._agent + 
                 " and uri " + pattern._uri + "?");

      if (!matchAgentPart(pattern)) {
        _log.debug("agent match failed");
        return false;
      } else if (pattern._uri.equals("/*")) {
        _log.debug("matched because the uri is universal");
        return true;
      } else if (_uri.equals(pattern._uri)) {
        _log.debug("matched because the uri's are equal");
        return true;
      }
      _log.debug("no match");
      return false;
    }

    private boolean matchAgentPart(AgentUri pattern)
    {
      _log.debug("do the agents match?");
      if (rootURI() ^ pattern.rootURI()) {
        _log.debug("one agent is root the other isn't");
        return false;
      } else if (rootURI() && pattern.rootURI()) {
        _log.debug("both agents are root");
        return true;
      } else if (pattern._agent.equals("*")) {
        _log.debug("the agent pattern is universal");
        return true;
      } else if (_agent.equals(pattern._agent)) {
        _log.debug("the agent is the same as the pattern");
        return true;
      }
      _log.debug("The agents don't match");
      return false;
    }

  }

  public static class StringPair
  {
    public String _first;
    public String _second;

    public StringPair(String first, String second)
    {
      _first  = first;
      _second = second;
    }
  }

}
