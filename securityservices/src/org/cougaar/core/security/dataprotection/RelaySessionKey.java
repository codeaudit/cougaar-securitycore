/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
 *  All Rights Reserved
 * </copyright>
 */


package org.cougaar.core.security.dataprotection;


import java.util.HashMap;
import java.util.Collection;

/**
 * DOCUMENT ME!
 *
 * @version $Revision: 1.3 $
 * @author $author$
 */
public class RelaySessionKey {
    private static RelaySessionKey relaySessionKey = null;
    private HashMap pluginMap;

    private RelaySessionKey() {
        pluginMap = new HashMap();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public static synchronized RelaySessionKey getInstance() {
        if (relaySessionKey == null) {
            relaySessionKey = new RelaySessionKey();

        }

        return relaySessionKey;
    }


    /**
     * DOCUMENT ME!
     *
     * @param agentName DOCUMENT ME!
     * @param plugin DOCUMENT ME!
     */
    protected void addPlugin(String agentName, SessionKeySenderPlugin plugin) {
        pluginMap.put(agentName, plugin);
    }


    /**
     * DOCUMENT ME!
     *
     * @param key DOCUMENT ME!
     * @param pmName DOCUMENT ME!
     * @param sourceAgent DOCUMENT ME!
     */
    protected void relaySessionKey(Collection keycollection, String pmName,
        String sourceAgent) {
        if (pluginMap.get(sourceAgent) != null) {
            SessionKeySenderPlugin plugin = (SessionKeySenderPlugin) pluginMap
                .get(sourceAgent);
            //plugin.sendSessionKey(keycollection, pmName);
        }
    }
}
