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



package org.cougaar.core.security.dataprotection;


import java.util.HashMap;
import java.util.Collection;

/**
 * DOCUMENT ME!
 *
 * @version $Revision: 1.1 $
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
