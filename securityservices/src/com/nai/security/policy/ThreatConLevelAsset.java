package com.nai.security.policy;

import org.cougaar.domain.planning.ldm.asset.*;

public class ThreatConLevelAsset extends Asset {

    protected int threatConLevel;

    public ThreatConLevelAsset(){
        super();
    }

    public int getThreatConLevel(){
        return threatConLevel;
    }

    public void setThreatConLevel(int tcl){
        threatConLevel = tcl;
    }

}

