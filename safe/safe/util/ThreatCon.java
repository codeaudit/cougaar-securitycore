package safe.util;

import java.io.Serializable;

/**
 * This class acts as an example of an object that can
 * be instantiated and set via the EditBlackboardObjectDialog.
 * 
 * It contains a no-arg constructor, and a publicly accessible
 * field named 'level', which accepts a value of type String,
 * thus satisfying the 3 requirements of the EditBlackboardObject
 * mechanism.
 */
public class ThreatCon implements Serializable
{
    public ThreatCon ()
    {
    }                           

    public String level = null;
}
