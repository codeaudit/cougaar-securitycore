/**
 * Last Modified by: $Author: srosset $
 * On: $Date: 2002-05-17 23:18:08 $
 */package safe.comm;

import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;

import java.io.Serializable;

/**
 * A SAFEMessage extends Cougaar's base Message class to enable sending
 * a single serializable object inside the Message
 */
public class SAFEMessage extends Message
{
    public SAFEMessage()
    {
        super();
    }
    
    public SAFEMessage (MessageAddress s,
                        MessageAddress d,
                        Serializable contents)
    {
        super(s,d);
        _contents = contents;
    }
    
    public void writeExternal (java.io.ObjectOutput out)
    {
        try {
            super.writeExternal(out);
            out.writeObject(_contents);
        }
        catch (Exception xcp) {
            xcp.printStackTrace();
        }
    }
    
    public void readExternal (java.io.ObjectInput in)
    {
        try {
            super.readExternal(in);
            _contents = in.readObject();
        }
        catch (Exception xcp) {
            xcp.printStackTrace();
        }
    }
    
    public Object getContents()
    {
        return _contents;
    }
    
    private Object _contents;
        
}
