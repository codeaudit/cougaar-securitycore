package safe.policyManager;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.StringTokenizer;
import java.util.Collection;
import java.lang.reflect.*;
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.component.*;
import org.cougaar.core.service.*;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.planning.ldm.plan.*;

public class SetBlackboardObjectServletComponent extends BaseServletComponent 
    implements BlackboardClient
{        public static final String DELIMITER = ":";    
    protected String getPath()    {
        return "/setBlackboardObject";
    }        public void load()    {
        // should we print debugging info?
        String debug = System.getProperty("SAFE.debug");
        if (debug != null && debug.equalsIgnoreCase("true")) {
            _debug = true;
        }
        super.load();
    }  

    //
    // These "setXService(XService x) {..}" methods
    // are equivalent to the SimpleServletComponent's
    // "public void load() { .. serviceBroker.getService(..); .. }"
    // calls, EXCEPT that:
    //   1) these methods are only called at load-time.
    //   2) if one of these services is not available then this 
    //      Component will NOT be loaded.  In contrast, the 
    //      "load()" pattern allows the Component to (optionally) 
    //      continue loading even if any "getService(..)" returns null.
    //   3) these "setXService(..)" will request the service with
    //      "this" as the requestor.  The more generic "getService(..)"
    //      API allows the Component to pass a different class
    //      (e.g. an inner class to handle callbacks).
    //

    public void setBlackboardService(BlackboardService blackboard) {
        _blackboard = blackboard;
    }

    protected Servlet createServlet() {      
        return new MyServlet();
    }

    private class MyServlet extends HttpServlet {
        public void doGet (HttpServletRequest request,
                           HttpServletResponse response) throws IOException        {            PrintWriter out = response.getWriter();
            try {
                String queryStr = request.getQueryString();
                StringTokenizer tokenizer = new StringTokenizer(queryStr, DELIMITER);
                if (tokenizer.countTokens() != 3) {                    out.print("Invalid parameter format: " + queryStr);
                }
                else {                    String className = tokenizer.nextToken();                    String fieldName = tokenizer.nextToken();
                    String value = tokenizer.nextToken();
                    if (_debug) System.out.println("\nSetBlackboardObjectServletComponent: received input:");
                    if (_debug) System.out.println("className: " + className);
                    if (_debug) System.out.println("fieldName: " + fieldName);                    if (_debug) System.out.println("value: " + value);
                    Class triggerClass = Class.forName(className);
                    Field field = triggerClass.getField(fieldName);
                    
                    // see if an object of this class is already on the blackboard
                    Collection c = _blackboard.query(new ObjectPredicate(triggerClass));
                    
                    // if not, instantiate a new object of the specified class
                    if (c.size() == 0) {
                        Object o = triggerClass.newInstance();
                        field.set(o, value);
                        _blackboard.openTransaction();
                        _blackboard.publishAdd(o);
                        _blackboard.closeTransaction();                        out.print("Successfully published new instance of " + className + " with " + fieldName + " = " + value);
                    }
                    // if there is one object of the specified type on the blackboard,
                    // set the fieldName to value
                    else if (c.size() == 1) {
                        Object o = c.iterator().next();
                        field.set(o, value);
                        _blackboard.openTransaction();
                        _blackboard.publishChange(o);
                        _blackboard.closeTransaction();                        out.print("Successfully modified existing instance of " + className + " to " + fieldName + " = " + value);
                    }
                    // if there is more than one object of the specified type on the blackboard,
                    // report an error
                    else {
                        out.print("Error: there is more than one object of type " + className + " on the blackboard");
                    }
                }            }
            catch (Exception ex) {
                out.print("Error: " + ex.getClass().toString());
                System.out.println(ex);
            }            out.flush();            out.close();           
        }
    }

    //
    // These are oddities of implementing BlackboardClient:
    //
    // Note: A Component must implement BlackboardClient in order 
    // to obtain BlackboardService.
    //

    // odd BlackboardClient method:
    public String getBlackboardClientName() {
        return toString();
    }

    // odd BlackboardClient method:
    public long currentTimeMillis() {
        throw new UnsupportedOperationException(
            this+" asked for the current time???");
    }

    // unused BlackboardClient method:
    public boolean triggerEvent(Object event) {
        // if we had Subscriptions we'd need to implement this.
        //
        // see "ComponentPlugin" for details.
        throw new UnsupportedOperationException(
            this+" only supports Blackboard queries, but received "+
            "a \"trigger\" event: "+event);
    }
    private class ObjectPredicate implements UnaryPredicate
    {
        public ObjectPredicate (Class c) {
            _class = c;
        }
        
        public boolean execute (Object o)
        {
            return (o.getClass().equals(_class));
        }
        
        private Class _class;
    }
        private BlackboardService _blackboard;
    private boolean _debug;    
}
