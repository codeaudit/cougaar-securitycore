package org.cougaar.core.security.auth.role;

// cougaar classes
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.component.ComponentDescription;
import org.cougaar.core.component.ServiceBroker;
// security services classes
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.ObjectContext;
import org.cougaar.core.security.services.auth.AuthorizationService;
// java classes
import java.security.Permission;
import java.util.ArrayList;

/**
 * TODO: This is only a stub implementation
 */
public class AuthServiceImpl implements AuthorizationService {
  private ServiceBroker _sb;
  
  public AuthServiceImpl(ServiceBroker sb) {
    _sb = sb;  
  }
  
  public ExecutionContext createExecutionContext(MessageAddress agent,
                                                 ComponentDescription component) {
    ArrayList agentRoles = new ArrayList();
    ArrayList componentRoles = new ArrayList();
    String []userRoles = {""};
    agentRoles.add(agent.toString());
    componentRoles.add(component.getClassname());
    
    return (new RoleContext((String [])agentRoles.toArray(new String [0]),
                            (String [])componentRoles.toArray(new String [0]),
                            userRoles));                                         
  }

  public ExecutionContext createExecutionContext(MessageAddress agent,
                                        String uri, String userName) {
  
    return new RoleContext(null, null, null);
  }

  public ObjectContext createObjectContext(ExecutionContext ec, Object object) {
    return new RoleContext(null, null, null);
  }
  
  public void checkPermission(Permission perm) {
    
  }
  
  public void checkPermission(Permission perm, Object context) {
    
  }
}
