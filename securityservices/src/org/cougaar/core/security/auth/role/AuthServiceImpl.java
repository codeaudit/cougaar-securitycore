package org.cougaar.core.security.auth.role;

// cougaar classes
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.component.ComponentDescription;
import org.cougaar.core.component.ServiceBroker;
// security services classes
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.ObjectContext;
import org.cougaar.core.security.services.auth.AuthorizationService;
import org.cougaar.core.security.policy.enforcers.util.RoleMapping;
import org.cougaar.core.security.acl.auth.UserRoles;
// java classes
import java.security.Permission;
import java.util.ArrayList;
import java.util.Set;

/**
 * TODO: This is only a stub implementation
 */
public class AuthServiceImpl implements AuthorizationService {
  private ServiceBroker _sb;
  private RoleMapping   _roleMap;
  
  public AuthServiceImpl(ServiceBroker sb) {
    _sb = sb;  
    _roleMap = new RoleMapping(sb);
  }
  
  public ExecutionContext createExecutionContext(MessageAddress agent,
                                                 ComponentDescription component) {
    String componentName = component.getClassname();
    Set s = _roleMap.getRolesForComponent(componentName);
    String[] compRoles = (String[]) s.toArray(new String[s.size()]);
    s = _roleMap.getRolesForAgent(agent.toString());
    String[] agentRoles = (String[]) s.toArray(new String[s.size()]);
    String[] userRoles = UserRoles.getRoles();
    String userName = UserRoles.getUserName();
    
    return (new RoleExecutionContext(agent, componentName, userName,
                                     agentRoles, compRoles, userRoles));
  }

  public ExecutionContext createExecutionContext(MessageAddress agent,
                                                 String uri,
                                                 String userName) {
    Set s = _roleMap.getRolesForUri(uri);
    String[] compRoles = (String[]) s.toArray(new String[s.size()]);
    s = _roleMap.getRolesForAgent(agent.toString());
    String[] agentRoles = (String[]) s.toArray(new String[s.size()]);
    String[] userRoles = UserRoles.getRoles();
    
    return (new RoleExecutionContext(agent, uri, userName,
                                     agentRoles, compRoles, userRoles));
  }

  public ObjectContext createObjectContext(ExecutionContext ec, Object object) {
    // no context necessary
    return new RoleObjectContext(((RoleExecutionContext)ec).getAgent());
  }
  
  public void checkPermission(Permission perm) {
    
  }
  
  public void checkPermission(Permission perm, Object context) {
    
  }
}
