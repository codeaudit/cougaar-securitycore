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
import org.cougaar.core.security.auth.BlackboardPermission;
import org.cougaar.core.security.auth.BlackboardObjectPermission;

// java classes
import java.security.Permission;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Set;
import java.util.List;
import java.util.LinkedList;
import java.security.ProtectionDomain;

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
  
  public boolean implies(ProtectionDomain domain, Permission perm) {
//     System.out.println("Checking if the permission is implied");
    return true;
  }
  
  public List getPermissions(ProtectionDomain domain) {
    /*
    Principal p[] = domain.getPrincipals();
    StringBuffer pBuf = new StringBuffer();
    for (int i = 0; i < p.length; i++) {
      pBuf.append(p[i]);
      pBuf.append(" - ");
    }
    System.out.println("Getting permissions for " + pBuf);
    */
    List permissions = new LinkedList();
    // add all of the permissions for now:
    permissions.add(new BlackboardPermission("*", "add,change,remove,query"));
    permissions.add(new BlackboardObjectPermission("*", "create,read,write"));
    return new LinkedList();
  }

}
