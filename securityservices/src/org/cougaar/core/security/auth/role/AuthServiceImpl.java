package org.cougaar.core.security.auth.role;

// cougaar classes
import org.cougaar.core.component.ComponentDescription;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.acl.auth.URIPrincipal;
import org.cougaar.core.security.acl.auth.UserRoles;
import org.cougaar.core.security.auth.BlackboardObjectPermission;
import org.cougaar.core.security.auth.BlackboardPermission;
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.auth.ExecutionPrincipal;
import org.cougaar.core.security.auth.ObjectContext;
import org.cougaar.core.security.policy.ontology.EntityInstancesConcepts;
import org.cougaar.core.security.policy.ontology.UltralogActionConcepts;
import org.cougaar.core.security.policy.enforcers.util.OwlBlackboardMapping;
import org.cougaar.core.security.policy.enforcers.util.RoleMapping;
import org.cougaar.core.security.services.auth.AuthorizationService;
import org.cougaar.core.security.services.auth.SecurityContextService;
import org.cougaar.core.security.util.ActionPermission;
import org.cougaar.core.service.LoggingService;
import java.security.Permission;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.Collections;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import javax.agent.service.ServiceFailure;

import kaos.ontology.vocabulary.ActionConcepts;
import kaos.ontology.management.UnknownConceptException;
import kaos.ontology.repository.ActionInstanceDescription;
import kaos.ontology.repository.TargetInstanceDescription;
import kaos.policy.information.KAoSProperty;
import safe.enforcer.NodeEnforcer;
import safe.guard.EnforcerManagerService;
import safe.guard.NodeGuard;

/**
 * TODO: This is only a stub implementation
 */
public class AuthServiceImpl 
  implements AuthorizationService, NodeEnforcer {
  public static final String DAML_PROPERTY = 
    "org.cougaar.core.security.policy.auth.role.useDaml";
  private static final boolean USE_OWL = Boolean.getBoolean(DAML_PROPERTY);

  private static int _counter = 0;
  private SecurityContextService _scs;
  private ServiceBroker          _sb;
  private EnforcerManagerService _guard;
  private RoleMapping            _roleMap;
  private LoggingService         _log;

  private static final String _enforcedActionType 
            = UltralogActionConcepts.BlackBoardAccess();
  private static final Map _owlActionMapping;
  static {
    _owlActionMapping = new HashMap();
    String accessModes[] = {"Add", "Remove", "Change", "Query",
                            "Read", "Write", "Create"};
    for (int i = 0; i < accessModes.length; i++) {
      _owlActionMapping.put(
              accessModes[i].toLowerCase(),
              EntityInstancesConcepts.EntityInstancesOwlURL()
              + "BlackBoardAccess" + accessModes[i]
      );
    }
  }
  private static final Set _blackboardObjectActions;
  static {
    _blackboardObjectActions = new HashSet();
    _blackboardObjectActions.add("create");
    _blackboardObjectActions.add("read");
    _blackboardObjectActions.add("write");
  }
  private static Set            _nameableBlackboardObjects = null;
  private Set                   _allBlackboardObjectsOWL  = null;
  private OwlBlackboardMapping _owlObjectMap;
  
  public AuthServiceImpl(ServiceBroker sb) {
    _sb = sb;  

    _roleMap = new RoleMapping(sb);

    _log = (LoggingService) 
      _sb.getService(this, LoggingService.class, null);

    _owlObjectMap = new OwlBlackboardMapping(_sb);
    _owlObjectMap.initialize();
    _nameableBlackboardObjects = _owlObjectMap.namedObjects();
    _allBlackboardObjectsOWL = _owlObjectMap.allDAMLObjectNames();

    _scs = (SecurityContextService)
      _sb.getService(this, SecurityContextService.class, null);
    if (_scs == null) {
      if (_log.isDebugEnabled()) {
        _log.debug("SecurityContextService not available yet...");
      }
      _sb.addServiceListener(new SecurityContextServiceAvailableListener());
    }
    registerEnforcer();
    if (_log.isDebugEnabled()) {
      _log.debug("AuthServiceImp Constructor completed - UseDaml = " +
                 USE_OWL);
    }
  }

  public void registerEnforcer()
  {
    _guard = (EnforcerManagerService)
                     _sb.getService(this, EnforcerManagerService.class, null);
    if (_guard == null) {
      _sb.releaseService(this, EnforcerManagerService.class, _guard);
      _log.fatal("Cannot continue without guard", new Throwable());
      throw new RuntimeException("Cannot continue without guard");
    }
    if (!_guard.registerEnforcer(this, _enforcedActionType, new Vector())) {
      _sb.releaseService(this, EnforcerManagerService.class, _guard);
        _log.fatal("Could not register with the Enforcer Manager Service");
      throw new SecurityException(
                   "Cannot register with Enforcer Manager Service");
    }
  }

  public static Set nameableBlackboardObjects()
  {
    return _nameableBlackboardObjects; 
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

  public RoleExecutionContext 
    getExecutionContextFromDomain(ProtectionDomain domain)
  {
    // get the principals from the protection domain
    Principal p[] = domain.getPrincipals();
    ExecutionContext ec = null;
    for(int i = 0; i < p.length; i++) {
      // we want to look for the ExecutionPrincipal
      if(p[i] instanceof ExecutionPrincipal) {
        // the ExecutionPrincipal contains the ExecutionContext used for authorization
        ec = ((ExecutionPrincipal)p[i]).getExecutionContext();
        break;
      } 
    }
    
    if (_scs == null) { 
      if (_log.isWarnEnabled()) {
            _log.warn("Failed to get securitycontext service before mediation"
                      + "this may be an issue");
      }
      return null;
    }
    // ec is null because there isn't an ExecutionPrincipal 
    // in the ProtectionDomain
    if(ec == null && _scs != null) {
      // if no ExecutionPrincipal get the ExecutionContext 
      // from the SecurityContextService
      ec = _scs.getExecutionContext(); 
    }
    if (ec instanceof RoleExecutionContext) {
      return (RoleExecutionContext) ec;
    } else {
      if (_log.isDebugEnabled()) {
        _log.debug("Execution context = " + ec);
        if (ec != null) {
          _log.debug("Not the right kind of execution context, class = " + 
                     ec.getClass().getName());
        }
      }
      return null;
    }
  }

  public boolean implies(ProtectionDomain domain, Permission perm) {
    if (_log.isDebugEnabled()) {
      _log.debug("Checking if the permission is implied");
    }
    
    RoleExecutionContext ec = getExecutionContextFromDomain(domain);
    if (ec != null) {
      if (_log.isDebugEnabled() && ((++_counter) % 10000 == 0)) {
        _log.debug("\n" + _counter + " blackboard mediations.");
      }
      if (_log.isDebugEnabled()) {
        _log.debug("Have an execution context calling isAuthorizeUL");
      }
      boolean ret = isAuthorizedUL(ec, perm);
      if(!ret) {   
        if(_log.isDebugEnabled()) {
          _log.debug("UNAUTHORIZED BLACKBOARD ACCESS: [" + ec.getComponent() + ", " + perm.getName() + ", " + perm.getActions() + "]");
          _log.debug("Component execution context: \n" + ec); 
        }
      }
      else {
        if(_log.isDebugEnabled()) {
          _log.info("AUTHORIZED BLACKBOARD ACCESS: [" + ec.getComponent() + ", " + perm.getName() + ", " + perm.getActions() + "]");
        }
      }
      return ret;
    } else {
      if (_log.isWarnEnabled()) {
        _log.warn("No execution context available at mediation time");
        _log.info("Here is the current location", new Exception());
      }
      return true;
    }
  }
  
  public List getPermissions(ProtectionDomain domain) {
    _log.debug("In Blackboard getPermissions function");
    RoleExecutionContext rec = getExecutionContextFromDomain(domain);
    if (rec == null && _log.isDebugEnabled()) {
      _log.debug("domain which has no RoleExecutionContext");
      return new LinkedList();
    }
    List permissions = new LinkedList();
    if (!USE_OWL) {
    // add all of the permissions for now:
      permissions.add(new BlackboardPermission("*", 
                                               "add,change,remove,query"));
      permissions.add(new BlackboardObjectPermission("*", 
                                                     "create,read,write"));
      return permissions;
    }
    Set targets = new HashSet();
    targets.add(new TargetInstanceDescription(
                      UltralogActionConcepts.blackBoardAccessMode(),
                      EntityInstancesConcepts.EntityInstancesOwlURL() + 
                      "BlackBoardAccessAdd"));
    ActionInstanceDescription action = 
      new ActionInstanceDescription(_enforcedActionType,
                                    rec,
                                    targets);
    KAoSProperty accessProp =
      action.getProperty(UltralogActionConcepts.blackBoardAccessMode());
    for (Iterator accessIt = _owlActionMapping.keySet().iterator();
         accessIt.hasNext();) {
      String accessMode = (String) accessIt.next();
      String accessModeOwl = (String) _owlActionMapping.get(accessMode);
      {
        Vector tmp = new Vector();
        tmp.add(accessModeOwl);
        accessProp.setMultipleInstances(tmp);
      }
      if (_log.isDebugEnabled()) {
        _log.debug("action = " + action);
      }
      Set objectsInOWL = null;
      try {
        objectsInOWL = 
           _guard.getAllowableValuesForActionProperty(
                    UltralogActionConcepts.blackBoardAccessObject(),
                    action,
                    _allBlackboardObjectsOWL,
                    false);
      } catch (ServiceFailure sf) {
        if (_log.isErrorEnabled()) {
          _log.error("This shouldn't happen", sf);
        }
        objectsInOWL = new HashSet();
      }
      for (Iterator owlObjectNameIt =  objectsInOWL.iterator();
           owlObjectNameIt.hasNext();) {
        String owlObjectName = (String) owlObjectNameIt.next();
        if (owlObjectName.
            equals(OwlBlackboardMapping.otherBlackboardObjectDAML)) {
          if (_blackboardObjectActions.contains(accessMode)) {
            permissions.add(new BlackboardObjectPermission("%Other%",
                                                           accessMode));
          } else {
            permissions.add(new BlackboardPermission("%Other%",
                                                     accessMode));
          }
        } else {
          Set objectsInUL = _owlObjectMap.damlToClassNames(owlObjectName);
          for (Iterator objectsInULIt = objectsInUL.iterator();
               objectsInULIt.hasNext();) {
            String ulObjectName = (String) objectsInULIt.next();
            if (_blackboardObjectActions.contains(accessMode)) {
              permissions.add(new BlackboardObjectPermission(ulObjectName,
                                                             accessMode));
            } else {
              permissions.add(new BlackboardPermission(ulObjectName,
                                                       accessMode));
            }
          }
        }
      }
    }
    return permissions;
  }


  private boolean isAuthorizedUL(RoleExecutionContext ec, Permission p) {

    if (_log.isDebugEnabled()) {
      _log.debug("Entering isAuthorizedUL with context" + ec 
                 + " and permission " + p);
    }
    if (!USE_OWL) { return true; }
    // i'm allowing everything that isn't a BlackboardPermission 
    if(!(p instanceof BlackboardPermission) &&
       !(p instanceof BlackboardObjectPermission)) {
      if (_log.isWarnEnabled()) {
          _log.warn("should I be here? object type = " +
                    p.getClass());
      }
      return true;
    }
    ActionPermission ap = (ActionPermission) p;
    // get the classname of the object
    // e.g. org.cougaar.core.adaptivity.OperatingModeImpl
    String object     = p.getName();
    String owlObject = _owlObjectMap.classToDAMLName(object);

    // get the action the plugin wants to perform on the object
    // e.g. add
    String actions [] = ap.getActionList();

    int firstPolicyUpdateCounter = 0;
    try {
      firstPolicyUpdateCounter = _guard.getPolicyUpdateCount().intValue();
      if (_log.isDebugEnabled()) {
        _log.debug("Obtained policy counter = " + firstPolicyUpdateCounter);
      }
    } catch (ServiceFailure sf) {
      if (_log.isErrorEnabled()) {
        _log.error("This shouldn't happen", sf);
        return false;
      }
    }
    if (ec.cachedIsAuthorized(object,
                              actions,
                              firstPolicyUpdateCounter)) {
      if (_log.isDebugEnabled()) {
        _log.debug("Access is cached and therefore permitted");
      }
      return true;
    }

    if (_log.isDebugEnabled()) {
      _log.debug("authorize plugin(" + ec + ") for actions (");
      for (int i = 0; i < actions.length; i++) { 
        _log.debug(actions[i] + " ");
      }
      _log.debug(") and object " + object);
    }
    for (int i = 0; i < actions.length; i++) {
      String action = actions[i];
      String owlAction = (String) _owlActionMapping.get(action);
      if  (owlAction == null) {
        throw new RuntimeException
          ("Invalid Action Type used in enforcement routines");
      }
      if (! isAuthorizedOwl(ec, owlAction, owlObject)) {
        return false;
      }
    }
    int secondPolicyUpdateCounter = 0;
    try {
      secondPolicyUpdateCounter = _guard.getPolicyUpdateCount().intValue();
      if (_log.isDebugEnabled()) {
        _log.debug("Obtained second update counter = " 
                   + secondPolicyUpdateCounter);
      }
    } catch (ServiceFailure sf) {
      if (_log.isErrorEnabled()) {
        _log.error("This shouldn't happen but the mediation passed", sf);
      }
      return true;
    }
    if (firstPolicyUpdateCounter == secondPolicyUpdateCounter) {
      if (_log.isDebugEnabled()) {
        _log.debug("Updating cache with success");
      }
      ec.updateCachedAuthorization(object, 
                                   actions,
                                   secondPolicyUpdateCounter);
    }
    return true;
  }

  public boolean isAuthorizedOwl(RoleExecutionContext rec,
                                  String action,
                                  String objectName)
  {
    if (_log.isDebugEnabled()) {
      _log.debug("going to owl policy check");
    }
    Set targets = new HashSet();
    targets.add(new TargetInstanceDescription(
                      UltralogActionConcepts.blackBoardAccessMode(),
                      action));
    targets.add(new TargetInstanceDescription(
                      UltralogActionConcepts.blackBoardAccessObject(),
                      objectName));
    ActionInstanceDescription aid = 
      new ActionInstanceDescription(_enforcedActionType,
                                    "Dummy",
                                    targets);
    KAoSProperty actorProp = 
      aid.getProperty(ActionConcepts.performedBy());
    {
      Vector tmp = new Vector();
      tmp.add(rec);
      actorProp.setMultipleInstances(tmp);
    }
    try {
      kaos.policy.guard.ActionPermission kap 
        = new kaos.policy.guard.ActionPermission("foo", aid);
      _guard.checkPermission(kap, null);
      return true;
    } catch (ServiceFailure sf) {
      if (_log.isErrorEnabled()) {
        _log.error("This shouldn't happen", sf);
      }
      if (_log.isWarnEnabled()) {
        _log.warn("Permission denied due to error in mediation mechanism");
      }
    } catch (SecurityException e) {
      if (_log.isWarnEnabled()) {
        _log.warn("Permission denied " + e);
      }
    }
    if (_log.isWarnEnabled() && 
        !action.equals(EntityInstancesConcepts.EntityInstancesOwlURL() + 
                       "BlackBoardAccessQuery")) {
      _log.warn("Action = " + aid);
    }
    return false;
  }
  
  private URIPrincipal getServletURIPrincipal(ProtectionDomain domain)
  {
    // get the principals from the protection domain
    Principal p[] = domain.getPrincipals();
    URIPrincipal up = null;
    for(int i = 0; i < p.length; i++) {
      // we want to look for the URIPrincipal since this is servlet context call
      if(p[i] instanceof URIPrincipal) {
        up = (URIPrincipal)p[i];
        break;
      } 
    }
    return up;
  }
    
  private class SecurityContextServiceAvailableListener
    implements ServiceAvailableListener
  {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      Class sc = ae.getService();
      if (org.cougaar.core.security.services.auth.SecurityContextService.class.
          isAssignableFrom(sc)) {
        if (_log.isDebugEnabled()) {
          _log.debug("SecurityContext Service is now available");
        }
        _scs = (SecurityContextService)
          _sb.getService(this, SecurityContextService.class, null);        
      }
    }
  }

  public String getName() { return "BlackboardEnforcer"; }

  public Vector getControlledActionClasses () 
  { 
    Vector ret = new Vector();
    ret.add(_enforcedActionType);
    return ret;
  }

}
