package org.cougaar.core.security.policy.enforcers.match;

import java.util.Collection;
import java.util.Iterator;
import java.util.Set;

import kaos.ontology.matching.*;
import kaos.ontology.jena.ActionConcepts;
import kaos.policy.information.KAoSProperty;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.LoggingService;


public class ComponentSemanticMatcherFactory 
    implements SemanticMatcherFactory
{

    private ServiceBroker _sb;
    private CommunityService _communityService;
    private LoggingService _log;
    private CommunitySemanticMatcher _semMatch;

    public ComponentSemanticMatcherFactory(ServiceBroker sb)
    {
	_sb               = sb;
	_semMatch         = new  CommunitySemanticMatcher();

        // get the LoggingService
        _log = (LoggingService) _sb.getService(this,
                                               LoggingService.class,
                                               null);
        if (_log == null) {
            throw new NullPointerException("LoggingService");
        }
    }
    /**
     * Instantiate a semantic matcher for the property name.
     *
     * @param  propertyName               The String specifying the
     *                                  property, for which a matcher
     *                                  is requested.  
     *     
     * @return SemanticMatcher           an instance of the requested
     *                                   semantic matcher, or null, if
     *                                  no semantic matcher is required.
     *
     * @exception                       SemanticMatcherInitializationException
     *                                   is thrown if the
     *                                  instantiation of the matcher was not  
     *                                  successful, details will be
     *                                  provided in the exception's message. 
     */
    public  SemanticMatcher getInstance (String propertyName) 
        throws SemanticMatcherInitializationException
    {
	if (propertyName.equals(ActionConcepts._performedBy_) || 
	    propertyName.equals(ActionConcepts._hasDestination_) ) {
	    return _semMatch;
	} else {
	    return null;
	}
    }


    private void ensureCommunityServicePresent()
    {
	if (_communityService == null) {
	    _communityService = 
		(CommunityService) _sb.getService(this, 
						  CommunityService.class, 
						  null);
	    if (_communityService == null) {
		throw new RuntimeException("No community service");
	    }
	    _log.debug("ComponentSemanticMatcher: Community Service installed");
	}

    }

    static String removeHashChar(String s)
    {
	if (s.startsWith("#")) {
	    return s.substring(1);
	}
	return s;
    }

    private class CommunitySemanticMatcher implements SemanticMatcher
    {
	public void initSemanticMatcher ()
	    throws SemanticMatcherInitializationException 
	{
	    return;
	}

	public boolean matchSemantically(String className, Object instance) 
		throws SemanticMatcherInitializationException
	{
	    ensureCommunityServicePresent();

	    String agent = (String) instance;
	    agent     = removeHashChar(agent);
	    className = removeHashChar(className);
	    String communityPrefix = "MembersOfDomain";
	    if (className.startsWith(communityPrefix)) {
		String community 
		    = className.substring(communityPrefix.length());
		Collection communities = 
		    _communityService.listParentCommunities((String) agent);
		return communities.contains(community);
	    } else {
		return false;
	    }
	}

	public int matchSemantically(String className, Set instances)
	    throws SemanticMatcherInitializationException
	{
	    ensureCommunityServicePresent();

	    String communityPrefix = "MembersOfDomain";
	    boolean someMatch     = false;
	    boolean someDontMatch = false;

	    className = removeHashChar(className);
	    if (className.startsWith(communityPrefix)) {
		String community 
		    = className.substring(communityPrefix.length());
		for (Iterator agentIt = instances.iterator(); 
		     agentIt.hasNext();) {
		    String agent = (String) agentIt.next();
		    agent = removeHashChar(agent);

		    Collection communities = 
			_communityService.listParentCommunities(agent);
		    _log.debug("matchSemantically: Communities for agent, " 
			       + agent + " = ");
		    for(Iterator communitiesIt = communities.iterator();
			communitiesIt.hasNext();) {
			_log.debug("Community: " + communitiesIt.next());
		    }
		    _log.debug("matchSemantically: contains community, "
			       + community + "?");
		    if (communities.contains(community)) {
			_log.debug("matchSemantically: yes");
			someMatch = true;
		    } else {
			_log.debug("matchSemantically: no");
			someDontMatch = true;
		    }
		    if (someMatch && someDontMatch) {
			_log.debug("matchSemantically: return partial match");
			return 1;  // a partial match
		    }
		}
		// can't have both someMatch and someDontMatch
		_log.debug("matchSemantically: someMatch = " + someMatch);
		_log.debug("matchSemantically: someDontMatch = " + 
			   someDontMatch);
		if (someMatch) {
		    return KAoSProperty._ALL_INST_PRESENT;
		} else if (someDontMatch) {
		    return KAoSProperty._NO_INST_PRESENT;
		} else {
		    return KAoSProperty._ALL_INST_PRESENT;
		}
	    } else {
		return KAoSProperty._NO_INST_PRESENT;
	    }
	}
    }
}
