package org.cougaar.core.security.policy.enforcers.ontology.jena;

final public class ActionConcepts
{
    final public static String ActionDamlURL = "http://ontology.coginst.uwf.edu/Action.daml#";

	// Concepts
    final public static String _CommunicationAction_ = ActionDamlURL + "CommunicationAction";
    final public static String _MobilityAction_ = ActionDamlURL + "MobilityAction";
    final public static String _SignedCommunicationAction_ = ActionDamlURL + "SignedCommunicationAction";
    final public static String _AccessAction_ = ActionDamlURL + "AccessAction";
    final public static String _NonSignedCommunicationAction_ = ActionDamlURL + "NonSignedCommunicationAction";
    final public static String _Target_ = ActionDamlURL + "Target";
    final public static String _RequestAction_ = ActionDamlURL + "RequestAction";
    final public static String _ResponseAction_ = ActionDamlURL + "ResponseAction";
    final public static String _NonEncryptedCommunicationAction_ = ActionDamlURL + "NonEncryptedCommunicationAction";
    final public static String _ResourceAction_ = ActionDamlURL + "ResourceAction";
    final public static String _QueryAction_ = ActionDamlURL + "QueryAction";
    final public static String _Action_ = ActionDamlURL + "Action";
    final public static String _EncryptedCommunicationAction_ = ActionDamlURL + "EncryptedCommunicationAction";
    final public static String _ProposeAction_ = ActionDamlURL + "ProposeAction";
    final public static String _ApproveAction_ = ActionDamlURL + "ApproveAction";
    final public static String _MonitorAction_ = ActionDamlURL + "MonitorAction";


	// Properties
    final public static String _carriesMessage_ = ActionDamlURL + "carriesMessage";
    final public static String _replyTo_ = ActionDamlURL + "replyTo";
    final public static String _accessedEntity_ = ActionDamlURL + "accessedEntity";
    final public static String _performedOn_ = ActionDamlURL + "performedOn";
    final public static String _performedBy_ = ActionDamlURL + "performedBy";
    final public static String _movingTo_ = ActionDamlURL + "movingTo";
    final public static String _hasDestination_ = ActionDamlURL + "hasDestination";
}
