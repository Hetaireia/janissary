"""Third-party integrations and protocol clients."""

from .graphql import (
    ARG_PAYLOADS,
    INTROSPECTION_QUERY,
    TYPENAME_QUERY,
    FuzzResult,
    GraphQLClient,
    GraphQLError,
    GraphQLProfile,
    GraphQLResponse,
    alias_probe,
    build_alias_query,
    build_argument_query,
    build_nested_query,
    depth_probe,
    detect,
    enumerate_fields,
    fuzz_arguments,
    resolve_endpoint,
)
from .websocket import (
    WebSocketFinding,
    WebSocketProfile,
    is_plaintext,
    profile_to_json,
)
from .websocket import scan as websocket_scan
from .websocket import scan_sync as websocket_scan_sync
from .xmlrpc import (  # nosec B411 # relative import of local .xmlrpc package, not stdlib xmlrpclib
    AUTH_METHODS,
    METHODS_OF_INTEREST,
    XmlRpcAttempt,
    XmlRpcClient,
    XmlRpcError,
    XmlRpcFault,
    XmlRpcProfile,
    bruteforce_multicall,
    build_call,
    build_multicall,
    parse_response,
    pingback_probe,
)
from .xmlrpc import (
    detect as xmlrpc_detect,  # nosec B411 # relative import of local .xmlrpc package, not stdlib xmlrpclib
)
from .xmlrpc import (
    resolve_endpoint as xmlrpc_resolve_endpoint,  # nosec B411 # relative import of local .xmlrpc package, not stdlib xmlrpclib
)

__all__ = [
    "ARG_PAYLOADS",
    "AUTH_METHODS",
    "INTROSPECTION_QUERY",
    "METHODS_OF_INTEREST",
    "TYPENAME_QUERY",
    "FuzzResult",
    "GraphQLClient",
    "GraphQLError",
    "GraphQLProfile",
    "GraphQLResponse",
    "WebSocketFinding",
    "WebSocketProfile",
    "XmlRpcAttempt",
    "XmlRpcClient",
    "XmlRpcError",
    "XmlRpcFault",
    "XmlRpcProfile",
    "alias_probe",
    "bruteforce_multicall",
    "build_alias_query",
    "build_argument_query",
    "build_call",
    "build_multicall",
    "build_nested_query",
    "depth_probe",
    "detect",
    "enumerate_fields",
    "fuzz_arguments",
    "is_plaintext",
    "parse_response",
    "pingback_probe",
    "profile_to_json",
    "resolve_endpoint",
    "websocket_scan",
    "websocket_scan_sync",
    "xmlrpc_detect",
    "xmlrpc_resolve_endpoint",
]
