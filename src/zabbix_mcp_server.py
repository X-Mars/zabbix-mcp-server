#!/usr/bin/env python3
"""
Zabbix MCP Server - Complete integration with Zabbix API using python-zabbix-utils

This server provides comprehensive access to Zabbix API functionality through
the Model Context Protocol (MCP), enabling AI assistants and other tools to
interact with Zabbix monitoring systems.

Author: Zabbix MCP Server Contributors
License: MIT
"""

import os
import json
import logging
from typing import Any, Dict, List, Optional, Union
from fastmcp import FastMCP
from zabbix_utils import ZabbixAPI
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO if os.getenv("DEBUG") else logging.WARNING,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize FastMCP
mcp = FastMCP("Zabbix MCP Server")

# Global Zabbix API client
zabbix_api: Optional[ZabbixAPI] = None


def get_zabbix_client() -> ZabbixAPI:
    """Get or create Zabbix API client with proper authentication.
    
    Returns:
        ZabbixAPI: Authenticated Zabbix API client
        
    Raises:
        ValueError: If required environment variables are missing
        Exception: If authentication fails
    """
    global zabbix_api
    
    if zabbix_api is None:
        url = os.getenv("ZABBIX_URL")
        if not url:
            raise ValueError("ZABBIX_URL environment variable is required")
        
        logger.info(f"Initializing Zabbix API client for {url}")
        
        # Configure SSL verification
        verify_ssl = os.getenv("VERIFY_SSL", "true").lower() in ("true", "1", "yes")
        logger.info(f"SSL certificate verification: {'enabled' if verify_ssl else 'disabled'}")
        
        # Initialize client
        zabbix_api = ZabbixAPI(url=url, validate_certs=verify_ssl)

        # Authenticate using token or username/password
        token = os.getenv("ZABBIX_TOKEN")
        if token:
            logger.info("Authenticating with API token")
            zabbix_api.login(token=token)
        else:
            user = os.getenv("ZABBIX_USER")
            password = os.getenv("ZABBIX_PASSWORD")
            if not user or not password:
                raise ValueError("Either ZABBIX_TOKEN or ZABBIX_USER/ZABBIX_PASSWORD must be set")
            logger.info(f"Authenticating with username: {user}")
            zabbix_api.login(user=user, password=password)
        
        logger.info("Successfully authenticated with Zabbix API")
    
    return zabbix_api


def is_read_only() -> bool:
    """Check if server is in read-only mode.
    
    Returns:
        bool: True if read-only mode is enabled
    """
    return os.getenv("READ_ONLY", "true").lower() in ("true", "1", "yes")


def format_response(data: Any) -> str:
    """Format response data as JSON string.
    
    Args:
        data: Data to format
        
    Returns:
        str: JSON formatted string
    """
    return json.dumps(data, indent=2, default=str)


def validate_read_only() -> None:
    """Validate that write operations are allowed.
    
    Raises:
        ValueError: If server is in read-only mode
    """
    if is_read_only():
        raise ValueError("Server is in read-only mode - write operations are not allowed")


# HOST MANAGEMENT
@mcp.tool()
def host_get(hostids: Optional[List[str]] = None, 
             groupids: Optional[List[str]] = None,
             templateids: Optional[List[str]] = None,
             proxyids: Optional[List[str]] = None,
             maintenanceids: Optional[List[str]] = None,
             output: Union[str, List[str]] = "extend",
             search: Optional[Dict[str, str]] = None,
             filter: Optional[Dict[str, Any]] = None,
             limit: Optional[int] = None,
             selectHostGroups: Optional[str] = None,
             selectParentTemplates: Optional[str] = None,
             selectInterfaces: Optional[str] = None,
             selectInventory: Optional[str] = None,
             selectItems: Optional[str] = None,
             selectTriggers: Optional[str] = None,
             selectTags: Optional[str] = None,
             selectMacros: Optional[str] = None,
             selectDiscoveries: Optional[str] = None,
             selectGraphs: Optional[str] = None,
             selectHttpTests: Optional[str] = None,
             selectDashboards: Optional[str] = None,
             selectValueMaps: Optional[str] = None,
             monitored_hosts: bool = False,
             with_items: bool = False,
             with_triggers: bool = False,
             with_monitored_items: bool = False,
             with_monitored_triggers: bool = False,
             with_httptests: bool = False,
             with_monitored_httptests: bool = False,
             with_graphs: bool = False,
             withProblemsSuppressed: Optional[bool] = None,
             severities: Optional[List[int]] = None,
             tags: Optional[List[Dict[str, Any]]] = None,
             inheritedTags: bool = False,
             evaltype: int = 0,
             searchInventory: Optional[Dict[str, str]] = None,
             sortfield: Optional[Union[str, List[str]]] = None,
             sortorder: Optional[Union[str, List[str]]] = None) -> str:
    """Get hosts from Zabbix with optional filtering.
    
    Note: maintenance_status is an OUTPUT field, not an input parameter.
    It will be included when output="extend" is used.
    
    Args:
        hostids: List of host IDs to retrieve
        groupids: List of host group IDs to filter by
        templateids: List of template IDs to filter by
        proxyids: List of proxy IDs to filter by
        maintenanceids: List of maintenance IDs to filter by (hosts affected by these maintenances)
        output: Output format (extend or list of specific fields like ["hostid", "host", "name", "status"])
        search: Search criteria (e.g., {"name": "server"} for partial match)
        filter: Filter criteria (e.g., {"status": 0} for enabled hosts)
        limit: Maximum number of results
        selectHostGroups: Return host groups (use "extend" to get all fields)
        selectParentTemplates: Return linked templates (use "extend" to get all fields)
        selectInterfaces: Return host interfaces (use "extend" to get all fields)
        selectInventory: Return host inventory data (use "extend" to get all fields)
        selectItems: Return host items (use "extend" or "count")
        selectTriggers: Return host triggers (use "extend" or "count")
        selectTags: Return host tags (use "extend" to get all fields)
        selectMacros: Return host macros (use "extend" to get all fields)
        selectDiscoveries: Return host LLD rules (use "extend" or "count")
        selectGraphs: Return host graphs (use "extend" or "count")
        selectHttpTests: Return host web scenarios (use "extend" or "count")
        selectDashboards: Return dashboards (use "extend" or "count")
        selectValueMaps: Return host value maps (use "extend")
        monitored_hosts: Return only monitored hosts
        with_items: Return only hosts that have items
        with_triggers: Return only hosts that have triggers
        with_monitored_items: Return only hosts with enabled items
        with_monitored_triggers: Return only hosts with enabled triggers
        with_httptests: Return only hosts with web checks
        with_monitored_httptests: Return only hosts with enabled web checks
        with_graphs: Return only hosts with graphs
        withProblemsSuppressed: Filter hosts with suppressed problems (True/False/None)
        severities: Filter by problem severities (0-5)
        tags: Filter by tags (format: [{"tag": "name", "value": "value", "operator": 0}])
        inheritedTags: Return hosts that have given tags also in all linked templates
        evaltype: Tag evaluation method (0=And/Or, 2=Or)
        searchInventory: Search by inventory fields (e.g., {"os": "Linux"})
        sortfield: Sort by field(s) - ONLY hostid, host, name, status are supported
        sortorder: Sort order (ASC or DESC)
        
    Returns:
        str: JSON formatted list of hosts with all requested data
    """
    client = get_zabbix_client()
    
    # Ensure output includes essential fields for host identification
    if output == "extend":
        # When using "extend", all fields are returned including "host" and "name"
        params = {"output": output}
    elif isinstance(output, list):
        # Ensure "host" is included if not already present
        if "host" not in output:
            output.append("host")
        params = {"output": output}
    else:
        # For other formats, use as specified
        params = {"output": output}
    
    # ID filters
    if hostids:
        params["hostids"] = hostids
    if groupids:
        params["groupids"] = groupids
    if templateids:
        params["templateids"] = templateids
    if proxyids:
        params["proxyids"] = proxyids
    if maintenanceids:
        params["maintenanceids"] = maintenanceids
    
    # Search and filter
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    if searchInventory:
        params["searchInventory"] = searchInventory
    if limit:
        params["limit"] = limit
    
    # Select related data - IMPORTANT: These ensure full data is returned
    if selectHostGroups:
        params["selectHostGroups"] = selectHostGroups
    if selectParentTemplates:
        params["selectParentTemplates"] = selectParentTemplates
    if selectInterfaces:
        params["selectInterfaces"] = selectInterfaces
    if selectInventory:
        params["selectInventory"] = selectInventory
    if selectItems:
        params["selectItems"] = selectItems
    if selectTriggers:
        params["selectTriggers"] = selectTriggers
    if selectTags:
        params["selectTags"] = selectTags
    if selectMacros:
        params["selectMacros"] = selectMacros
    if selectDiscoveries:
        params["selectDiscoveries"] = selectDiscoveries
    if selectGraphs:
        params["selectGraphs"] = selectGraphs
    if selectHttpTests:
        params["selectHttpTests"] = selectHttpTests
    if selectDashboards:
        params["selectDashboards"] = selectDashboards
    if selectValueMaps:
        params["selectValueMaps"] = selectValueMaps
    
    # Boolean flags
    if monitored_hosts:
        params["monitored_hosts"] = monitored_hosts
    if with_items:
        params["with_items"] = with_items
    if with_triggers:
        params["with_triggers"] = with_triggers
    if with_monitored_items:
        params["with_monitored_items"] = with_monitored_items
    if with_monitored_triggers:
        params["with_monitored_triggers"] = with_monitored_triggers
    if with_httptests:
        params["with_httptests"] = with_httptests
    if with_monitored_httptests:
        params["with_monitored_httptests"] = with_monitored_httptests
    if with_graphs:
        params["with_graphs"] = with_graphs
    if withProblemsSuppressed is not None:
        params["withProblemsSuppressed"] = withProblemsSuppressed
    
    # Tag filtering
    if severities is not None:
        params["severities"] = severities
    if tags:
        params["tags"] = tags
        params["evaltype"] = evaltype
    if inheritedTags:
        params["inheritedTags"] = inheritedTags
    
    # Sorting - host.get ONLY supports hostid, host, name, status
    if sortfield:
        valid_sortfields = ["hostid", "host", "name", "status"]
        if isinstance(sortfield, str):
            if sortfield not in valid_sortfields:
                sortfield = "name"  # Default to valid field
        elif isinstance(sortfield, list):
            sortfield = [f for f in sortfield if f in valid_sortfields] or ["name"]
        params["sortfield"] = sortfield
    if sortorder:
        params["sortorder"] = sortorder
    
    result = client.host.get(**params)
    return format_response(result)


@mcp.tool()
def get_current_problems(hostids: Optional[List[str]] = None,
                        groupids: Optional[List[str]] = None,
                        severities: Optional[List[int]] = None,
                        acknowledged: Optional[bool] = None,
                        recent: bool = False,
                        suppressed: Optional[bool] = None,
                        limit: Optional[int] = None) -> str:
    """Get current problems from Zabbix.
    
    Args:
        hostids: List of host IDs to filter by
        groupids: List of host group IDs to filter by
        severities: List of severity levels (0=Not classified, 1=Information, 2=Warning, 3=Average, 4=High, 5=Disaster)
        acknowledged: Filter by acknowledgment status (True=acknowledged only, False=unacknowledged only)
        recent: Include recently resolved problems (default: False returns UNRESOLVED only)
        suppressed: Filter by suppression status (True=suppressed only, False=unsuppressed only)
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of current problems
    """
    client = get_zabbix_client()
    params = {
        "output": "extend",
        "source": 0,  # Trigger problems
        "object": 0,  # Triggers
        "selectAcknowledges": "extend",
        "selectTags": "extend",
        "selectSuppressionData": "extend",
        "sortfield": ["eventid"],  # problem.get only supports eventid for sortfield
        "sortorder": "DESC"
    }
    
    if hostids:
        params["hostids"] = hostids
    if groupids:
        params["groupids"] = groupids
    if severities is not None:
        # severities accepts integer or array of integers
        params["severities"] = severities
    if acknowledged is not None:
        params["acknowledged"] = acknowledged
    if recent:
        params["recent"] = recent
    if suppressed is not None:
        params["suppressed"] = suppressed
    if limit:
        params["limit"] = limit
    
    result = client.problem.get(**params)
    return format_response(result)


@mcp.tool()
def get_host_inventory(hostids: Optional[List[str]] = None,
                      output: Union[str, List[str]] = "extend") -> str:
    """Get host inventory data from Zabbix.
    
    Args:
        hostids: List of host IDs to retrieve inventory for
        output: Output format (extend or list of specific fields)
        
    Returns:
        str: JSON formatted host inventory data
    """
    client = get_zabbix_client()
    params = {
        "output": ["hostid", "host", "name"],
        "selectInventory": output
    }
    
    if hostids:
        params["hostids"] = hostids
    
    result = client.host.get(**params)
    return format_response(result)


@mcp.tool()
def get_host_interfaces(hostids: Optional[List[str]] = None,
                       output: Union[str, List[str]] = "extend") -> str:
    """Get host interface information from Zabbix.
    
    Args:
        hostids: List of host IDs to retrieve interfaces for
        output: Output format for interfaces (extend or list of specific fields)
        
    Returns:
        str: JSON formatted host interface data
    """
    client = get_zabbix_client()
    params = {
        "output": ["hostid", "host", "name"],
        "selectInterfaces": output
    }
    
    if hostids:
        params["hostids"] = hostids
    
    result = client.host.get(**params)
    return format_response(result)


@mcp.tool()
def get_host_triggers(hostids: Optional[List[str]] = None,
                     output: Union[str, List[str]] = "extend",
                     min_severity: Optional[int] = None,
                     only_true: bool = False) -> str:
    """Get triggers for specific hosts from Zabbix.
    
    Args:
        hostids: List of host IDs to retrieve triggers for
        output: Output format (extend or list of specific fields)
        min_severity: Minimum severity level (0-5)
        only_true: Return only triggers in problem state
        
    Returns:
        str: JSON formatted trigger data
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if hostids:
        params["hostids"] = hostids
    if min_severity is not None:
        params["min_severity"] = min_severity
    if only_true:
        params["only_true"] = only_true
    
    result = client.trigger.get(**params)
    return format_response(result)


@mcp.tool()
def get_host_items(hostids: Optional[List[str]] = None,
                  output: Union[str, List[str]] = "extend",
                  monitored: Optional[bool] = None,
                  limit: Optional[int] = None) -> str:
    """Get items for specific hosts from Zabbix.
    
    Args:
        hostids: List of host IDs to retrieve items for
        output: Output format (extend or list of specific fields)
        monitored: Return only enabled items on monitored hosts
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted item data
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if hostids:
        params["hostids"] = hostids
    if monitored is not None:
        params["monitored"] = monitored
    if limit:
        params["limit"] = limit
    
    result = client.item.get(**params)
    return format_response(result)


@mcp.tool()
def get_zabbix_version() -> str:
    """Get Zabbix API version information.
    
    Returns:
        str: JSON formatted API version
    """
    client = get_zabbix_client()
    result = client.apiinfo.version()
    return format_response({"version": result})


@mcp.tool()
def get_server_info() -> str:
    """Get Zabbix server information and status.
    
    Returns:
        str: JSON formatted server information
    """
    client = get_zabbix_client()
    # This is a generic call - in practice, you might need specific API calls
    version = client.apiinfo.version()
    # Try to get user info to verify connection
    try:
        user_info = client.user.get(output=["userid", "username", "name", "surname"])
        return format_response({
            "api_version": version,
            "connected_user": user_info[0] if user_info else None,
            "connection_status": "connected"
        })
    except Exception as e:
        return format_response({
            "api_version": version,
            "connection_status": "error",
            "error": str(e)
        })


@mcp.tool()
def search_hosts_by_name(name_pattern: str, 
                        output: Union[str, List[str]] = ["hostid", "host", "name", "status"],
                        limit: Optional[int] = None) -> str:
    """Search hosts by name pattern.
    
    Args:
        name_pattern: Pattern to search in host names (supports wildcards)
        output: Output format (extend or list of specific fields)
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of matching hosts
    """
    client = get_zabbix_client()
    params = {
        "output": output,
        "search": {"name": name_pattern},
        "searchWildcardsEnabled": True
    }
    
    if limit:
        params["limit"] = limit
    
    result = client.host.get(**params)
    return format_response(result)


@mcp.tool()
def get_host_groups_with_hosts(groupids: Optional[List[str]] = None,
                              output: Union[str, List[str]] = "extend",
                              selectHosts: str = "count") -> str:
    """Get host groups with host counts or details.
    
    Args:
        groupids: List of group IDs to retrieve
        output: Output format for groups
        selectHosts: Host selection mode (count, extend, or specific fields)
        
    Returns:
        str: JSON formatted list of host groups with host information
    """
    client = get_zabbix_client()
    params = {
        "output": output,
        "selectHosts": selectHosts
    }
    
    if groupids:
        params["groupids"] = groupids
    
    result = client.hostgroup.get(**params)
    return format_response(result)


@mcp.tool()
def get_alerts(alertids: Optional[List[str]] = None,
              actionids: Optional[List[str]] = None,
              eventids: Optional[List[str]] = None,
              userid: Optional[str] = None,
              output: Union[str, List[str]] = "extend",
              time_from: Optional[int] = None,
              time_till: Optional[int] = None,
              limit: Optional[int] = None) -> str:
    """Get alerts from Zabbix.
    
    Args:
        alertids: List of alert IDs to retrieve
        actionids: List of action IDs to filter by
        eventids: List of event IDs to filter by
        userid: User ID who received the alert
        output: Output format (extend or list of specific fields)
        time_from: Start time (Unix timestamp)
        time_till: End time (Unix timestamp)
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of alerts
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if alertids:
        params["alertids"] = alertids
    if actionids:
        params["actionids"] = actionids
    if eventids:
        params["eventids"] = eventids
    if userid:
        params["userid"] = userid
    if time_from:
        params["time_from"] = time_from
    if time_till:
        params["time_till"] = time_till
    if limit:
        params["limit"] = limit
    
    result = client.alert.get(**params)
    return format_response(result)


@mcp.tool()
def get_audit_logs(userid: Optional[str] = None,
                  action: Optional[int] = None,
                  resourcetype: Optional[int] = None,
                  resourceid: Optional[str] = None,
                  output: Union[str, List[str]] = "extend",
                  time_from: Optional[int] = None,
                  time_till: Optional[int] = None,
                  limit: Optional[int] = None) -> str:
    """Get audit logs from Zabbix.
    
    Args:
        userid: User ID to filter by
        action: Action type (0=Add, 1=Update, 2=Delete, etc.)
        resourcetype: Resource type (0=User, 4=Host, etc.)
        resourceid: Resource ID
        output: Output format (extend or list of specific fields)
        time_from: Start time (Unix timestamp)
        time_till: End time (Unix timestamp)
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of audit log entries
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if userid:
        params["userid"] = userid
    if action is not None:
        params["action"] = action
    if resourcetype is not None:
        params["resourcetype"] = resourcetype
    if resourceid:
        params["resourceid"] = resourceid
    if time_from:
        params["time_from"] = time_from
    if time_till:
        params["time_till"] = time_till
    if limit:
        params["limit"] = limit
    
    result = client.auditlog.get(**params)
    return format_response(result)


@mcp.tool()
def get_dashboard_widgets(dashboardids: Optional[List[str]] = None,
                         output: Union[str, List[str]] = "extend") -> str:
    """Get dashboard widgets from Zabbix.
    
    Args:
        dashboardids: List of dashboard IDs to retrieve widgets for
        output: Output format (extend or list of specific fields)
        
    Returns:
        str: JSON formatted list of dashboard widgets
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if dashboardids:
        params["dashboardids"] = dashboardids
    
    result = client.dashboard.get(**params)
    return format_response(result)


@mcp.tool()
def get_scripts(scriptids: Optional[List[str]] = None,
               groupids: Optional[List[str]] = None,
               hostids: Optional[List[str]] = None,
               output: Union[str, List[str]] = "extend") -> str:
    """Get global scripts from Zabbix.
    
    Args:
        scriptids: List of script IDs to retrieve
        groupids: List of host group IDs to filter by
        hostids: List of host IDs to filter by
        output: Output format (extend or list of specific fields)
        
    Returns:
        str: JSON formatted list of scripts
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if scriptids:
        params["scriptids"] = scriptids
    if groupids:
        params["groupids"] = groupids
    if hostids:
        params["hostids"] = hostids
    
    result = client.script.get(**params)
    return format_response(result)


@mcp.tool()
def host_create(host: str, groups: List[Dict[str, str]], 
                interfaces: List[Dict[str, Any]],
                templates: Optional[List[Dict[str, str]]] = None,
                name: Optional[str] = None,
                inventory_mode: int = -1,
                status: int = 0,
                description: Optional[str] = None,
                tags: Optional[List[Dict[str, str]]] = None,
                macros: Optional[List[Dict[str, str]]] = None,
                inventory: Optional[Dict[str, str]] = None,
                monitored_by: int = 0,
                proxyid: Optional[str] = None,
                proxy_groupid: Optional[str] = None,
                tls_connect: int = 1,
                tls_accept: int = 1,
                tls_psk_identity: Optional[str] = None,
                tls_psk: Optional[str] = None,
                tls_issuer: Optional[str] = None,
                tls_subject: Optional[str] = None) -> str:
    """Create a new host in Zabbix.
    
    Args:
        host: Technical host name (unique identifier)
        groups: List of host groups (format: [{"groupid": "1"}])
        interfaces: List of host interfaces (format: [{"type": 1, "main": 1, "useip": 1, "ip": "192.168.1.1", "dns": "", "port": "10050"}])
                   Interface types: 1=Agent, 2=SNMP, 3=IPMI, 4=JMX
        templates: List of templates to link (format: [{"templateid": "1"}])
        name: Visible name of the host (displayed in frontend)
        inventory_mode: Inventory mode (-1=disabled, 0=manual, 1=automatic)
        status: Host status (0=enabled, 1=disabled)
        description: Host description
        tags: Host tags (format: [{"tag": "name", "value": "value"}])
        macros: Host macros (format: [{"macro": "{$MACRO}", "value": "value"}])
        inventory: Host inventory fields (format: {"os": "Linux", "location": "DC1"})
        monitored_by: Monitoring source (0=Zabbix server, 1=Proxy, 2=Proxy group)
        proxyid: Proxy ID (required if monitored_by=1)
        proxy_groupid: Proxy group ID (required if monitored_by=2)
        tls_connect: TLS connection (1=No encryption, 2=PSK, 4=Certificate)
        tls_accept: TLS accept (1=No encryption, 2=PSK, 4=Certificate, can be sum)
        tls_psk_identity: PSK identity
        tls_psk: Pre-shared key (min 32 hex digits)
        tls_issuer: Certificate issuer
        tls_subject: Certificate subject
        
    Returns:
        str: JSON formatted creation result with hostid
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "host": host,
        "groups": groups,
        "interfaces": interfaces,
        "inventory_mode": inventory_mode,
        "status": status
    }
    
    if name:
        params["name"] = name
    if templates:
        params["templates"] = templates
    if description:
        params["description"] = description
    if tags:
        params["tags"] = tags
    if macros:
        params["macros"] = macros
    if inventory:
        params["inventory"] = inventory
    
    # Monitoring configuration
    params["monitored_by"] = monitored_by
    if monitored_by == 1 and proxyid:
        params["proxyid"] = proxyid
    if monitored_by == 2 and proxy_groupid:
        params["proxy_groupid"] = proxy_groupid
    
    # TLS configuration
    params["tls_connect"] = tls_connect
    params["tls_accept"] = tls_accept
    if tls_psk_identity:
        params["tls_psk_identity"] = tls_psk_identity
    if tls_psk:
        params["tls_psk"] = tls_psk
    if tls_issuer:
        params["tls_issuer"] = tls_issuer
    if tls_subject:
        params["tls_subject"] = tls_subject
    
    result = client.host.create(**params)
    return format_response(result)


@mcp.tool()
def host_update(hostid: str, host: Optional[str] = None, 
                name: Optional[str] = None, status: Optional[int] = None,
                description: Optional[str] = None,
                groups: Optional[List[Dict[str, str]]] = None,
                templates: Optional[List[Dict[str, str]]] = None,
                templates_clear: Optional[List[Dict[str, str]]] = None,
                tags: Optional[List[Dict[str, str]]] = None,
                macros: Optional[List[Dict[str, str]]] = None,
                inventory: Optional[Dict[str, str]] = None,
                inventory_mode: Optional[int] = None,
                monitored_by: Optional[int] = None,
                proxyid: Optional[str] = None,
                proxy_groupid: Optional[str] = None) -> str:
    """Update an existing host in Zabbix.
    
    Args:
        hostid: Host ID to update (required)
        host: New technical host name
        name: New visible name
        status: New status (0=enabled, 1=disabled)
        description: New description
        groups: New host groups (replaces existing)
        templates: Templates to link (will be added to existing)
        templates_clear: Templates to unlink and clear (removes all related entities)
        tags: New host tags (replaces existing)
        macros: New host macros (replaces existing)
        inventory: Inventory fields to update
        inventory_mode: New inventory mode (-1=disabled, 0=manual, 1=automatic)
        monitored_by: Monitoring source (0=Zabbix server, 1=Proxy, 2=Proxy group)
        proxyid: Proxy ID
        proxy_groupid: Proxy group ID
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"hostid": hostid}
    
    if host:
        params["host"] = host
    if name:
        params["name"] = name
    if status is not None:
        params["status"] = status
    if description:
        params["description"] = description
    if groups:
        params["groups"] = groups
    if templates:
        params["templates"] = templates
    if templates_clear:
        params["templates_clear"] = templates_clear
    if tags:
        params["tags"] = tags
    if macros:
        params["macros"] = macros
    if inventory:
        params["inventory"] = inventory
    if inventory_mode is not None:
        params["inventory_mode"] = inventory_mode
    if monitored_by is not None:
        params["monitored_by"] = monitored_by
    if proxyid:
        params["proxyid"] = proxyid
    if proxy_groupid:
        params["proxy_groupid"] = proxy_groupid
    
    result = client.host.update(**params)
    return format_response(result)


@mcp.tool()
def host_delete(hostids: List[str]) -> str:
    """Delete hosts from Zabbix.
    
    Args:
        hostids: List of host IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.host.delete(*hostids)
    return format_response(result)


# HOST GROUP MANAGEMENT
@mcp.tool()
def hostgroup_get(groupids: Optional[List[str]] = None,
                  hostids: Optional[List[str]] = None,
                  templateids: Optional[List[str]] = None,
                  graphids: Optional[List[str]] = None,
                  triggerids: Optional[List[str]] = None,
                  output: Union[str, List[str]] = "extend",
                  search: Optional[Dict[str, str]] = None,
                  filter: Optional[Dict[str, Any]] = None,
                  limit: Optional[int] = None,
                  selectHosts: Optional[str] = None,
                  selectTemplates: Optional[str] = None,
                  selectDiscoveryRules: Optional[str] = None,
                  selectHostPrototypes: Optional[str] = None,
                  with_hosts: bool = False,
                  with_templates: bool = False,
                  with_items: bool = False,
                  with_triggers: bool = False,
                  with_graphs: bool = False,
                  with_monitored_hosts: bool = False,
                  with_monitored_items: bool = False,
                  with_monitored_triggers: bool = False,
                  sortfield: Optional[Union[str, List[str]]] = None,
                  sortorder: Optional[Union[str, List[str]]] = None) -> str:
    """Get host groups from Zabbix with optional filtering.
    
    Args:
        groupids: List of group IDs to retrieve
        hostids: Return groups containing these hosts
        templateids: Return groups containing these templates
        graphids: Return groups containing hosts with these graphs
        triggerids: Return groups containing hosts with these triggers
        output: Output format (extend or list of specific fields)
        search: Search criteria (e.g., {"name": "Linux"})
        filter: Filter criteria
        limit: Maximum number of results
        selectHosts: Return hosts in the group (use "extend" or specific fields)
        selectTemplates: Return templates in the group
        selectDiscoveryRules: Return discovery rules
        selectHostPrototypes: Return host prototypes
        with_hosts: Return only groups containing hosts
        with_templates: Return only groups containing templates
        with_items: Return only groups containing hosts with items
        with_triggers: Return only groups containing hosts with triggers
        with_graphs: Return only groups containing hosts with graphs
        with_monitored_hosts: Return only groups containing monitored hosts
        with_monitored_items: Return only groups containing hosts with enabled items
        with_monitored_triggers: Return only groups containing hosts with enabled triggers
        sortfield: Sort by field(s) (groupid, name)
        sortorder: Sort order (ASC or DESC)
        
    Returns:
        str: JSON formatted list of host groups
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    # ID filters
    if groupids:
        params["groupids"] = groupids
    if hostids:
        params["hostids"] = hostids
    if templateids:
        params["templateids"] = templateids
    if graphids:
        params["graphids"] = graphids
    if triggerids:
        params["triggerids"] = triggerids
    
    # Search and filter
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    if limit:
        params["limit"] = limit
    
    # Select related data
    if selectHosts:
        params["selectHosts"] = selectHosts
    if selectTemplates:
        params["selectTemplates"] = selectTemplates
    if selectDiscoveryRules:
        params["selectDiscoveryRules"] = selectDiscoveryRules
    if selectHostPrototypes:
        params["selectHostPrototypes"] = selectHostPrototypes
    
    # Boolean flags
    if with_hosts:
        params["with_hosts"] = with_hosts
    if with_templates:
        params["with_templates"] = with_templates
    if with_items:
        params["with_items"] = with_items
    if with_triggers:
        params["with_triggers"] = with_triggers
    if with_graphs:
        params["with_graphs"] = with_graphs
    if with_monitored_hosts:
        params["with_monitored_hosts"] = with_monitored_hosts
    if with_monitored_items:
        params["with_monitored_items"] = with_monitored_items
    if with_monitored_triggers:
        params["with_monitored_triggers"] = with_monitored_triggers
    
    # Sorting
    if sortfield:
        params["sortfield"] = sortfield
    if sortorder:
        params["sortorder"] = sortorder
    
    result = client.hostgroup.get(**params)
    return format_response(result)


@mcp.tool()
def hostgroup_create(name: str) -> str:
    """Create a new host group in Zabbix.
    
    Args:
        name: Host group name
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.hostgroup.create(name=name)
    return format_response(result)


@mcp.tool()
def hostgroup_update(groupid: str, name: str) -> str:
    """Update an existing host group in Zabbix.
    
    Args:
        groupid: Group ID to update
        name: New group name
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.hostgroup.update(groupid=groupid, name=name)
    return format_response(result)


@mcp.tool()
def hostgroup_delete(groupids: List[str]) -> str:
    """Delete host groups from Zabbix.
    
    Args:
        groupids: List of group IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.hostgroup.delete(*groupids)
    return format_response(result)


# ITEM MANAGEMENT
@mcp.tool()
def item_get(itemids: Optional[List[str]] = None,
             hostids: Optional[List[str]] = None,
             groupids: Optional[List[str]] = None,
             templateids: Optional[List[str]] = None,
             interfaceids: Optional[List[str]] = None,
             triggerids: Optional[List[str]] = None,
             output: Union[str, List[str]] = "extend",
             search: Optional[Dict[str, str]] = None,
             filter: Optional[Dict[str, Any]] = None,
             limit: Optional[int] = None,
             selectHosts: Optional[str] = None,
             selectInterfaces: Optional[str] = None,
             selectTriggers: Optional[str] = None,
             selectTags: Optional[str] = None,
             selectPreprocessing: Optional[str] = None,
             selectValueMap: Optional[str] = None,
             webitems: bool = False,
             inherited: Optional[bool] = None,
             templated: Optional[bool] = None,
             monitored: Optional[bool] = None,
             with_triggers: Optional[bool] = None,
             group: Optional[str] = None,
             host: Optional[str] = None,
             tags: Optional[List[Dict[str, Any]]] = None,
             evaltype: int = 0,
             selectGraphs: Optional[str] = None,
             selectDiscoveryRule: Optional[str] = None,
             selectItemDiscovery: Optional[str] = None,
             limitSelects: Optional[int] = None,
             sortfield: Optional[Union[str, List[str]]] = None,
             sortorder: Optional[Union[str, List[str]]] = None,
             searchByAny: Optional[bool] = None,
             searchWildcardsEnabled: Optional[bool] = None,
             startSearch: Optional[bool] = None,
             excludeSearch: Optional[bool] = None,
             editable: Optional[bool] = None,
             preservekeys: Optional[bool] = None,
             countOutput: Optional[bool] = None) -> str:
    """Get items from Zabbix with optional filtering.
    
    Args:
        itemids: List of item IDs to retrieve
        hostids: List of host IDs to filter by
        groupids: List of host group IDs to filter by
        templateids: List of template IDs to filter by
        interfaceids: List of interface IDs to filter by
        triggerids: List of trigger IDs - return only items used in these triggers
        output: Output format (extend or list of specific fields)
        search: Search criteria (e.g., {"key_": "cpu", "name": "CPU"})
        filter: Filter criteria (e.g., {"type": 0, "status": 0})
        limit: Maximum number of results
        selectHosts: Return hosts that the item belongs to
        selectInterfaces: Return host interfaces used by the item
        selectTriggers: Return triggers that use this item
        selectTags: Return item tags
        selectPreprocessing: Return preprocessing rules
        selectValueMap: Return value map
        webitems: Include web items in the result
        inherited: Return only inherited items from templates
        templated: Return only items belonging to templates
        monitored: Return only enabled items on monitored hosts
        with_triggers: Return only items used in triggers
        group: Return items from host group with this name
        host: Return items from host with this technical name
        tags: Filter by tags
        evaltype: Tag evaluation method (0=And/Or, 2=Or)
        selectGraphs: Return graphs that contain the item
        selectDiscoveryRule: Return LLD rule that created the item
        selectItemDiscovery: Return item discovery object
        limitSelects: Limit number of records in subselects
        sortfield: Sort by field(s) (itemid, name, key_, delay, history, trends, type, status)
        sortorder: Sort order (ASC or DESC)
        searchByAny: Search in any of the fields
        searchWildcardsEnabled: Enable wildcards in search
        startSearch: Search from beginning of field
        excludeSearch: Exclude results matching search
        editable: Return only items editable by current user
        preservekeys: Preserve keys in result array
        countOutput: Return count instead of objects
        
    Returns:
        str: JSON formatted list of items
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    # ID filters
    if itemids:
        params["itemids"] = itemids
    if hostids:
        params["hostids"] = hostids
    if groupids:
        params["groupids"] = groupids
    if templateids:
        params["templateids"] = templateids
    if interfaceids:
        params["interfaceids"] = interfaceids
    if triggerids:
        params["triggerids"] = triggerids
    
    # Search and filter
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    if limit:
        params["limit"] = limit
    
    # Select related data
    if selectHosts:
        params["selectHosts"] = selectHosts
    if selectInterfaces:
        params["selectInterfaces"] = selectInterfaces
    if selectTriggers:
        params["selectTriggers"] = selectTriggers
    if selectTags:
        params["selectTags"] = selectTags
    if selectPreprocessing:
        params["selectPreprocessing"] = selectPreprocessing
    if selectValueMap:
        params["selectValueMap"] = selectValueMap
    if selectGraphs:
        params["selectGraphs"] = selectGraphs
    if selectDiscoveryRule:
        params["selectDiscoveryRule"] = selectDiscoveryRule
    if selectItemDiscovery:
        params["selectItemDiscovery"] = selectItemDiscovery
    if limitSelects:
        params["limitSelects"] = limitSelects
    
    # Boolean flags
    if webitems:
        params["webitems"] = webitems
    if inherited is not None:
        params["inherited"] = inherited
    if templated is not None:
        params["templated"] = templated
    if monitored is not None:
        params["monitored"] = monitored
    if with_triggers is not None:
        params["with_triggers"] = with_triggers
    
    # Name filters
    if group:
        params["group"] = group
    if host:
        params["host"] = host
    
    # Tag filtering
    if tags:
        params["tags"] = tags
        params["evaltype"] = evaltype
    
    # Sorting
    if sortfield:
        params["sortfield"] = sortfield
    if sortorder:
        params["sortorder"] = sortorder
    
    # Additional options
    if searchByAny is not None:
        params["searchByAny"] = searchByAny
    if searchWildcardsEnabled is not None:
        params["searchWildcardsEnabled"] = searchWildcardsEnabled
    if startSearch is not None:
        params["startSearch"] = startSearch
    if excludeSearch is not None:
        params["excludeSearch"] = excludeSearch
    if editable is not None:
        params["editable"] = editable
    if preservekeys is not None:
        params["preservekeys"] = preservekeys
    if countOutput is not None:
        params["countOutput"] = countOutput
    
    result = client.item.get(**params)
    return format_response(result)


@mcp.tool()
def item_create(name: str, key_: str, hostid: str, type: int,
                value_type: int, delay: str = "1m",
                units: Optional[str] = None,
                description: Optional[str] = None) -> str:
    """Create a new item in Zabbix.
    
    Args:
        name: Item name
        key_: Item key
        hostid: Host ID
        type: Item type (0=Zabbix agent, 2=Zabbix trapper, etc.)
        value_type: Value type (0=float, 1=character, 3=unsigned int, 4=text)
        delay: Update interval
        units: Value units
        description: Item description
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "name": name,
        "key_": key_,
        "hostid": hostid,
        "type": type,
        "value_type": value_type,
        "delay": delay
    }
    
    if units:
        params["units"] = units
    if description:
        params["description"] = description
    
    result = client.item.create(**params)
    return format_response(result)


@mcp.tool()
def item_update(itemid: str, name: Optional[str] = None,
                key_: Optional[str] = None, delay: Optional[str] = None,
                status: Optional[int] = None) -> str:
    """Update an existing item in Zabbix.
    
    Args:
        itemid: Item ID to update
        name: New item name
        key_: New item key
        delay: New update interval
        status: New status (0=enabled, 1=disabled)
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"itemid": itemid}
    
    if name:
        params["name"] = name
    if key_:
        params["key_"] = key_
    if delay:
        params["delay"] = delay
    if status is not None:
        params["status"] = status
    
    result = client.item.update(**params)
    return format_response(result)


@mcp.tool()
def item_delete(itemids: List[str]) -> str:
    """Delete items from Zabbix.
    
    Args:
        itemids: List of item IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.item.delete(*itemids)
    return format_response(result)


# TRIGGER MANAGEMENT
@mcp.tool()
def trigger_get(triggerids: Optional[List[str]] = None,
                hostids: Optional[List[str]] = None,
                groupids: Optional[List[str]] = None,
                templateids: Optional[List[str]] = None,
                itemids: Optional[List[str]] = None,
                output: Union[str, List[str]] = "extend",
                search: Optional[Dict[str, str]] = None,
                filter: Optional[Dict[str, Any]] = None,
                limit: Optional[int] = None,
                selectHostGroups: Optional[str] = None,
                selectHosts: Optional[str] = None,
                selectItems: Optional[str] = None,
                selectFunctions: Optional[str] = None,
                selectDependencies: Optional[str] = None,
                selectTags: Optional[str] = None,
                selectLastEvent: Optional[str] = None,
                expandComment: bool = False,
                expandDescription: bool = False,
                expandExpression: bool = False,
                inherited: Optional[bool] = None,
                templated: Optional[bool] = None,
                dependent: Optional[bool] = None,
                monitored: bool = False,
                active: bool = False,
                maintenance: Optional[bool] = None,
                withUnacknowledgedEvents: bool = False,
                withLastEventUnacknowledged: bool = False,
                skipDependent: bool = False,
                only_true: bool = False,
                min_severity: Optional[int] = None,
                tags: Optional[List[Dict[str, Any]]] = None,
                evaltype: int = 0,
                sortfield: Optional[Union[str, List[str]]] = None,
                sortorder: Optional[Union[str, List[str]]] = None) -> str:
    """Get triggers from Zabbix with optional filtering.
    
    Args:
        triggerids: List of trigger IDs to retrieve
        hostids: List of host IDs to filter by
        groupids: List of host group IDs to filter by
        templateids: List of template IDs to filter by
        itemids: List of item IDs - return triggers containing these items
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria (e.g., {"value": 1} for triggers in problem state)
        limit: Maximum number of results
        selectHostGroups: Return host groups
        selectHosts: Return hosts that the trigger belongs to
        selectItems: Return items used in the trigger
        selectFunctions: Return functions used in the trigger
        selectDependencies: Return trigger dependencies
        selectTags: Return trigger tags
        selectLastEvent: Return last significant event
        expandComment: Expand macros in comments
        expandDescription: Expand macros in trigger name
        expandExpression: Expand functions and macros in expression
        inherited: Return only inherited triggers
        templated: Return only triggers from templates
        dependent: Return only triggers with/without dependencies
        monitored: Return only enabled triggers on monitored hosts
        active: Return only enabled triggers on monitored hosts
        maintenance: Return only triggers for hosts in maintenance
        withUnacknowledgedEvents: Return triggers with unacknowledged events
        withLastEventUnacknowledged: Return triggers with last event unacknowledged
        skipDependent: Skip dependent triggers in problem state
        only_true: Return only triggers recently in problem state
        min_severity: Return triggers with severity >= this value
        tags: Filter by tags
        evaltype: Tag evaluation method (0=And/Or, 2=Or)
        sortfield: Sort by field(s) (triggerid, description, status, priority, lastchange, hostname)
        sortorder: Sort order (ASC or DESC)
        
    Returns:
        str: JSON formatted list of triggers
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    # ID filters
    if triggerids:
        params["triggerids"] = triggerids
    if hostids:
        params["hostids"] = hostids
    if groupids:
        params["groupids"] = groupids
    if templateids:
        params["templateids"] = templateids
    if itemids:
        params["itemids"] = itemids
    
    # Search and filter
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    if limit:
        params["limit"] = limit
    
    # Select related data
    if selectHostGroups:
        params["selectHostGroups"] = selectHostGroups
    if selectHosts:
        params["selectHosts"] = selectHosts
    if selectItems:
        params["selectItems"] = selectItems
    if selectFunctions:
        params["selectFunctions"] = selectFunctions
    if selectDependencies:
        params["selectDependencies"] = selectDependencies
    if selectTags:
        params["selectTags"] = selectTags
    if selectLastEvent:
        params["selectLastEvent"] = selectLastEvent
    
    # Expansion options
    if expandComment:
        params["expandComment"] = expandComment
    if expandDescription:
        params["expandDescription"] = expandDescription
    if expandExpression:
        params["expandExpression"] = expandExpression
    
    # Boolean flags
    if inherited is not None:
        params["inherited"] = inherited
    if templated is not None:
        params["templated"] = templated
    if dependent is not None:
        params["dependent"] = dependent
    if monitored:
        params["monitored"] = monitored
    if active:
        params["active"] = active
    if maintenance is not None:
        params["maintenance"] = maintenance
    if withUnacknowledgedEvents:
        params["withUnacknowledgedEvents"] = withUnacknowledgedEvents
    if withLastEventUnacknowledged:
        params["withLastEventUnacknowledged"] = withLastEventUnacknowledged
    if skipDependent:
        params["skipDependent"] = skipDependent
    if only_true:
        params["only_true"] = only_true
    if min_severity is not None:
        params["min_severity"] = min_severity
    
    # Tag filtering
    if tags:
        params["tags"] = tags
        params["evaltype"] = evaltype
    
    # Sorting
    if sortfield:
        params["sortfield"] = sortfield
    if sortorder:
        params["sortorder"] = sortorder
    
    result = client.trigger.get(**params)
    return format_response(result)


@mcp.tool()
def trigger_create(description: str, expression: str,
                   priority: int = 0, status: int = 0,
                   comments: Optional[str] = None) -> str:
    """Create a new trigger in Zabbix.
    
    Args:
        description: Trigger description
        expression: Trigger expression
        priority: Severity (0=not classified, 1=info, 2=warning, 3=average, 4=high, 5=disaster)
        status: Status (0=enabled, 1=disabled)
        comments: Additional comments
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "description": description,
        "expression": expression,
        "priority": priority,
        "status": status
    }
    
    if comments:
        params["comments"] = comments
    
    result = client.trigger.create(**params)
    return format_response(result)


@mcp.tool()
def trigger_update(triggerid: str, description: Optional[str] = None,
                   expression: Optional[str] = None, priority: Optional[int] = None,
                   status: Optional[int] = None) -> str:
    """Update an existing trigger in Zabbix.
    
    Args:
        triggerid: Trigger ID to update
        description: New trigger description
        expression: New trigger expression
        priority: New severity level
        status: New status (0=enabled, 1=disabled)
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"triggerid": triggerid}
    
    if description:
        params["description"] = description
    if expression:
        params["expression"] = expression
    if priority is not None:
        params["priority"] = priority
    if status is not None:
        params["status"] = status
    
    result = client.trigger.update(**params)
    return format_response(result)


@mcp.tool()
def trigger_delete(triggerids: List[str]) -> str:
    """Delete triggers from Zabbix.
    
    Args:
        triggerids: List of trigger IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.trigger.delete(*triggerids)
    return format_response(result)


# TEMPLATE MANAGEMENT
@mcp.tool()
def template_get(templateids: Optional[List[str]] = None,
                 groupids: Optional[List[str]] = None,
                 hostids: Optional[List[str]] = None,
                 parentTemplateids: Optional[List[str]] = None,
                 graphids: Optional[List[str]] = None,
                 itemids: Optional[List[str]] = None,
                 triggerids: Optional[List[str]] = None,
                 output: Union[str, List[str]] = "extend",
                 search: Optional[Dict[str, str]] = None,
                 filter: Optional[Dict[str, Any]] = None,
                 limit: Optional[int] = None,
                 selectHostGroups: Optional[str] = None,
                 selectTemplateGroups: Optional[str] = None,
                 selectParentTemplates: Optional[str] = None,
                 selectTemplates: Optional[str] = None,
                 selectHosts: Optional[str] = None,
                 selectItems: Optional[str] = None,
                 selectTriggers: Optional[str] = None,
                 selectGraphs: Optional[str] = None,
                 selectDiscoveries: Optional[str] = None,
                 selectHttpTests: Optional[str] = None,
                 selectMacros: Optional[str] = None,
                 selectDashboards: Optional[str] = None,
                 selectTags: Optional[str] = None,
                 selectValueMaps: Optional[str] = None,
                 with_items: bool = False,
                 with_triggers: bool = False,
                 with_graphs: bool = False,
                 with_httptests: bool = False,
                 tags: Optional[List[Dict[str, Any]]] = None,
                 evaltype: int = 0,
                 sortfield: Optional[Union[str, List[str]]] = None,
                 sortorder: Optional[Union[str, List[str]]] = None) -> str:
    """Get templates from Zabbix with optional filtering.
    
    Args:
        templateids: List of template IDs to retrieve
        groupids: List of host group IDs to filter by
        hostids: List of host IDs to filter by (return templates linked to these hosts)
        parentTemplateids: Return templates that are linked to these parent templates
        graphids: Return templates with these graphs
        itemids: Return templates with these items
        triggerids: Return templates with these triggers
        output: Output format (extend or list of specific fields like ["templateid", "host", "name"])
        search: Search criteria (e.g., {"name": "Linux"} for partial match)
        filter: Filter criteria (e.g., {"host": "Template OS Linux"})
        limit: Maximum number of results
        selectHostGroups: Return host groups (use "extend" to get all fields)
        selectTemplateGroups: Return template groups (use "extend" to get all fields)
        selectParentTemplates: Return parent templates (use "extend" to get all fields)
        selectTemplates: Return linked templates (use "extend" to get all fields)
        selectHosts: Return hosts linked to this template (use "extend" to get all fields)
        selectItems: Return template items (use "extend" or "count")
        selectTriggers: Return template triggers (use "extend" or "count")
        selectGraphs: Return template graphs (use "extend" or "count")
        selectDiscoveries: Return template LLD rules (use "extend" or "count")
        selectHttpTests: Return template web scenarios (use "extend" or "count")
        selectMacros: Return template macros (use "extend" to get all fields)
        selectDashboards: Return template dashboards (use "extend" to get all fields)
        selectTags: Return template tags (use "extend" to get all fields)
        selectValueMaps: Return template value maps (use "extend" to get all fields)
        with_items: Return only templates with items
        with_triggers: Return only templates with triggers
        with_graphs: Return only templates with graphs
        with_httptests: Return only templates with web scenarios
        tags: Filter by tags (format: [{"tag": "name", "value": "value", "operator": 0}])
        evaltype: Tag evaluation method (0=And/Or, 2=Or)
        sortfield: Sort by field(s) (templateid, host, name)
        sortorder: Sort order (ASC or DESC)
        
    Returns:
        str: JSON formatted list of templates with all requested data
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    # ID filters
    if templateids:
        params["templateids"] = templateids
    if groupids:
        params["groupids"] = groupids
    if hostids:
        params["hostids"] = hostids
    if parentTemplateids:
        params["parentTemplateids"] = parentTemplateids
    if graphids:
        params["graphids"] = graphids
    if itemids:
        params["itemids"] = itemids
    if triggerids:
        params["triggerids"] = triggerids
    
    # Search and filter
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    if limit:
        params["limit"] = limit
    
    # Select related data
    if selectHostGroups:
        params["selectHostGroups"] = selectHostGroups
    if selectTemplateGroups:
        params["selectTemplateGroups"] = selectTemplateGroups
    if selectParentTemplates:
        params["selectParentTemplates"] = selectParentTemplates
    if selectTemplates:
        params["selectTemplates"] = selectTemplates
    if selectHosts:
        params["selectHosts"] = selectHosts
    if selectItems:
        params["selectItems"] = selectItems
    if selectTriggers:
        params["selectTriggers"] = selectTriggers
    if selectGraphs:
        params["selectGraphs"] = selectGraphs
    if selectDiscoveries:
        params["selectDiscoveries"] = selectDiscoveries
    if selectHttpTests:
        params["selectHttpTests"] = selectHttpTests
    if selectMacros:
        params["selectMacros"] = selectMacros
    if selectDashboards:
        params["selectDashboards"] = selectDashboards
    if selectTags:
        params["selectTags"] = selectTags
    if selectValueMaps:
        params["selectValueMaps"] = selectValueMaps
    
    # Boolean flags
    if with_items:
        params["with_items"] = with_items
    if with_triggers:
        params["with_triggers"] = with_triggers
    if with_graphs:
        params["with_graphs"] = with_graphs
    if with_httptests:
        params["with_httptests"] = with_httptests
    
    # Tag filtering
    if tags:
        params["tags"] = tags
        params["evaltype"] = evaltype
    
    # Sorting
    if sortfield:
        params["sortfield"] = sortfield
    if sortorder:
        params["sortorder"] = sortorder
    
    result = client.template.get(**params)
    return format_response(result)


@mcp.tool()
def template_create(host: str, groups: List[Dict[str, str]],
                    name: Optional[str] = None, description: Optional[str] = None) -> str:
    """Create a new template in Zabbix.
    
    Args:
        host: Template technical name
        groups: List of host groups (format: [{"groupid": "1"}])
        name: Template visible name
        description: Template description
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "host": host,
        "groups": groups
    }
    
    if name:
        params["name"] = name
    if description:
        params["description"] = description
    
    result = client.template.create(**params)
    return format_response(result)


@mcp.tool()
def template_update(templateid: str, host: Optional[str] = None,
                    name: Optional[str] = None, description: Optional[str] = None) -> str:
    """Update an existing template in Zabbix.
    
    Args:
        templateid: Template ID to update
        host: New template technical name
        name: New template visible name
        description: New template description
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"templateid": templateid}
    
    if host:
        params["host"] = host
    if name:
        params["name"] = name
    if description:
        params["description"] = description
    
    result = client.template.update(**params)
    return format_response(result)


@mcp.tool()
def template_delete(templateids: List[str]) -> str:
    """Delete templates from Zabbix.
    
    Args:
        templateids: List of template IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.template.delete(*templateids)
    return format_response(result)


# PROBLEM MANAGEMENT
@mcp.tool()
def problem_get(eventids: Optional[List[str]] = None,
                groupids: Optional[List[str]] = None,
                hostids: Optional[List[str]] = None,
                objectids: Optional[List[str]] = None,
                output: Union[str, List[str]] = "extend",
                source: int = 0,
                object: int = 0,
                time_from: Optional[int] = None,
                time_till: Optional[int] = None,
                eventid_from: Optional[str] = None,
                eventid_till: Optional[str] = None,
                recent: bool = False,
                acknowledged: Optional[bool] = None,
                action: Optional[int] = None,
                action_userids: Optional[List[str]] = None,
                suppressed: Optional[bool] = None,
                symptom: Optional[bool] = None,
                severities: Optional[List[int]] = None,
                tags: Optional[List[Dict[str, Any]]] = None,
                evaltype: int = 0,
                selectAcknowledges: Optional[str] = None,
                selectTags: Optional[str] = None,
                selectSuppressionData: Optional[str] = None,
                sortfield: Optional[Union[str, List[str]]] = None,
                sortorder: Optional[Union[str, List[str]]] = None,
                limit: Optional[int] = None) -> str:
    """Get problems from Zabbix with optional filtering.
    
    Note: This method returns unresolved problems. Use recent=True to also include
    recently resolved problems. For older resolved problems, use event_get.
    
    Args:
        eventids: List of event IDs to retrieve
        groupids: List of host group IDs to filter by
        hostids: List of host IDs to filter by
        objectids: List of object IDs (trigger IDs) to filter by
        output: Output format (extend or list of specific fields)
        source: Event source (0=trigger, 1=discovery, 2=autoregistration, 3=internal, 4=service)
        object: Event object type (0=trigger, 4=item, 5=LLD rule, 6=service)
        time_from: Start time (Unix timestamp)
        time_till: End time (Unix timestamp)
        eventid_from: Return problems with event IDs >= this value
        eventid_till: Return problems with event IDs <= this value
        recent: Include recently resolved problems (default: False returns UNRESOLVED only)
        acknowledged: Filter by acknowledgment status (True=acknowledged only, False=unacknowledged only)
        action: Return only problems for which the given event update actions have been performed
        action_userids: Return only problems with actions performed by these user IDs
        suppressed: Filter by suppression status (True=suppressed only, False=unsuppressed only)
        symptom: Filter symptom problems (True=symptoms only, False=causes only)
        severities: List of severity levels to filter by (0=Not classified, 1=Information, 2=Warning, 3=Average, 4=High, 5=Disaster)
        tags: Filter by tags (format: [{"tag": "name", "value": "value", "operator": 0}])
        evaltype: Tag evaluation method (0=And/Or, 2=Or)
        selectAcknowledges: Return acknowledgment details (use "extend")
        selectTags: Return problem tags (use "extend")
        selectSuppressionData: Return suppression data (use "extend")
        sortfield: Sort by field - ONLY "eventid" is supported
        sortorder: Sort order (ASC or DESC)
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of problems
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    # ID filters
    if eventids:
        params["eventids"] = eventids
    if groupids:
        params["groupids"] = groupids
    if hostids:
        params["hostids"] = hostids
    if objectids:
        params["objectids"] = objectids
    
    # Source and object type
    params["source"] = source
    params["object"] = object
    
    # Time filters
    if time_from:
        params["time_from"] = time_from
    if time_till:
        params["time_till"] = time_till
    if eventid_from:
        params["eventid_from"] = eventid_from
    if eventid_till:
        params["eventid_till"] = eventid_till
    
    # Boolean flags
    if recent:
        params["recent"] = recent
    if acknowledged is not None:
        params["acknowledged"] = acknowledged
    if action is not None:
        params["action"] = action
    if action_userids:
        params["action_userids"] = action_userids
    if suppressed is not None:
        params["suppressed"] = suppressed
    if symptom is not None:
        params["symptom"] = symptom
    
    # Severity filter - accepts integer or array of integers
    if severities is not None:
        params["severities"] = severities
    
    # Tag filtering
    if tags:
        params["tags"] = tags
        params["evaltype"] = evaltype
    
    # Select related data
    if selectAcknowledges:
        params["selectAcknowledges"] = selectAcknowledges
    if selectTags:
        params["selectTags"] = selectTags
    if selectSuppressionData:
        params["selectSuppressionData"] = selectSuppressionData
    
    # Sorting and limit - problem.get ONLY supports "eventid" as sortfield
    if sortfield:
        # Validate sortfield - only eventid is allowed
        if isinstance(sortfield, str):
            if sortfield != "eventid":
                sortfield = "eventid"  # Force to valid value
        elif isinstance(sortfield, list):
            sortfield = ["eventid"]  # Force to valid value
        params["sortfield"] = sortfield
    if sortorder:
        params["sortorder"] = sortorder
    if limit:
        params["limit"] = limit
    
    result = client.problem.get(**params)
    return format_response(result)


# EVENT MANAGEMENT
@mcp.tool()
def event_get(eventids: Optional[List[str]] = None,
              groupids: Optional[List[str]] = None,
              hostids: Optional[List[str]] = None,
              objectids: Optional[List[str]] = None,
              output: Union[str, List[str]] = "extend",
              time_from: Optional[int] = None,
              time_till: Optional[int] = None,
              limit: Optional[int] = None) -> str:
    """Get events from Zabbix with optional filtering.
    
    Args:
        eventids: List of event IDs to retrieve
        groupids: List of host group IDs to filter by
        hostids: List of host IDs to filter by
        objectids: List of object IDs to filter by
        output: Output format (extend or list of specific fields)
        time_from: Start time (Unix timestamp)
        time_till: End time (Unix timestamp)
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of events
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if eventids:
        params["eventids"] = eventids
    if groupids:
        params["groupids"] = groupids
    if hostids:
        params["hostids"] = hostids
    if objectids:
        params["objectids"] = objectids
    if time_from:
        params["time_from"] = time_from
    if time_till:
        params["time_till"] = time_till
    if limit:
        params["limit"] = limit
    
    result = client.event.get(**params)
    return format_response(result)


@mcp.tool()
def event_acknowledge(eventids: List[str], action: int = 1,
                      message: Optional[str] = None) -> str:
    """Acknowledge events in Zabbix.
    
    Args:
        eventids: List of event IDs to acknowledge
        action: Acknowledge action (1=acknowledge, 2=close, etc.)
        message: Acknowledge message
        
    Returns:
        str: JSON formatted acknowledgment result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "eventids": eventids,
        "action": action
    }
    
    if message:
        params["message"] = message
    
    result = client.event.acknowledge(**params)
    return format_response(result)


# HISTORY MANAGEMENT
@mcp.tool()
def history_get(itemids: List[str], history: int = 0,
                time_from: Optional[int] = None,
                time_till: Optional[int] = None,
                limit: Optional[int] = None,
                sortfield: str = "clock",
                sortorder: str = "DESC") -> str:
    """Get history data from Zabbix.
    
    Args:
        itemids: List of item IDs to get history for
        history: History type (0=float, 1=character, 2=log, 3=unsigned, 4=text)
        time_from: Start time (Unix timestamp)
        time_till: End time (Unix timestamp)
        limit: Maximum number of results
        sortfield: Field to sort by
        sortorder: Sort order (ASC or DESC)
        
    Returns:
        str: JSON formatted history data
    """
    client = get_zabbix_client()
    params = {
        "itemids": itemids,
        "history": history,
        "sortfield": sortfield,
        "sortorder": sortorder
    }
    
    if time_from:
        params["time_from"] = time_from
    if time_till:
        params["time_till"] = time_till
    if limit:
        params["limit"] = limit
    
    result = client.history.get(**params)
    return format_response(result)


# TREND MANAGEMENT
@mcp.tool()
def trend_get(itemids: List[str], time_from: Optional[int] = None,
              time_till: Optional[int] = None,
              limit: Optional[int] = None) -> str:
    """Get trend data from Zabbix.
    
    Args:
        itemids: List of item IDs to get trends for
        time_from: Start time (Unix timestamp)
        time_till: End time (Unix timestamp)
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted trend data
    """
    client = get_zabbix_client()
    params = {"itemids": itemids}
    
    if time_from:
        params["time_from"] = time_from
    if time_till:
        params["time_till"] = time_till
    if limit:
        params["limit"] = limit
    
    result = client.trend.get(**params)
    return format_response(result)


# USER MANAGEMENT
@mcp.tool()
def user_get(userids: Optional[List[str]] = None,
             output: Union[str, List[str]] = "extend",
             search: Optional[Dict[str, str]] = None,
             filter: Optional[Dict[str, Any]] = None) -> str:
    """Get users from Zabbix with optional filtering.
    
    Args:
        userids: List of user IDs to retrieve
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        
    Returns:
        str: JSON formatted list of users
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if userids:
        params["userids"] = userids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    result = client.user.get(**params)
    return format_response(result)


@mcp.tool()
def user_create(username: str, passwd: str, usrgrps: List[Dict[str, str]],
                name: Optional[str] = None, surname: Optional[str] = None,
                email: Optional[str] = None) -> str:
    """Create a new user in Zabbix.
    
    Args:
        username: Username
        passwd: Password
        usrgrps: List of user groups (format: [{"usrgrpid": "1"}])
        name: First name
        surname: Last name
        email: Email address
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "username": username,
        "passwd": passwd,
        "usrgrps": usrgrps
    }
    
    if name:
        params["name"] = name
    if surname:
        params["surname"] = surname
    if email:
        params["email"] = email
    
    result = client.user.create(**params)
    return format_response(result)


@mcp.tool()
def user_update(userid: str, username: Optional[str] = None,
                name: Optional[str] = None, surname: Optional[str] = None,
                email: Optional[str] = None) -> str:
    """Update an existing user in Zabbix.
    
    Args:
        userid: User ID to update
        username: New username
        name: New first name
        surname: New last name
        email: New email address
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"userid": userid}
    
    if username:
        params["username"] = username
    if name:
        params["name"] = name
    if surname:
        params["surname"] = surname
    if email:
        params["email"] = email
    
    result = client.user.update(**params)
    return format_response(result)


@mcp.tool()
def user_delete(userids: List[str]) -> str:
    """Delete users from Zabbix.
    
    Args:
        userids: List of user IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.user.delete(*userids)
    return format_response(result)


# PROXY MANAGEMENT
@mcp.tool()
def proxy_get(proxyids: Optional[List[str]] = None,
              output: str = "extend",
              search: Optional[Dict[str, str]] = None,
              filter: Optional[Dict[str, Any]] = None,
              limit: Optional[int] = None) -> str:
    """Get proxies from Zabbix with optional filtering.
    
    Args:
        proxyids: List of proxy IDs to retrieve
        output: Output format (extend, shorten, or specific fields)
        search: Search criteria
        filter: Filter criteria
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of proxies
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if proxyids:
        params["proxyids"] = proxyids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    if limit:
        params["limit"] = limit
    
    result = client.proxy.get(**params)
    return format_response(result)


@mcp.tool()
def proxy_create(host: str, status: int = 5,
                 description: Optional[str] = None,
                 tls_connect: int = 1,
                 tls_accept: int = 1) -> str:
    """Create a new proxy in Zabbix.
    
    Args:
        host: Proxy name
        status: Proxy status (5=active proxy, 6=passive proxy)
        description: Proxy description
        tls_connect: TLS connection settings (1=no encryption, 2=PSK, 4=certificate)
        tls_accept: TLS accept settings (1=no encryption, 2=PSK, 4=certificate)
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "host": host,
        "status": status,
        "tls_connect": tls_connect,
        "tls_accept": tls_accept
    }
    
    if description:
        params["description"] = description
    
    result = client.proxy.create(**params)
    return format_response(result)


@mcp.tool()
def proxy_update(proxyid: str, host: Optional[str] = None,
                 status: Optional[int] = None,
                 description: Optional[str] = None,
                 tls_connect: Optional[int] = None,
                 tls_accept: Optional[int] = None) -> str:
    """Update an existing proxy in Zabbix.
    
    Args:
        proxyid: Proxy ID to update
        host: New proxy name
        status: New proxy status (5=active proxy, 6=passive proxy)
        description: New proxy description
        tls_connect: New TLS connection settings
        tls_accept: New TLS accept settings
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"proxyid": proxyid}
    
    if host:
        params["host"] = host
    if status is not None:
        params["status"] = status
    if description:
        params["description"] = description
    if tls_connect is not None:
        params["tls_connect"] = tls_connect
    if tls_accept is not None:
        params["tls_accept"] = tls_accept
    
    result = client.proxy.update(**params)
    return format_response(result)


@mcp.tool()
def proxy_delete(proxyids: List[str]) -> str:
    """Delete proxies from Zabbix.
    
    Args:
        proxyids: List of proxy IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.proxy.delete(*proxyids)
    return format_response(result)


# MAINTENANCE MANAGEMENT
@mcp.tool()
def maintenance_get(maintenanceids: Optional[List[str]] = None,
                    groupids: Optional[List[str]] = None,
                    hostids: Optional[List[str]] = None,
                    output: Union[str, List[str]] = "extend",
                    selectHostGroups: Optional[str] = None,
                    selectHosts: Optional[str] = None,
                    selectTags: Optional[str] = None,
                    selectTimeperiods: Optional[str] = None,
                    sortfield: Optional[Union[str, List[str]]] = None,
                    sortorder: Optional[Union[str, List[str]]] = None,
                    search: Optional[Dict[str, str]] = None,
                    filter: Optional[Dict[str, Any]] = None,
                    limit: Optional[int] = None) -> str:
    """Get maintenance periods from Zabbix.
    
    Note: active_since and active_till are OUTPUT fields, not input parameters.
    Use filter parameter to filter by these fields if needed.
    
    Args:
        maintenanceids: List of maintenance IDs to retrieve
        groupids: List of host group IDs that are assigned to the maintenance
        hostids: List of host IDs that are assigned to the maintenance
        output: Output format (extend or list of specific fields)
        selectHostGroups: Return host groups assigned to the maintenance (use "extend")
        selectHosts: Return hosts assigned to the maintenance (use "extend")
        selectTags: Return problem tags of the maintenance (use "extend")
        selectTimeperiods: Return time periods of the maintenance (use "extend")
        sortfield: Sort by field(s) - supports: maintenanceid, name, maintenance_type, active_since, active_till
        sortorder: Sort order (ASC or DESC)
        search: Search criteria (e.g., {"name": "maintenance"})
        filter: Filter criteria (e.g., {"maintenance_type": 0})
        limit: Maximum number of results
        
    Returns:
        str: JSON formatted list of maintenance periods
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if maintenanceids:
        params["maintenanceids"] = maintenanceids
    if groupids:
        params["groupids"] = groupids
    if hostids:
        params["hostids"] = hostids
    
    # Select related data
    if selectHostGroups:
        params["selectHostGroups"] = selectHostGroups
    if selectHosts:
        params["selectHosts"] = selectHosts
    if selectTags:
        params["selectTags"] = selectTags
    if selectTimeperiods:
        params["selectTimeperiods"] = selectTimeperiods
    
    # Search and filter
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    # Sorting
    if sortfield:
        params["sortfield"] = sortfield
    if sortorder:
        params["sortorder"] = sortorder
    
    if limit:
        params["limit"] = limit
    
    result = client.maintenance.get(**params)
    return format_response(result)


@mcp.tool()
def maintenance_create(name: str, active_since: int, active_till: int,
                       groupids: Optional[List[str]] = None,
                       hostids: Optional[List[str]] = None,
                       timeperiods: Optional[List[Dict[str, Any]]] = None,
                       description: Optional[str] = None) -> str:
    """Create a new maintenance period in Zabbix.
    
    Args:
        name: Maintenance name
        active_since: Start time (Unix timestamp)
        active_till: End time (Unix timestamp)
        groupids: List of host group IDs
        hostids: List of host IDs
        timeperiods: List of time periods
        description: Maintenance description
        
    Returns:
        str: JSON formatted creation result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "name": name,
        "active_since": active_since,
        "active_till": active_till
    }
    
    if groupids:
        params["groupids"] = groupids
    if hostids:
        params["hostids"] = hostids
    if timeperiods:
        params["timeperiods"] = timeperiods
    if description:
        params["description"] = description
    
    result = client.maintenance.create(**params)
    return format_response(result)


@mcp.tool()
def maintenance_update(maintenanceid: str, name: Optional[str] = None,
                       active_since: Optional[int] = None, active_till: Optional[int] = None,
                       description: Optional[str] = None) -> str:
    """Update an existing maintenance period in Zabbix.
    
    Args:
        maintenanceid: Maintenance ID to update
        name: New maintenance name
        active_since: New start time (Unix timestamp)
        active_till: New end time (Unix timestamp)
        description: New maintenance description
        
    Returns:
        str: JSON formatted update result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {"maintenanceid": maintenanceid}
    
    if name:
        params["name"] = name
    if active_since:
        params["active_since"] = active_since
    if active_till:
        params["active_till"] = active_till
    if description:
        params["description"] = description
    
    result = client.maintenance.update(**params)
    return format_response(result)


@mcp.tool()
def maintenance_delete(maintenanceids: List[str]) -> str:
    """Delete maintenance periods from Zabbix.
    
    Args:
        maintenanceids: List of maintenance IDs to delete
        
    Returns:
        str: JSON formatted deletion result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    result = client.maintenance.delete(*maintenanceids)
    return format_response(result)


# GRAPH MANAGEMENT
@mcp.tool()
def graph_get(graphids: Optional[List[str]] = None,
              hostids: Optional[List[str]] = None,
              templateids: Optional[List[str]] = None,
              output: Union[str, List[str]] = "extend",
              search: Optional[Dict[str, str]] = None,
              filter: Optional[Dict[str, Any]] = None) -> str:
    """Get graphs from Zabbix with optional filtering.
    
    Args:
        graphids: List of graph IDs to retrieve
        hostids: List of host IDs to filter by
        templateids: List of template IDs to filter by
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        
    Returns:
        str: JSON formatted list of graphs
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if graphids:
        params["graphids"] = graphids
    if hostids:
        params["hostids"] = hostids
    if templateids:
        params["templateids"] = templateids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    result = client.graph.get(**params)
    return format_response(result)


# DISCOVERY RULE MANAGEMENT
@mcp.tool()
def discoveryrule_get(itemids: Optional[List[str]] = None,
                      hostids: Optional[List[str]] = None,
                      templateids: Optional[List[str]] = None,
                      output: Union[str, List[str]] = "extend",
                      search: Optional[Dict[str, str]] = None,
                      filter: Optional[Dict[str, Any]] = None) -> str:
    """Get discovery rules from Zabbix with optional filtering.
    
    Args:
        itemids: List of discovery rule IDs to retrieve
        hostids: List of host IDs to filter by
        templateids: List of template IDs to filter by
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        
    Returns:
        str: JSON formatted list of discovery rules
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if itemids:
        params["itemids"] = itemids
    if hostids:
        params["hostids"] = hostids
    if templateids:
        params["templateids"] = templateids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    result = client.discoveryrule.get(**params)
    return format_response(result)


# ITEM PROTOTYPE MANAGEMENT
@mcp.tool()
def itemprototype_get(itemids: Optional[List[str]] = None,
                      discoveryids: Optional[List[str]] = None,
                      hostids: Optional[List[str]] = None,
                      output: Union[str, List[str]] = "extend",
                      search: Optional[Dict[str, str]] = None,
                      filter: Optional[Dict[str, Any]] = None) -> str:
    """Get item prototypes from Zabbix with optional filtering.
    
    Args:
        itemids: List of item prototype IDs to retrieve
        discoveryids: List of discovery rule IDs to filter by
        hostids: List of host IDs to filter by
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        
    Returns:
        str: JSON formatted list of item prototypes
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if itemids:
        params["itemids"] = itemids
    if discoveryids:
        params["discoveryids"] = discoveryids
    if hostids:
        params["hostids"] = hostids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    result = client.itemprototype.get(**params)
    return format_response(result)


# CONFIGURATION EXPORT/IMPORT
@mcp.tool()
def configuration_export(format: str = "json",
                         options: Optional[Dict[str, Any]] = None) -> str:
    """Export configuration from Zabbix.
    
    Args:
        format: Export format (json, xml)
        options: Export options
        
    Returns:
        str: JSON formatted export result
    """
    client = get_zabbix_client()
    params = {"format": format}
    
    if options:
        params["options"] = options
    
    result = client.configuration.export(**params)
    return format_response(result)


@mcp.tool()
def configuration_import(format: str, source: str,
                         rules: Dict[str, Any]) -> str:
    """Import configuration to Zabbix.
    
    Args:
        format: Import format (json, xml)
        source: Configuration data to import
        rules: Import rules
        
    Returns:
        str: JSON formatted import result
    """
    validate_read_only()
    
    client = get_zabbix_client()
    params = {
        "format": format,
        "source": source,
        "rules": rules
    }
    
    result = client.configuration.import_(**params)
    return format_response(result)


# MACRO MANAGEMENT
@mcp.tool()
def usermacro_get(globalmacroids: Optional[List[str]] = None,
                  hostids: Optional[List[str]] = None,
                  output: Union[str, List[str]] = "extend",
                  search: Optional[Dict[str, str]] = None,
                  filter: Optional[Dict[str, Any]] = None) -> str:
    """Get global macros from Zabbix with optional filtering.
    
    Args:
        globalmacroids: List of global macro IDs to retrieve
        hostids: List of host IDs to filter by (for host macros)
        output: Output format (extend or list of specific fields)
        search: Search criteria
        filter: Filter criteria
        
    Returns:
        str: JSON formatted list of global macros
    """
    client = get_zabbix_client()
    params = {"output": output}
    
    if globalmacroids:
        params["globalmacroids"] = globalmacroids
    if hostids:
        params["hostids"] = hostids
    if search:
        params["search"] = search
    if filter:
        params["filter"] = filter
    
    result = client.usermacro.get(**params)
    return format_response(result)


# SYSTEM INFO
@mcp.tool()
def apiinfo_version() -> str:
    """Get Zabbix API version information.
    
    Returns:
        str: JSON formatted API version info
    """
    client = get_zabbix_client()
    result = client.apiinfo.version()
    return format_response(result)


def get_transport_config() -> Dict[str, Any]:
    """Get transport configuration from environment variables.
    
    Returns:
        Dict[str, Any]: Transport configuration
        
    Raises:
        ValueError: If invalid transport configuration
    """
    transport = os.getenv("ZABBIX_MCP_TRANSPORT", "stdio").lower()
    
    if transport not in ["stdio", "streamable-http"]:
        raise ValueError(f"Invalid ZABBIX_MCP_TRANSPORT: {transport}. Must be 'stdio' or 'streamable-http'")
    
    config = {"transport": transport}
    
    if transport == "streamable-http":
        # Check AUTH_TYPE requirement
        auth_type = os.getenv("AUTH_TYPE", "").lower()
        if auth_type != "no-auth":
            raise ValueError("AUTH_TYPE must be set to 'no-auth' when using streamable-http transport")
        
        # Get HTTP configuration with defaults
        config.update({
            "host": os.getenv("ZABBIX_MCP_HOST", "127.0.0.1"),
            "port": int(os.getenv("ZABBIX_MCP_PORT", "8000")),
            "stateless_http": os.getenv("ZABBIX_MCP_STATELESS_HTTP", "false").lower() in ("true", "1", "yes")
        })
        
        logger.info(f"HTTP transport configured: {config['host']}:{config['port']}, stateless_http={config['stateless_http']}")
    
    return config


def main():
    """Main entry point for uv execution."""
    logger.info("Starting Zabbix MCP Server")
    
    # Get transport configuration
    try:
        transport_config = get_transport_config()
        logger.info(f"Transport: {transport_config['transport']}")
    except ValueError as e:
        logger.error(f"Transport configuration error: {e}")
        return 1
    
    # Log configuration
    logger.info(f"Read-only mode: {is_read_only()}")
    logger.info(f"Zabbix URL: {os.getenv('ZABBIX_URL', 'Not configured')}")
    
    try:
        if transport_config["transport"] == "stdio":
            mcp.run()
        else:  # streamable-http
            mcp.run(
                transport="streamable-http",
                host=transport_config["host"],
                port=transport_config["port"],
                stateless_http=transport_config["stateless_http"]
            )
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise


if __name__ == "__main__":
    main()
