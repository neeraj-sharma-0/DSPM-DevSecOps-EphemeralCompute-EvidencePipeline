from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

# Canonical asset categories used by the normalizer
CANONICAL = {
    "object_storage",
    "relational_db",
    "key_value_store",
    "serverless_function",
    "event_bus",
    "api_gateway",
    "vpc_network",
    "log_store",
}

# Provider resource type mapping (demo subset)
RESOURCE_MAP: Dict[str, Dict[str, str]] = {
    "aws": {
        "aws_s3_bucket": "object_storage",
        "aws_db_instance": "relational_db",
        "aws_lambda_function": "serverless_function",
        "aws_cloudwatch_log_group": "log_store",
        "aws_apigatewayv2_api": "api_gateway",
        "aws_cloudwatch_event_rule": "event_bus",
        "aws_vpc": "vpc_network",
    },
    "azure": {
        "azurerm_storage_account": "object_storage",
        "azurerm_mssql_server": "relational_db",
        "azurerm_function_app": "serverless_function",
        "azurerm_log_analytics_workspace": "log_store",
        "azurerm_api_management": "api_gateway",
        "azurerm_eventgrid_topic": "event_bus",
        "azurerm_virtual_network": "vpc_network",
    },
    "gcp": {
        "google_storage_bucket": "object_storage",
        "google_sql_database_instance": "relational_db",
        "google_cloudfunctions_function": "serverless_function",
        "google_logging_project_sink": "log_store",
        "google_api_gateway_api": "api_gateway",
        "google_pubsub_topic": "event_bus",
        "google_compute_network": "vpc_network",
    },
    "ibm": {
        "ibm_cos_bucket": "object_storage",
        "ibm_db2": "relational_db",
        "ibm_function": "serverless_function",
        "ibm_log_analysis": "log_store",
        "ibm_api_gateway": "api_gateway",
        "ibm_event_streams": "event_bus",
        "ibm_is_vpc": "vpc_network",
    },
}

def normalize_resource_type(provider: str, resource_type: str) -> str:
    m = RESOURCE_MAP.get(provider.lower(), {})
    return m.get(resource_type, "unknown")

@dataclass(frozen=True)
class NormalizedAsset:
    asset_id: str
    provider: str
    native_type: str
    canonical_type: str
    tenant: str
    classification: str
    exposure_surface: List[str]  # ids of principals/compute
