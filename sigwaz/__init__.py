"""SigWaz — Sigma to Wazuh XML conversion engine."""
from .converter import convert_single, convert_batch, merge_results_xml, ConversionConfig
from .field_maps import FIELD_MAPS, list_products
from .sid_maps import IF_SID_MAP, IF_GROUP_MAP

__version__ = "1.0.0"
__all__ = [
    "convert_single", "convert_batch", "merge_results_xml", "ConversionConfig",
    "FIELD_MAPS", "list_products",
    "IF_SID_MAP", "IF_GROUP_MAP",
]
