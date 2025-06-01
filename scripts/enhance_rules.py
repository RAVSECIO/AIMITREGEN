import json
import os
import sys
from tqdm import tqdm

# --- Configuration ---
DEFAULT_RULES_JSON_PATH = 'outputs/rules.json'
DEFAULT_MITRE_MATRIX_PATH = 'data/mitre_matrix.json'

# --- Logging function for consistent output ---
def log(message, level="INFO"):
    """Prints a log message with a specified level."""
    print(f"[{level}] enhance_rules.py: {message}")

# --- Data Loading (re-used) ---
def load_data(file_path, data_type='json'):
    """
    Loads data from a specified file path.

    Args:
        file_path (str): The path to the data file.
        data_type (str): 'json' to indicate the file type.

    Returns:
        dict or list: The loaded data.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        json.JSONDecodeError: If JSON file content is invalid.
        Exception: For other unexpected errors.
    """
    log(f"Attempting to load {data_type} data from: {file_path}")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Data file not found at: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        log(f"Successfully loaded {data_type} data from {file_path}.")
        return data
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log(f"Error loading {file_path}: {e}", "ERROR")
        raise
    except Exception as e:
        log(f"An unexpected error occurred while loading {file_path}: {e}", "ERROR")
        raise

# --- Normalization Helpers ---
def normalize_list_casing(items_list):
    """Normalizes casing of strings in a list to Title Case and removes duplicates."""
    if not isinstance(items_list, list):
        return items_list # Return as is if not a list
    return sorted(list(set(item.strip().title() for item in items_list if isinstance(item, str))))

def apply_canonical_mapping(items_list, mapping):
    """Applies canonical mapping to terms in a list."""
    if not isinstance(items_list, list):
        return items_list
    return sorted(list(set(mapping.get(item, item) for item in items_list)))

# Define some canonical mappings
CANONICAL_MAPPINGS = {
    "Windows Logs": "Windows Event Logs",
    "Windows Security Logs": "Windows Event Logs",
    "Sysmon": "Windows Event Logs", # Sysmon events are typically ingested as Windows Event Logs
    "Firewall": "Network Firewall Logs",
    "Network Flow": "Network Traffic Logs",
    "DNS": "DNS Logs",
    "Proxy": "Proxy Logs",
    "Cloud Trail": "Cloud Audit Logs",
    "Authentication": "Authentication Logs",
    "Endpoint": "Endpoint Activity Logs",
    "Process": "Process Activity Logs"
}

# --- Enrichment Helpers ---
def build_mitre_details_map(mitre_matrix):
    """Builds a map from MITRE ID to its description and URL."""
    mitre_map = {}
    for tech in mitre_matrix:
        tech_id = tech.get('technique_id')
        if tech_id:
            mitre_map[tech_id] = {
                'description': tech.get('description', 'No description available for this technique.'),
                'url': tech.get('url', f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/") # Corrected URL format
            }
        for sub_tech in tech.get('sub_techniques', []):
            sub_tech_id = sub_tech.get('sub_technique_id')
            if sub_tech_id:
                parent_id_part = sub_tech_id.split('.')[0]
                sub_id_part = sub_tech_id.split('.')[1]
                mitre_map[sub_tech_id] = {
                    'description': sub_tech.get('description', 'No description available for this sub-technique.'),
                    'url': sub_tech.get('url', f"https://attack.mitre.org/techniques/{parent_id_part}/{sub_id_part}/")
                }
    return mitre_map

# --- Initial FP Reduction Strategy Helper ---
def get_generic_fp_reduction_suggestion(rule_data):
    """Provides generic FP reduction suggestions based on rule data."""
    suggestions = []
    
    data_sources = [ds.lower() for ds in rule_data.get("Data Sources", [])]
    tech_categories = [tc.lower() for tc in rule_data.get("Tech Categories", [])]

    if "network event logs" in data_sources or "network traffic logs" in data_sources or "network firewall logs" in data_sources:
        suggestions.append("Consider baselining common network traffic patterns and exclude known good internal/external IP ranges.")
    if "endpoint activity logs" in data_sources or "process activity logs" in data_sources:
        suggestions.append("Implement application whitelisting for critical processes and monitor for unsigned executable launches.")
    if "authentication logs" in data_sources:
        suggestions.append("Monitor for unusual login times, geolocations, or failed login attempts followed by success from new sources.")
    if "dns logs" in data_sources:
        suggestions.append("Filter out queries to known legitimate DNS servers and internal domains; focus on suspicious TLDs or high-entropy domains.")
    if "proxy logs" in data_sources:
        suggestions.append("Exclude known good internal proxy traffic. Focus on direct-to-IP connections bypassing proxy, or unusual user-agents.")
    if "cloud audit logs" in data_sources:
        suggestions.append("Establish a baseline for normal cloud API calls and user activity; monitor for privilege escalation attempts or unusual resource creation/deletion.")
    
    if not suggestions and rule_data.get("Synthetic", False):
         suggestions.append("As a synthetic rule, a detailed FP reduction strategy requires specific data source analysis and threat intelligence.")
    elif not suggestions:
        suggestions.append("Review relevant system logs and application behavior to establish a baseline for normal activity.")

    return " ".join(suggestions)

# --- Main Enhancement Function ---
def main(rules_json_path=DEFAULT_RULES_JSON_PATH, mitre_matrix_path=DEFAULT_MITRE_MATRIX_PATH):
    """
    Enhances generated rules with normalization, enrichment, and initial FP reduction strategies.

    Args:
        rules_json_path (str): Path to the consolidated rules JSON file.
        mitre_matrix_path (str): Path to the MITRE ATT&CK matrix JSON file.
    """
    log("Starting rule enhancement process.")

    try:
        # Load rules and MITRE matrix
        rules_data = load_data(rules_json_path, 'json')
        mitre_matrix = load_data(mitre_matrix_path, 'json')
        mitre_details_map = build_mitre_details_map(mitre_matrix)

        log(f"Processing {len(rules_data)} rules for enhancement...")
        for rule in tqdm(rules_data, desc="Enhancing Rules"):
            mitre_id = rule.get("MITRE Technique ID")

            # 1. Normalization
            rule["Data Sources"] = normalize_list_casing(rule.get("Data Sources", []))
            rule["Data Sources"] = apply_canonical_mapping(rule["Data Sources"], CANONICAL_MAPPINGS)
            
            rule["Tech Categories"] = normalize_list_casing(rule.get("Tech Categories", []))
            rule["Tech Categories"] = apply_canonical_mapping(rule["Tech Categories"], CANONICAL_MAPPINGS)

            # 2. Enrichment
            if mitre_id and mitre_id in mitre_details_map:
                mitre_info = mitre_details_map[mitre_id]
                rule["MITRE Description"] = mitre_info['description']
                rule["MITRE URL"] = mitre_info['url']
            else:
                rule["MITRE Description"] = "Description not found for this MITRE ID."
                rule["MITRE URL"] = "N/A"

            # 3. Initial FP Reduction Strategy
            current_fp_reduction = rule.get("FP Reduction", "")
            generic_suggestion = get_generic_fp_reduction_suggestion(rule)
            
            if current_fp_reduction and current_fp_reduction != "To be defined later":
                rule["FP Reduction"] = f"{current_fp_reduction}. {generic_suggestion}"
            else:
                rule["FP Reduction"] = generic_suggestion
            
        # Save the enhanced rules
        log(f"Saving enhanced rules to: {rules_json_path}")
        with open(rules_json_path, 'w', encoding='utf-8') as f:
            json.dump(rules_data, f, indent=4)
        log("Rule enhancement process completed successfully.")

    except FileNotFoundError as e:
        log(f"Required file not found: {e}", "CRITICAL")
        sys.exit(1)
    except json.JSONDecodeError as e:
        log(f"Invalid JSON format in input file: {e}", "CRITICAL")
        sys.exit(1)
    except Exception as e:
        log(f"An unhandled error occurred during rule enhancement: {e}", "CRITICAL")
        sys.exit(1)

if __name__ == "__main__":
    # Example usage if run directly:
    # python scripts/enhance_rules.py outputs/rules.json data/mitre_matrix.json

    if len(sys.argv) == 1: # No arguments, use defaults
        log("No arguments provided. Using default paths for rule enhancement.", "INFO")
        main()
    elif len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])
    else:
        log("Usage: python scripts/enhance_rules.py <rules_json_path> <mitre_matrix_json_path>", "ERROR")
        sys.exit(1)
