import json
import os
import sys
from tqdm import tqdm
import textwrap # For formatting multi-line strings as YAML

# --- Configuration ---
DEFAULT_RULES_JSON_PATH = 'outputs/rules.json'
DEFAULT_TOOLS_CONFIG_PATH = 'data/tools_config.json'

# --- Logging function for consistent output ---
def log(message, level="INFO"):
    """Prints a log message with a specified level."""
    print(f"[{level}] correlation_logic_builder.py: {message}")

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

# --- Global Mappings & Orderings ---
MITRE_TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]

# Mapping common field names to canonical entity types
COMMON_ENTITY_FIELDS = {
    'user': ['user', 'username', 'account_name', 'sid', 'identity'],
    'host': ['hostname', 'host_ip', 'device_name', 'computer_name', 'ip_address'],
    'ip_address': ['src_ip', 'dest_ip', 'ip_address', 'remote_ip'],
    'process': ['process_id', 'process_name', 'process_path'],
    'file': ['file_name', 'file_path', 'file_hash'],
    'url': ['url', 'request_url']
}

# --- Helper Functions ---

def get_tool_fields_map(tools_config):
    """Builds a map from tool name to its list of fields."""
    tool_fields_map = {}
    for tool in tools_config:
        tool_name = tool.get('tool_name')
        if tool_name:
            tool_fields_map[tool_name] = tool.get('fields', [])
    return tool_fields_map

def find_common_entities(tool1_fields, tool2_fields):
    """
    Finds common canonical entity types between two sets of tool fields.
    """
    common_entities = set()
    for entity_type, aliases in COMMON_ENTITY_FIELDS.items():
        # Check if any alias for this entity type exists in both tool's fields
        tool1_has_entity = any(alias in tool1_fields for alias in aliases)
        tool2_has_entity = any(alias in tool2_fields for alias in aliases)
        if tool1_has_entity and tool2_has_entity:
            common_entities.add(entity_type)
    return sorted(list(common_entities))

def format_yaml_string(data, indent=2):
    """
    Manually formats a dictionary into a YAML-like string.
    This is a simplified formatter and doesn't handle all YAML complexities.
    """
    yaml_lines = []
    def _format(obj, current_indent):
        if isinstance(obj, dict):
            for key, value in obj.items():
                yaml_lines.append(f"{' ' * current_indent}{key}:")
                _format(value, current_indent + indent)
        elif isinstance(obj, list):
            for item in obj:
                yaml_lines.append(f"{' ' * current_indent}-")
                _format(item, current_indent + indent)
        elif isinstance(obj, str) and '\n' in obj:
            # For multi-line strings, use literal style (|+ or |-)
            # This is a simplification; a full YAML parser would be better.
            yaml_lines[-1] += " |" # Append to the key line from dict/list above
            for line in obj.splitlines():
                yaml_lines.append(f"{' ' * (current_indent + indent)}{line}")
        else:
            yaml_lines[-1] += f" {json.dumps(obj)}" # Append value to the key line

    _format(data, 0)
    return "\n".join(yaml_lines)


# --- Main Correlation Logic Builder ---
def main(rules_json_path=DEFAULT_RULES_JSON_PATH, tools_config_path=DEFAULT_TOOLS_CONFIG_PATH):
    """
    Builds correlation logic suggestions for generated rules.

    Args:
        rules_json_path (str): Path to the consolidated rules JSON file (input/output).
        tools_config_path (str): Path to the tools_config JSON file.
    """
    log("Starting correlation logic building process.")

    try:
        # Load data
        rules_data = load_data(rules_json_path, 'json')
        tools_config = load_data(tools_config_path, 'json')
        tool_fields_map = get_tool_fields_map(tools_config)

        log(f"Processing {len(rules_data)} rules to build correlation logic...")

        # Create a mapping for quick lookup of rules by technique and tactic
        rules_by_tactic_tech = {}
        for rule in rules_data:
            tactic = rule.get('MITRE Tactic')
            tech_id = rule.get('MITRE Technique ID')
            if tactic and tech_id:
                if tactic not in rules_by_tactic_tech:
                    rules_by_tactic_tech[tactic] = {}
                if tech_id not in rules_by_tactic_tech[tactic]:
                    rules_by_tactic_tech[tactic][tech_id] = []
                rules_by_tactic_tech[tactic][tech_id].append(rule)

        for i, current_rule in enumerate(tqdm(rules_data, desc="Building Correlation Logic")):
            current_rule_correlations = []
            
            current_mitre_id = current_rule.get('MITRE Technique ID')
            current_tactic = current_rule.get('MITRE Tactic')
            current_tool_name = current_rule.get('Recommended Technologies', ['N/A'])[0]
            current_tool_fields = tool_fields_map.get(current_tool_name, [])

            # 1. Same Technique, Cross-Tool Correlation
            if current_mitre_id and current_tactic:
                if current_mitre_id in rules_by_tactic_tech[current_tactic]:
                    for correlated_rule in rules_by_tactic_tech[current_tactic][current_mitre_id]:
                        if correlated_rule['Rule Name'] != current_rule['Rule Name']: # Ensure not correlating with itself
                            correlated_tool_name = correlated_rule.get('Recommended Technologies', ['N/A'])[0]
                            correlated_tool_fields = tool_fields_map.get(correlated_tool_name, [])
                            
                            common_entities = find_common_entities(current_tool_fields, correlated_tool_fields)
                            
                            if common_entities:
                                correlation_obj = {
                                    "type": "same_technique_cross_tool",
                                    "correlated_rules": [
                                        {"rule_name": current_rule['Rule Name'], "mitre_id": current_mitre_id, "tool": current_tool_name},
                                        {"rule_name": correlated_rule['Rule Name'], "mitre_id": current_mitre_id, "tool": correlated_tool_name}
                                    ],
                                    "common_entities": common_entities,
                                    "logic_summary": f"Correlate '{current_tool_name}' and '{correlated_tool_name}' detections for {current_mitre_id} on the same {', '.join(common_entities)} entities."
                                }
                                current_rule_correlations.append(correlation_obj)
                                # Limit to max 3 similar technique correlations per rule to avoid overwhelming
                                if len(current_rule_correlations) >= 3:
                                    break


            # 2. Sequential Tactic, Cross-Tool/Cross-Technique Correlation
            if current_tactic and current_tactic in MITRE_TACTIC_ORDER:
                current_tactic_index = MITRE_TACTIC_ORDER.index(current_tactic)
                
                # Look for subsequent tactics
                for next_tactic_index in range(current_tactic_index + 1, min(current_tactic_index + 3, len(MITRE_TACTIC_ORDER))): # Look 2 tactics ahead
                    next_tactic = MITRE_TACTIC_ORDER[next_tactic_index]
                    
                    if next_tactic in rules_by_tactic_tech:
                        for next_tech_id in rules_by_tactic_tech[next_tactic]:
                            for potential_next_rule in rules_by_tactic_tech[next_tactic][next_tech_id]:
                                potential_next_tool_name = potential_next_rule.get('Recommended Technologies', ['N/A'])[0]
                                potential_next_tool_fields = tool_fields_map.get(potential_next_tool_name, [])
                                
                                common_entities = find_common_entities(current_tool_fields, potential_next_tool_fields)
                                
                                if common_entities:
                                    logic_summary = (
                                        f"Correlate if '{current_rule['Rule Name']}' ({current_tactic}) detects {current_mitre_id} "
                                        f"on a {', '.join(common_entities)} entity, followed by "
                                        f"'{potential_next_rule['Rule Name']}' ({next_tactic}) detecting {next_tech_id} "
                                        f"on the same {', '.join(common_entities)} within 5 minutes."
                                    )
                                    pseudo_code = textwrap.dedent(f"""\
                                        detection:
                                          initial_event: # Logic for {current_rule['Rule Name']}
                                          subsequent_event: # Logic for {potential_next_rule['Rule Name']}
                                        condition: initial_event.{" AND ".join([f"{ce} == subsequent_event.{ce}" for ce in common_entities])} AND subsequent_event.timestamp - initial_event.timestamp <= 300s
                                    """)

                                    correlation_obj = {
                                        "type": "sequential_tactic_cross_tool",
                                        "sequence": [
                                            {"rule_name": current_rule['Rule Name'], "mitre_id": current_mitre_id, "tool": current_tool_name, "tactic": current_tactic},
                                            {"rule_name": potential_next_rule['Rule Name'], "mitre_id": next_tech_id, "tool": potential_next_tool_name, "tactic": next_tactic}
                                        ],
                                        "common_entities": common_entities,
                                        "logic_summary": logic_summary,
                                        "pseudo_code_example": pseudo_code
                                    }
                                    current_rule_correlations.append(correlation_obj)
                                    # Limit to max 3 sequential correlations per rule to avoid overwhelming
                                    if len(current_rule_correlations) >= 6: # Total limit including same-technique
                                        break
                            if len(current_rule_correlations) >= 6:
                                break
                    if len(current_rule_correlations) >= 6:
                        break

            # Store the correlations as a YAML-like string
            if current_rule_correlations:
                correlation_data = {"correlation_suggestions": current_rule_correlations}
                current_rule["Correlation Logic"] = format_yaml_string(correlation_data)
            else:
                current_rule["Correlation Logic"] = "No specific correlation suggestions found for this rule based on defined heuristics."


        # Save the updated rules
        log(f"Saving rules with correlation logic to: {rules_json_path}")
        with open(rules_json_path, 'w', encoding='utf-8') as f:
            json.dump(rules_data, f, indent=4)
        log("Correlation logic building process completed successfully.")

    except FileNotFoundError as e:
        log(f"Required file not found: {e}", "CRITICAL")
        sys.exit(1)
    except json.JSONDecodeError as e:
        log(f"Invalid JSON format in input file: {e}", "CRITICAL")
        sys.exit(1)
    except Exception as e:
        log(f"An unhandled error occurred during correlation logic building: {e}", "CRITICAL")
        sys.exit(1)

if __name__ == "__main__":
    # Example usage if run directly:
    # python generators/correlation_logic_builder.py outputs/rules.json data/tools_config.json

    if len(sys.argv) == 1: # No arguments, use defaults
        log("No arguments provided. Using default paths for correlation logic building.", "INFO")
        main()
    elif len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])
    else:
        log("Usage: python generators/correlation_logic_builder.py <rules_json_path> <tools_config_json_path>", "ERROR")
        sys.exit(1)
