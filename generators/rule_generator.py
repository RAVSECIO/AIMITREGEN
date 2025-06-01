import json
import os
import sys
import uuid # For generating unique rule IDs
from jinja2 import Environment, FileSystemLoader
from tqdm import tqdm
import numpy as np
import yaml # Added yaml import for Jinja2 filter and JSON output
from datetime import datetime # For current date in Sigma rules

# --- Configuration ---
# Default paths (can be overridden by main.py arguments)
DEFAULT_MITRE_MATRIX_PATH = 'data/mitre_matrix.json'
DEFAULT_TOOLS_CONFIG_PATH = 'data/tools_config.json'
DEFAULT_TOOL_MITRE_MAPPING_PATH = 'data/tool_mitre_mapping.json'
DEFAULT_RULE_TEMPLATE_PATH = 'templates/rule_template.json'
DEFAULT_SYNTAX_TEMPLATES_DIR = 'templates/syntax_templates'
DEFAULT_GENERATED_RULES_DIR = 'outputs/generated_rules'
DEFAULT_RULES_JSON_OUTPUT_PATH = 'outputs/rules.json'

# --- Logging function for consistent output ---
def log(message, level="INFO"):
    """Prints a log message with a specified level."""
    print(f"[{level}] rule_generator.py: {message}", flush=True)

# --- Helper function to ensure a value is a list ---
def ensure_list(item):
    if isinstance(item, list):
        return item
    return [item]

# --- Data Loading (re-used from previous scripts) ---
def load_data(file_path, data_type):
    """
    Loads data from a specified file path, handling JSON and NumPy formats.

    Args:
        file_path (str): The path to the data file.
        data_type (str): 'json' or 'npy' to indicate the file type.

    Returns:
        dict or list or numpy.ndarray: The loaded data.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        json.JSONDecodeError: If JSON file content is invalid.
        Exception: For other unexpected errors.
    """
    log(f"Attempting to load {data_type} data from: {file_path}")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Data file not found at: {file_path}")
    try:
        if data_type == 'json':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        elif data_type == 'npy':
            data = np.load(file_path, allow_pickle=True).item() # .item() to get the dict back
        else:
            raise ValueError(f"Unsupported data_type: {data_type}. Must be 'json' or 'npy'.")
        log(f"Successfully loaded {data_type} data from {file_path}.")
        return data
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        log(f"Error loading {file_path}: {e}", "ERROR")
        raise
    except Exception as e:
        log(f"An unexpected error occurred while loading {file_path}: {e}", "ERROR")
        raise

# --- Helper to get MITRE details ---
def get_mitre_details(mitre_matrix, technique_id):
    """
    Retrieves details for a given MITRE technique or sub-technique ID from the matrix.
    Includes description and URL.

    Args:
        mitre_matrix (list): The loaded MITRE ATT&CK matrix.
        technique_id (str): The ID of the technique (e.g., T1003, T1059.001).

    Returns:
        dict: A dictionary containing 'technique_name', 'tactic', 'data_sources',
              'description', and 'url' for the technique, or None if not found.
    """
    # Assuming mitre_matrix is a list of technique dictionaries
    for tech in mitre_matrix:
        if tech.get('technique_id') == technique_id:
            tactics = tech.get('tactics', [])
            description = tech.get('description', 'No description available for this technique.')
            if description == 'No description available for this technique.':
                log(f"WARNING: No description found in MITRE matrix for technique ID: {technique_id}", "WARNING")
            else:
                log(f"DEBUG: Found description for {technique_id}: {description[:50]}...", "DEBUG") # Log snippet
            return {
                "technique_name": tech.get('technique', 'N/A'),
                "tactic": tactics[0] if tactics else 'N/A', # Take first tactic, or N/A
                "data_sources": tech.get('x_mitre_data_sources', []), # Use x_mitre_data_sources for consistency with STIX
                "description": description,
                "url": tech.get('url', f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/")
            }
        # Check sub-techniques
        for sub_tech in tech.get('sub_techniques', []):
            if sub_tech.get('sub_technique_id') == technique_id:
                parent_tactics = tech.get('tactics', [])
                parent_id_part = sub_tech.get('sub_technique_id').split('.')[0] if '.' in sub_tech.get('sub_technique_id') else sub_tech.get('sub_technique_id')
                sub_id_part = sub_tech.get('sub_technique_id').split('.')[1] if '.' in sub_tech.get('sub_technique_id') else ''
                
                description = sub_tech.get('description', 'No description available for this sub-technique.')
                if description == 'No description available for this sub-technique.':
                    log(f"WARNING: No description found in MITRE matrix for sub-technique ID: {technique_id}", "WARNING")
                else:
                    log(f"DEBUG: Found description for {technique_id}: {description[:50]}...", "DEBUG") # Log snippet

                return {
                    "technique_name": sub_tech.get('technique', 'N/A'),
                    "tactic": parent_tactics[0] if parent_tactics else 'N/A', # Sub-techniques inherit parent tactic
                    "data_sources": sub_tech.get('x_mitre_data_sources', []), # Use x_mitre_data_sources for consistency with STIX
                    "description": description,
                    "url": sub_tech.get('url', f"https://attack.mitre.org/techniques/{parent_id_part}/{sub_id_part}/")
                }
    log(f"WARNING: MITRE details not found for technique ID: {technique_id}", "WARNING")
    return None

# --- Helper to get Tool details ---
def get_tool_details(tools_config, tool_name):
    """
    Retrieves details for a given tool name.

    Args:
        tools_config (list): The loaded tools configuration.
        tool_name (str): The name of the tool.

    Returns:
        dict: A dictionary containing 'data_sources', 'tech_categories', 'fields',
              'supported_techniques', or None if not found.
    """
    for tool in tools_config:
        if tool.get('tool_name') == tool_name:
            return {
                "data_sources": tool.get('data_sources', []),
                "tech_categories": tool.get('tech_categories', []),
                "fields": tool.get('fields', []),
                "supported_techniques": tool.get('supported_techniques', [])
            }
    log(f"WARNING: Tool details not found for tool name: {tool_name}", "WARNING")
    return None

# --- Dynamic Detection Logic Generation ---
def generate_detection_logic(mitre_id, tool_details):
    """
    Generates a more realistic and actionable Sigma detection logic snippet
    as a Python dictionary, which will be converted to YAML by Jinja.

    Args:
        mitre_id (str): The MITRE Technique ID.
        tool_details (dict): Details of the tool, including its 'fields', 'data_sources', 'tech_categories'.

    Returns:
        dict: A dictionary representing the Sigma 'selection' block.
    """
    fields = tool_details.get('fields', [])
    data_sources = [ds.lower() for ds in tool_details.get('data_sources', [])]
    tech_categories = [tc.lower() for tc in tool_details.get('tech_categories', [])]
    
    selection_dict = {}
    
    # Helper to check if any of a set of fields is present
    def has_any_field(field_list):
        return any(f in fields for f in field_list)

    # --- T1003: Credential Dumping ---
    if mitre_id.startswith('T1003'):
        if 'windows event logs' in data_sources or 'endpoint activity logs' in data_sources:
            if has_any_field(['event_id', 'winlog_id']):
                selection_dict['EventID'] = ensure_list([4648, 4624, 4672])
                selection_dict['process_name|contains'] = ensure_list(['lsass.exe', 'mimikatz.exe'])
                selection_dict['ParentProcessName|contains'] = ensure_list(['cmd.exe', 'powershell.exe'])
        elif 'linux servers' in tech_categories or 'system logs' in data_sources:
            if has_any_field(['command', 'process']):
                selection_dict['command|contains'] = ensure_list(['cat /etc/shadow', 'sudo -l', 'gdb -p'])
                selection_dict['process|contains'] = ensure_list('hashdump')
        elif 'privileged sessions' in data_sources or 'credential access' in data_sources: # CyberArk PAM
            if has_any_field(['account', 'target', 'session_start']):
                selection_dict['account|endswith'] = ensure_list('$')
                selection_dict['target|contains'] = ensure_list('domain_controller')
                selection_dict['session_type'] = ensure_list(['RDP', 'SSH'])
                selection_dict['commands|contains'] = ensure_list(['dump', 'hash'])

    # --- T1059: Command and Scripting Interpreter ---
    elif mitre_id.startswith('T1059'):
        if 'windows event logs' in data_sources or 'endpoint activity logs' in data_sources:
            if has_any_field(['process_name', 'cmdline']):
                selection_dict['process_name|contains'] = ensure_list(['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe'])
                selection_dict['cmdline|contains'] = ensure_list([' -enc ', 'IEX (New-Object System.Net.WebClient).DownloadString', 'bitsadmin /transfer', 'certutil -urlcache -f'])
        elif 'linux servers' in tech_categories or 'system logs' in data_sources:
            if has_any_field(['command', 'process']):
                selection_dict['command|contains'] = ensure_list(['wget', 'curl', 'nc ', 'chmod +x', 'sh -i'])
                selection_dict['process|contains'] = ensure_list('bash')
            elif 'playbook executions' in data_sources: # Demisto SOAR, for automation abuse
                if has_any_field(['playbook', 'status']):
                    selection_dict['playbook_name|contains'] = ensure_list('malicious_automation')
                    selection_dict['status'] = ensure_list('failed')
                    selection_dict['user|contains'] = ensure_list(['api_key', 'service_account'])

    # --- T1071: Application Layer Protocol ---
    elif mitre_id.startswith('T1071'):
        if 'web traffic' in data_sources or 'proxy logs' in data_sources:
            if has_any_field(['url', 'http_method', 'user_agent']):
                selection_dict['url|contains'] = ensure_list(['.onion', '.xyz', '.top'])
                selection_dict['http_method'] = ensure_list('POST')
                selection_dict['user_agent|contains'] = ensure_list('curl')
                selection_dict['url|endswith'] = ensure_list(['.exe', '.dll'])
        elif 'network traffic' in data_sources or 'firewall logs' in data_sources:
            if has_any_field(['dest_ip', 'port', 'protocol']):
                selection_dict['dest_port'] = ensure_list(4444)
                selection_dict['protocol'] = ensure_list('TCP')
                selection_dict['bytes_out'] = '> 1000000' # This is a string comparison, not a list
                selection_dict['dest_ip|in'] = ensure_list(['192.0.2.1', '203.0.113.1']) # Example blacklisted IPs
            elif 'dns queries' in data_sources: # Infoblox DNS
                if has_any_field(['query', 'response']):
                    selection_dict['query|endswith'] = ensure_list(['.top', '.xyz'])
                    selection_dict['response'] = ensure_list('NXDOMAIN')
                    selection_dict['query|length'] = '> 60' # String comparison
                    selection_dict['query|contains'] = ensure_list('.dga.com')

    # --- T1078: Valid Accounts ---
    elif mitre_id.startswith('T1078'):
        if 'authentication logs' in data_sources or 'directory service access' in data_sources:
            if has_any_field(['user', 'auth_method', 'ip']):
                selection_dict['EventID'] = ensure_list([4625, 4776])
                selection_dict['user|count'] = '> 10' # String comparison
                selection_dict['time_frame'] = '60s' # String comparison
                selection_dict['ip'] = ensure_list('external_ip_range')
                selection_dict['logon_type'] = ensure_list([10, 3])
        elif 'privileged sessions' in data_sources: # CyberArk PAM
            if has_any_field(['account', 'target']):
                selection_dict['account|contains'] = ensure_list('privileged')
                selection_dict['target|contains'] = ensure_list('critical_server')
                selection_dict['session_status'] = ensure_list('failed')
                selection_dict['attempt_count'] = '> 5' # String comparison
            elif 'cloud app usage' in data_sources: # Netskope, Broadcom CASB
                if has_any_field(['user', 'app', 'action']):
                    selection_dict['app'] = ensure_list('Office 365')
                    selection_dict['action'] = ensure_list('login')
                    selection_dict['user_agent|contains'] = ensure_list('malicious')
                    selection_dict['country_code'] = ensure_list('RU')
                    selection_dict['cloud_service'] = ensure_list(['Azure AD', 'AWS'])

    # --- T1133: External Remote Services ---
    elif mitre_id.startswith('T1133'):
        if 'network traffic' in data_sources or 'firewall logs' in data_sources:
            if has_any_field(['src_ip', 'dest_ip', 'port', 'protocol']):
                selection_dict['dest_port'] = ensure_list([22, 3389, 5985, 5986])
                selection_dict['protocol'] = ensure_list('TCP')
                selection_dict['src_ip'] = ensure_list('external_ip')
                selection_dict['dest_ip'] = ensure_list('internal_server_ip')
            elif 'web traffic' in data_sources: # Proxies, WAFs
                if has_any_field(['url', 'http_method']):
                    selection_dict['url|contains'] = ensure_list('/remote_access_portal')
                    selection_dict['http_method'] = ensure_list('POST')
                    selection_dict['user_agent|contains'] = ensure_list(['python', 'go'])

    # --- T1190: Exploit Public-Facing Application ---
    elif mitre_id.startswith('T1190'):
        if 'web traffic' in data_sources or 'http headers' in data_sources: # WAFs, Web Servers
            if has_any_field(['uri', 'http_method', 'user_agent']):
                selection_dict['uri|contains'] = ensure_list(['../', 'union select', '<script>', 'etc/passwd'])
                selection_dict['http_method'] = ensure_list('POST')
                selection_dict['user_agent|contains'] = ensure_list(['nmap', 'sqlmap'])
            elif 'ips events' in data_sources: # Firepower, McAfee IPS
                if has_any_field(['signature', 'severity']):
                    selection_dict['signature|contains'] = ensure_list(['SQL_Injection', 'XSS_Attack', 'Command_Injection'])
                    selection_dict['severity'] = ensure_list('high')

    # --- T1547: Boot or Logon Autostart Execution ---
    elif mitre_id.startswith('T1547'):
        if 'windows event logs' in data_sources or 'endpoint activity logs' in data_sources:
            if has_any_field(['event_id', 'process_name', 'cmdline']):
                selection_dict['EventID'] = ensure_list([1, 12])
                selection_dict['process_name|contains'] = ensure_list(['reg.exe', 'schtasks.exe'])
                selection_dict['cmdline|contains'] = ensure_list(['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', '/create /tn ', '/sc daily /tr '])
            elif 'linux servers' in tech_categories or 'system logs' in data_sources:
                if has_any_field(['command', 'file_name']):
                    selection_dict['command|contains'] = ensure_list(['crontab -e', 'systemctl enable'])
                    selection_dict['file_name|contains'] = ensure_list('.bashrc')
                    selection_dict['file_path|contains'] = ensure_list('/etc/rc.local')

    # --- T1567: Exfiltration Over Web Service ---
    elif mitre_id.startswith('T1567'):
        if 'web traffic' in data_sources or 'proxy logs' in data_sources or 'ssl inspection' in data_sources:
            if has_any_field(['url', 'bytes', 'action']):
                selection_dict['url|contains'] = ensure_list(['pastebin.com', 'mega.nz', 'drive.google.com'])
                selection_dict['bytes_out'] = '> 5000000' # String comparison
                selection_dict['action'] = ensure_list('upload')
            elif 'data transfers' in data_sources: # DLP
                if has_any_field(['user', 'content_type', 'destination']):
                    selection_dict['content_type'] = ensure_list('confidential_document')
                    selection_dict['destination|contains'] = ensure_list('external_cloud_storage')
                    selection_dict['action'] = ensure_list(['export', 'forward'])

    # --- T1110: Brute Force ---
    elif mitre_id.startswith('T1110'):
        if 'authentication logs' in data_sources or 'directory service access' in data_sources:
            if has_any_field(['user', 'auth_method', 'ip']):
                selection_dict['EventID'] = ensure_list(4625)
                selection_dict['user|count'] = '> 10' # String comparison
                selection_dict['time_frame'] = '60s' # String comparison
                selection_dict['ip'] = ensure_list('external_ip')
            elif 'privileged sessions' in data_sources: # CyberArk PAM
                if has_any_field(['account', 'session_status']):
                    selection_dict['account|contains'] = ensure_list('admin')
                    selection_dict['target|contains'] = ensure_list('critical_server')
                    selection_dict['session_status'] = ensure_list('failed')
                    selection_dict['attempt_count'] = '> 5' # String comparison

    # --- T1213: Data from Information Repositories ---
    elif mitre_id.startswith('T1213'):
        if 'database queries' in data_sources or 'schema changes' in data_sources: # DAM
            if has_any_field(['db_user', 'query', 'target']):
                selection_dict['db_user|contains'] = ensure_list('sysadmin')
                selection_dict['query|contains'] = ensure_list(['SELECT * FROM CreditCardNumbers', 'DROP TABLE Users'])
                selection_dict['target|contains'] = ensure_list('sensitive_database')
                selection_dict['client_ip'] = ensure_list(['unauthorized_ip', 'external_ip'])

    # --- T1114: Email Collection ---
    elif mitre_id.startswith('T1114'):
        if 'audit logs' in data_sources or 'mailbox access' in data_sources: # O365
            if has_any_field(['user', 'operation', 'object']):
                selection_dict['operation'] = ensure_list('MailItemsAccessed')
                selection_dict['user|contains'] = ensure_list('privileged_user')
                selection_dict['object|contains'] = ensure_list('Inbox')
                selection_dict['client_ip'] = ensure_list('unusual_country_ip')
                selection_dict['action'] = ensure_list(['export', 'forward'])

    # --- T1595: Active Scanning ---
    elif mitre_id.startswith('T1595'):
        if 'network traffic' in data_sources or 'vulnerability scans' in data_sources: # Qualys VM, Bitsight ASM
            if has_any_field(['src_ip', 'dest_ip', 'port', 'protocol']):
                selection_dict['dest_port'] = ensure_list([21, 23, 80, 445])
                selection_dict['protocol'] = ensure_list('TCP')
                selection_dict['connection_count'] = '> 50' # String comparison
                selection_dict['time_frame'] = '10s' # String comparison
                selection_dict['signature|contains'] = ensure_list(['portscan', 'vulnerability_scan'])

    # --- T1498: Network Denial of Service ---
    elif mitre_id.startswith('T1498'):
        if 'network traffic' in data_sources or 'anomaly detection' in data_sources: # Arbor DDoS
            if has_any_field(['src_ip', 'dest_ip', 'pps', 'bps']):
                selection_dict['dest_ip'] = ensure_list('target_server_ip')
                selection_dict['pps'] = '> 100000' # String comparison
                selection_dict['bps'] = '> 100000000' # String comparison
                selection_dict['protocol'] = ensure_list(['UDP', 'ICMP'])
                selection_dict['anomaly_type'] = ensure_list(['SYN_Flood', 'UDP_Amplification'])

    # --- Fallback/Generic Logic for other techniques or missing specific fields ---
    if not selection_dict: # If no specific logic was added
        log(f"No specific detection logic defined for {mitre_id} with tool fields: {fields} and data sources: {data_sources}. Using generic fallback.", "WARNING")
        if has_any_field(['process_name', 'command', 'cmdline']):
            selection_dict['process_name|contains'] = ensure_list('suspicious')
            selection_dict['command|contains'] = ensure_list('malicious')
        elif has_any_field(['url', 'dest_ip', 'src_ip']):
            selection_dict['url|contains'] = ensure_list('suspicious_domain')
            selection_dict['dest_ip|in'] = ensure_list(['192.0.2.1', '203.0.113.1']) # Example IPs
        elif has_any_field(['user', 'account']):
            selection_dict['user|contains'] = ensure_list('temp_account')
            selection_dict['account|contains'] = ensure_list('service_account')
        else:
            selection_dict['keywords|contains'] = ensure_list('suspicious_activity')
        # Removed selection_dict['level'] = 'high' as level is a top-level field

    return selection_dict

# --- Main Rule Generation Function ---
def main(mitre_matrix_path=DEFAULT_MITRE_MATRIX_PATH,
         tools_config_path=DEFAULT_TOOLS_CONFIG_PATH,
         tool_mitre_mapping_path=DEFAULT_TOOL_MITRE_MAPPING_PATH,
         rule_template_path=DEFAULT_RULE_TEMPLATE_PATH,
         syntax_templates_dir=DEFAULT_SYNTAX_TEMPLATES_DIR,
         generated_rules_dir=DEFAULT_GENERATED_RULES_DIR,
         rules_json_output_path=DEFAULT_RULES_JSON_OUTPUT_PATH):
    """
    Generates Sigma rules based on tool-to-MITRE mappings and templates.

    Args:
        mitre_matrix_path (str): Path to the MITRE ATT&CK matrix JSON file.
        tools_config_path (str): Path to the tools_config JSON file.
        tool_mitre_mapping_path (str): Path to the tool-MITRE mapping JSON file.
        rule_template_path (str): Path to the base rule template JSON file (13 columns).
        syntax_templates_dir (str): Directory containing Sigma/YARA syntax templates.
        generated_rules_dir (str): Directory to save individual generated Sigma/YARA rules.
        rules_json_output_path (str): Path to save the consolidated rules JSON file.
    """
    log("Starting rule generation process.")

    try:
        # 1. Load all necessary data
        mitre_matrix = load_data(mitre_matrix_path, 'json')
        tools_config = load_data(tools_config_path, 'json')
        tool_mitre_mapping = load_data(tool_mitre_mapping_path, 'json')
        rule_base_template = load_data(rule_template_path, 'json')

        # Set up Jinja2 environment for syntax templates
        jinja_env = Environment(loader=FileSystemLoader(syntax_templates_dir))
        # Set indent to 0 here for to_yaml filter, so Jinja's indent filter can control it
        # Added sort_keys=False for consistent output order
        jinja_env.filters['to_yaml'] = lambda d: yaml.dump(d, default_flow_style=False, indent=0, sort_keys=False)
        sigma_template = jinja_env.get_template('sigma_template.yaml')
        # yara_template = jinja_env.get_template('yara_template.yar') # If you want to generate YARA too

        # Create a set of all MITRE technique IDs (including sub-techniques) for coverage tracking
        all_mitre_ids = set()
        mitre_id_to_details = {} # For quick lookup
        
        # Build a more robust MITRE details map including descriptions and URLs
        # This assumes mitre_matrix is structured with 'technique_id', 'description', 'url' etc.
        for tech in mitre_matrix: # Assuming mitre_matrix is a list like your sample
            tech_id = tech.get('technique_id')
            
            # Get the tactic for the parent technique
            # It looks for 'tactic' (singular string) from your JSON sample
            parent_tactic_value = tech.get('tactic', 'N/A') 
            
            # Get data sources, trying 'x_mitre_data_sources' first, then 'data_sources' from your sample
            parent_data_sources = tech.get('x_mitre_data_sources', tech.get('data_sources', []))

            if tech_id:
                mitre_id_to_details[tech_id] = {
                    'technique_name': tech.get('technique', 'N/A'),
                    'tactic': parent_tactic_value, # Use the correctly retrieved parent tactic
                    'data_sources': parent_data_sources,
                    'description': tech.get('description', 'No description available for this technique.'),
                    'url': tech.get('url', f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/")
                }
            
            # Process sub-techniques, they will inherit the parent_tactic_value
            for sub_tech in tech.get('sub_techniques', []):
                sub_tech_id = sub_tech.get('sub_technique_id')
                if sub_tech_id:
                    parent_id_part = sub_tech_id.split('.')[0] if '.' in sub_tech_id else sub_tech_id
                    sub_id_part = sub_tech_id.split('.')[1] if '.' in sub_tech_id else ''
                    
                    # Get data sources for sub-technique, similar fallback
                    sub_tech_data_sources = sub_tech.get('x_mitre_data_sources', sub_tech.get('data_sources', []))
                    
                    mitre_id_to_details[sub_tech_id] = {
                        'technique_name': sub_tech.get('technique', 'N/A'),
                        'tactic': parent_tactic_value, # Sub-techniques inherit the parent's tactic
                        'data_sources': sub_tech_data_sources,
                        'description': sub_tech.get('description', 'No description available for this sub-technique.'),
                        'url': sub_tech.get('url', f"https://attack.mitre.org/techniques/{parent_id_part}/{sub_id_part}/")
                    }
             # This part for all_mitre_ids can remain as is
            if tech_id: # Ensure tech_id is not None before adding
                all_mitre_ids.add(tech_id)
            for sub_tech in tech.get('sub_techniques', []):
                sub_tech_id = sub_tech.get('sub_technique_id')
                if sub_tech_id: # Ensure sub_tech_id is not None
                    all_mitre_ids.add(sub_tech_id)


        covered_mitre_ids = set()
        all_generated_rules_data = []

        # Ensure output directory exists
        os.makedirs(generated_rules_dir, exist_ok=True)

        log("Generating rules based on tool-MITRE mappings...")
        # Iterate through the technique-centric mapping
        for mitre_id, mapped_tools in tqdm(tool_mitre_mapping.items(), desc="Processing Mapped Techniques"):
            mitre_details = mitre_id_to_details.get(mitre_id)
            
            # --- DEBUG LOGGING ADDED ---
            log(f"DEBUG: Retrieved MITRE details for {mitre_id}: {mitre_details}", "DEBUG")
            # --- END DEBUG LOGGING ---

            if not mitre_details:
                log(f"Skipping unknown MITRE ID found in mapping: {mitre_id}", "WARNING")
                continue

            for mapped_tool in mapped_tools:
                tool_name = mapped_tool['tool_name']
                similarity_score = mapped_tool['score']
                tool_details = get_tool_details(tools_config, tool_name)

                if not tool_details:
                    log(f"Skipping rule generation for unknown tool: {tool_name} mapped to {mitre_id}", "WARNING")
                    continue

                # --- Populate 13 Columns ---
                rule_data = rule_base_template.copy()
                rule_data["Rule Name"] = f"{tool_name} - {mitre_details['technique_name']} ({mitre_id}) Detection"
                rule_data["MITRE Technique ID"] = mitre_id
                rule_data["MITRE Technique"] = mitre_details['technique_name']
                rule_data["MITRE Tactic"] = mitre_details['tactic']
                rule_data["MITRE Description"] = mitre_details['description'] # Populated from mitre_details
                rule_data["Correlation Score"] = round(similarity_score, 4) # Round for readability
                rule_data["Data Sources"] = list(set(mitre_details['data_sources'] + tool_details['data_sources'])) # Combine and deduplicate
                rule_data["Tech Categories"] = tool_details['tech_categories']
                rule_data["Recommended Technologies"] = [tool_name] # For now, just the current tool
                rule_data["Correlation Logic"] = "To be defined by correlation_logic_builder.py"
                rule_data["False Positive Rate"] = 0.0 # Placeholder, to be updated later
                rule_data["FP Reduction"] = "To be defined later" # Placeholder
                rule_data["Synthetic"] = False # These are based on mappings, not fully synthetic

                # --- Generate Detection Logic Dictionary ---
                detection_logic_dict = generate_detection_logic(mitre_id, tool_details)
                
                # --- Prepare context for Jinja2 template for FULL Sigma YAML ---
                # Heuristic for logsource fields
                logsource_product = 'general'
                logsource_category = 'event'
                logsource_service = 'event'

                if tool_details['tech_categories']:
                    # Use the first tech category, lowercased and snake_cased
                    logsource_product = tool_details['tech_categories'][0].lower().replace(' ', '_')
                
                if tool_details['data_sources']:
                    first_data_source = tool_details['data_sources'][0].lower()
                    logsource_service = first_data_source.replace(' ', '_')
                    if 'authentication' in first_data_source:
                        logsource_category = 'authentication'
                    elif 'process' in first_data_source or 'endpoint' in first_data_source:
                        logsource_category = 'process_creation'
                    elif 'network' in first_data_source or 'firewall' in first_data_source or 'proxy' in first_data_source:
                        logsource_category = 'network_connection'
                    elif 'dns' in first_data_source:
                        logsource_category = 'dns_query'
                    elif 'cloud' in first_data_source or 'azure' in first_data_source or 'aws' in first_data_source:
                        logsource_category = 'cloud_audit'
                    elif 'database' in first_data_source:
                        logsource_category = 'database'
                    elif 'email' in first_data_source or 'mailbox' in first_data_source:
                        logsource_category = 'email'
                    else:
                        logsource_category = 'other' # Default for unknown data sources

                # Ensure tags are valid and don't contain 'N/A'
                # Corrected tag format: attack.tXXX or attack.tXXX.YYY
                tags = [f"attack.{mitre_id.lower()}"] 
                if mitre_details['tactic'] and mitre_details['tactic'] != 'N/A':
                    # Corrected tag format: attack.tactic_name
                    tags.append(f"attack.{mitre_details['tactic'].lower().replace(' ', '_')}") 
                
                if rule_data["Synthetic"]:
                    tags.append("synthetic_rule")
                
                # Get fields from tool_details for the 'fields' section
                sigma_fields = tool_details.get('fields', [])

                template_context = {
                    "title": rule_data["Rule Name"],
                    "id": str(uuid.uuid4()), # Generate a unique ID for the Sigma rule
                    "status": "experimental", # Default status
                    "description": mitre_details['description'], # Use MITRE description here
                    "author": "AIMitreGen", # Project name as author
                    "date": datetime.now().strftime("%Y/%m/%d"),
                    "logsource_product": logsource_product,
                    "logsource_service": logsource_service,
                    "logsource_category": logsource_category,
                    "detection_selection_dict": detection_logic_dict, # Pass the dictionary for Jinja2 to render
                    "detection_condition": "selection", # Default condition for single selection
                    "falsepositives": ["Unknown"], # Default false positives
                    "level": "medium", # Default level, will be updated by score_and_fp_estimator.py
                    "tags": tags, # Use refined tags
                    "fields": sigma_fields # Pass fields list to template
                }


                # --- Render and Save Individual Sigma YAML file ---
                sigma_rule_filename = f"sigma_{mitre_id.replace('.', '_')}_{tool_name.replace(' ', '_').replace('/', '_')}.yaml"
                sigma_rule_path = os.path.join(generated_rules_dir, sigma_rule_filename)
                
                full_sigma_yaml_content = sigma_template.render(template_context)
                
                with open(sigma_rule_path, 'w', encoding='utf-8') as f:
                    f.write(full_sigma_yaml_content)
                log(f"Generated Sigma rule: {sigma_rule_filename}")
                # --- DEBUG LOGGING ADDED ---
                log(f"DEBUG: First 10 lines of generated Sigma YAML for {sigma_rule_filename}:\n{os.linesep.join(full_sigma_yaml_content.splitlines()[:10])}", "DEBUG")
                # --- END DEBUG LOGGING ---


                # --- Assign FULL Sigma YAML to Rule Syntax 1 in JSON output ---
                rule_data["Rule Syntax 1"] = full_sigma_yaml_content
                rule_data["Rule Syntax ref"] = f"Generated by AIMitreGen for {tool_name} and {mitre_id}"
                rule_data["Rule Filename"] = sigma_rule_filename # Ensure filename is stored


                all_generated_rules_data.append(rule_data)
                covered_mitre_ids.add(mitre_id)

        # --- Generate Synthetic Rules for Uncovered MITRE Techniques ---
        uncovered_mitre_ids = all_mitre_ids - covered_mitre_ids
        log(f"\nGenerating synthetic rules for {len(uncovered_mitre_ids)} uncovered MITRE techniques...")

        for mitre_id in tqdm(uncovered_mitre_ids, desc="Generating Synthetic Rules"):
            mitre_details = mitre_id_to_details.get(mitre_id)
            # --- DEBUG LOGGING ADDED ---
            log(f"DEBUG: Retrieved MITRE details for synthetic {mitre_id}: {mitre_details}", "DEBUG")
            # --- END DEBUG LOGGING ---
            if not mitre_details:
                log(f"Could not find details for uncovered MITRE ID: {mitre_id}", "WARNING")
                continue

            rule_data = rule_base_template.copy()
            rule_data["Rule Name"] = f"Synthetic Rule for {mitre_id} - {mitre_details['technique_name']}"
            rule_data["MITRE Technique ID"] = mitre_id
            rule_data["MITRE Technique"] = mitre_details['technique_name']
            rule_data["MITRE Tactic"] = mitre_details['tactic']
            rule_data["MITRE Description"] = mitre_details['description'] # Populated from mitre_details
            rule_data["Correlation Score"] = 0.0 # No correlation for synthetic
            rule_data["Data Sources"] = mitre_details['data_sources'] # Use MITRE's suggested data sources
            rule_data["Tech Categories"] = ["general"] # Generic category
            rule_data["Recommended Technologies"] = ["Generic SIEM"]
            rule_data["Correlation Logic"] = "To be defined by correlation_logic_builder.py"
            rule_data["False Positive Rate"] = 0.5 # Higher default FPR for generic synthetic rule
            rule_data["FP Reduction"] = "Requires specific data source analysis"
            rule_data["Synthetic"] = True

            # --- Assign FULL Sigma YAML to Rule Syntax 1 in JSON output ---
            # For synthetic rules, generate a simple detection logic string
            detection_logic_dict_syn = {'keywords|contains': ensure_list(mitre_details['technique_name'].replace(' ', '_').lower())}
            template_context_syn = {
                "title": rule_data["Rule Name"],
                "id": str(uuid.uuid4()),
                "status": "experimental",
                "description": mitre_details['description'],
                "author": "AIMitreGen (Synthetic)",
                "date": datetime.now().strftime("%Y/%m/%d"),
                "logsource_product": "general",
                "logsource_category": "generic",
                "logsource_service": "event",
                "detection_selection_dict": detection_logic_dict_syn,
                "detection_condition": "selection",
                "falsepositives": ["Unknown"],
                "level": "medium",
                "tags": [f"attack.{mitre_id.lower()}", f"attack.{mitre_details['tactic'].lower().replace(' ', '_')}", "synthetic_rule"],
                "fields": []
            }
            # Render the synthetic rule content using the sigma template
            full_sigma_yaml_content_syn = sigma_template.render(template_context_syn)
            rule_data["Rule Syntax 1"] = full_sigma_yaml_content_syn
            rule_data["Rule Syntax ref"] = f"Generated by AIMitreGen (Synthetic) for {mitre_id}"
            
            # --- Add Rule Filename for Validation Script ---
            sigma_rule_filename = f"sigma_{mitre_id.replace('.', '_')}_SYNTHETIC.yaml"
            rule_data["Rule Filename"] = sigma_rule_filename


            all_generated_rules_data.append(rule_data)

            # --- Render and Save Individual Synthetic Sigma YAML file ---
            sigma_rule_path = os.path.join(generated_rules_dir, sigma_rule_filename)
            
            with open(sigma_rule_path, 'w', encoding='utf-8') as f:
                f.write(full_sigma_yaml_content_syn)
            log(f"Generated synthetic Sigma rule: {sigma_rule_filename}")
            # --- DEBUG LOGGING ADDED ---
            log(f"DEBUG: First 10 lines of generated Sigma YAML for {sigma_rule_filename}:\n{os.linesep.join(full_sigma_yaml_content_syn.splitlines()[:10])}", "DEBUG")
            # --- END DEBUG LOGGING ---


        # 5. Save consolidated rules to JSON
        log(f"\nSaving consolidated rules to: {rules_json_output_path}")
        with open(rules_json_output_path, 'w', encoding='utf-8') as f: # Removed flush=True
            json.dump(all_generated_rules_data, f, indent=4)
        log(f"Consolidated {len(all_generated_rules_data)} rules saved successfully.")

        log("Rule generation process completed.")

    except FileNotFoundError as e:
        log(f"Required file not found: {e}", "CRITICAL")
        sys.exit(1)
    except json.JSONDecodeError as e:
        log(f"Invalid JSON format in input file: {e}", "CRITICAL")
        sys.exit(1)
    except Exception as e:
        log(f"An unhandled error occurred during rule generation: {e}", "CRITICAL")
        sys.exit(1)

if __name__ == "__main__":
    # Example usage if run directly:
    # python generators/rule_generator.py \
    #   data/mitre_matrix.json \
    #   data/tools_config.json \
    #   data/tool_mitre_mapping.json \
    #   templates/rule_template.json \
    #   templates/syntax_templates \
    #   outputs/generated_rules \
    #   outputs/rules.json

    if len(sys.argv) == 1: # No arguments, use defaults
        log("No arguments provided. Using default paths for rule generation.", "INFO")
        main()
    elif len(sys.argv) == 8:
        main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])
    else:
        log("Usage: python generators/rule_generator.py " \
            "<mitre_matrix_json_path> <tools_config_json_path> " \
            "<tool_mitre_mapping_json_path> <rule_template_json_path> " \
            "<syntax_templates_dir> <generated_rules_dir> <rules_json_output_path>", "ERROR")
        sys.exit(1)
