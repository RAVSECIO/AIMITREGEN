import json
import os
import sys
import requests
from tqdm import tqdm

# --- Configuration ---
MITRE_ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OUTPUT_MITRE_MATRIX_PATH = "data/mitre_matrix.json"

# --- Logging function for consistent output ---
def log(message, level="INFO"):
    """Prints a log message with a specified level."""
    print(f"[{level}] update_mitre_matrix.py: {message}")

# --- Data Fetching ---
def fetch_mitre_stix_data(url):
    """
    Fetches the MITRE ATT&CK STIX JSON data from the specified URL.

    Args:
        url (str): The URL of the STIX JSON file.

    Returns:
        dict: The parsed JSON content.

    Raises:
        requests.exceptions.RequestException: If there's an error fetching the data.
        json.JSONDecodeError: If the response content is not valid JSON.
    """
    log(f"Fetching MITRE ATT&CK STIX data from: {url}")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        log("Successfully fetched and parsed MITRE ATT&CK STIX data.")
        return data
    except requests.exceptions.RequestException as e:
        log(f"Error fetching data from {url}: {e}", "CRITICAL")
        raise
    except json.JSONDecodeError as e:
        log(f"Error decoding JSON from response: {e}", "CRITICAL")
        raise
    except Exception as e:
        log(f"An unexpected error occurred during data fetch: {e}", "CRITICAL")
        raise

# --- Data Transformation ---
def transform_stix_to_custom_format(stix_data):
    """
    Transforms the raw STIX data into the custom MITRE matrix format
    expected by the rule generator.
    """
    log("Transforming STIX data to custom MITRE matrix format...")
    transformed_matrix = []
    
    # First pass: Collect all techniques and sub-techniques
    techniques_map = {}
    sub_techniques_map = {}

    for obj in tqdm(stix_data['objects'], desc="Processing STIX Objects"):
        if obj.get('type') == 'attack-pattern' and not obj.get('revoked') and not obj.get('x_mitre_deprecated'):
            external_references = obj.get('external_references', [])
            mitre_id = None
            mitre_url = None
            for ref in external_references:
                if ref.get('source_name') == 'mitre-attack':
                    mitre_id = ref.get('external_id')
                    mitre_url = ref.get('url')
                    break
            
            if not mitre_id:
                continue # Skip if no MITRE ID found

            technique_name = obj.get('name', 'N/A')
            description = obj.get('description', 'No description available for this technique.')
            
            # Debug log for description
            if description != 'No description available for this technique.':
                log(f"DEBUG: Extracted description for {mitre_id}: {description[:50]}...", "DEBUG")

            tactics = []
            for kill_chain_phase in obj.get('kill_chain_phases', []):
                if kill_chain_phase.get('kill_chain_name') == 'mitre-attack':
                    tactics.append(kill_chain_phase.get('phase_name').replace('-', ' ').title()) # Format tactic name

            data_sources = obj.get('x_mitre_data_sources', []) # Use x_mitre_data_sources

            if obj.get('x_mitre_is_subtechnique'):
                sub_techniques_map[mitre_id] = {
                    "sub_technique_id": mitre_id,
                    "technique": technique_name,
                    "data_sources": data_sources,
                    "description": description,
                    "url": mitre_url
                }
            else:
                techniques_map[mitre_id] = {
                    "technique_id": mitre_id,
                    "technique": technique_name,
                    "tactic": tactics, # Keep as list for now, will take first later
                    "data_sources": data_sources,
                    "description": description,
                    "url": mitre_url,
                    "sub_techniques": [] # Initialize sub-techniques list
                }
    
    # Second pass: Link sub-techniques to their parent techniques
    for obj in tqdm(stix_data['objects'], desc="Linking Sub-Techniques"):
        if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'subtechnique-of':
            source_ref = obj.get('source_ref')
            target_ref = obj.get('target_ref')

            source_id = None
            target_id = None

            # Find external_id for source and target
            for ref_obj in stix_data['objects']:
                if ref_obj.get('id') == source_ref and ref_obj.get('type') == 'attack-pattern':
                    for ext_ref in ref_obj.get('external_references', []):
                        if ext_ref.get('source_name') == 'mitre-attack':
                            source_id = ext_ref.get('external_id')
                            break
                if ref_obj.get('id') == target_ref and ref_obj.get('type') == 'attack-pattern':
                    for ext_ref in ref_obj.get('external_references', []):
                        if ext_ref.get('source_name') == 'mitre-attack':
                            target_id = ext_ref.get('external_id')
                            break
            
            if source_id and target_id and source_id in sub_techniques_map and target_id in techniques_map:
                techniques_map[target_id]['sub_techniques'].append(sub_techniques_map[source_id])
            elif source_id and target_id:
                log(f"Warning: Relationship found for {source_id} (sub) -> {target_id} (parent), but one or both not found in maps. Skipping.", "WARNING")

    # Final assembly: Convert tactics list to single string as expected by rule_generator
    for tech_id in sorted(techniques_map.keys()): # Sort by ID for consistent output
        tech_data = techniques_map[tech_id]
        tech_data['tactic'] = tech_data['tactic'][0] if tech_data['tactic'] else 'N/A'
        # Sort sub-techniques by ID for consistent output
        tech_data['sub_techniques'].sort(key=lambda x: x['sub_technique_id'])
        transformed_matrix.append(tech_data)

    log("Transformation complete.")
    return transformed_matrix

# --- Main function for script execution ---
def main():
    """
    Main function to orchestrate the MITRE matrix update process.
    """
    log("Starting MITRE ATT&CK matrix update process.")
    try:
        # 1. Fetch raw STIX data
        stix_data = fetch_mitre_stix_data(MITRE_ATTACK_STIX_URL)

        # 2. Transform data
        transformed_matrix = transform_stix_to_custom_format(stix_data)

        # 3. Save the transformed matrix
        log(f"Saving transformed MITRE matrix to: {OUTPUT_MITRE_MATRIX_PATH}")
        os.makedirs(os.path.dirname(OUTPUT_MITRE_MATRIX_PATH), exist_ok=True)
        with open(OUTPUT_MITRE_MATRIX_PATH, 'w', encoding='utf-8') as f:
            json.dump(transformed_matrix, f, indent=4)
        log("MITRE ATT&CK matrix updated successfully.")

    except (requests.exceptions.RequestException, json.JSONDecodeError, Exception) as e:
        log(f"An error occurred during the MITRE matrix update process: {e}", "CRITICAL")
        sys.exit(1)

if __name__ == "__main__":
    main()
