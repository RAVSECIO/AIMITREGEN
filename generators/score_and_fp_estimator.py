import json
import os
import sys
from tqdm import tqdm

# --- Configuration ---
DEFAULT_RULES_JSON_PATH = 'outputs/rules.json'

# --- Logging function for consistent output ---
def log(message, level="INFO"):
    """Prints a log message with a specified level."""
    print(f"[{level}] score_and_fp_estimator.py: {message}")

# --- Data Loading (re-used) ---
def load_data(file_path, data_type='json'):
    """
    Loads data from a specified file path.
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

# --- Heuristic Parameters ---
BASE_FPR_GENERIC = 0.2
BASE_FPR_SYNTHETIC = 0.5

# Specificity/Generality impacts for Detection Logic
SPECIFICITY_SCORE_IMPACT = {
    'exact_match': 0.08,  # e.g., field: 'value'
    'event_id': 0.1,      # presence of specific event_id
    'and_condition': 0.05, # each 'AND' operator
    'contains_modifier': -0.05, # each '|contains' operator
    'or_condition': -0.03, # each 'OR' operator
}

# Noise levels for Data Sources / Tech Categories
# These are normalized and canonicalized names from enhance_rules.py
NOISE_IMPACT = {
    'high_noise_sources': ['network traffic logs', 'general web logs', 'proxy logs', 'authentication logs'],
    'low_noise_sources': ['windows event logs', 'endpoint activity logs', 'process activity logs',
                          'cloud audit logs', 'deception logs', 'pam logs', 'dlp logs'],
    'high_noise_impact': 0.1,  # Increases FPR
    'low_noise_impact': -0.05  # Decreases FPR
}

# Correlation Logic Impact
CORRELATION_SCORE_BOOST = 0.15 # flat boost for presence of correlation logic
FPR_REDUCTION_VIA_CORRELATION = 0.2 # flat FPR reduction for presence of correlation logic

# --- Heuristic Calculation Functions ---

def calculate_detection_logic_specificity(detection_logic_str):
    """
    Estimates detection logic specificity based on keywords and operators.
    Returns a score between 0.0 (very generic) and 1.0 (very specific).
    """
    specificity_score = 0.5 # Start neutral

    # Convert to lowercase for easier parsing
    logic_lower = detection_logic_str.lower()

    # Impact of specific keywords/patterns
    if 'event_id:' in logic_lower or 'log_id:' in logic_lower:
        specificity_score += SPECIFICITY_SCORE_IMPACT['event_id']

    # Count operators and modifiers
    specificity_score += logic_lower.count(' and ') * SPECIFICITY_SCORE_IMPACT['and_condition']
    specificity_score += logic_lower.count(' or ') * SPECIFICITY_SCORE_IMPACT['or_condition']
    specificity_score += logic_lower.count('|contains') * SPECIFICITY_SCORE_IMPACT['contains_modifier']
    
    # Heuristic for exact matches (absence of modifiers suggests exact, but also presence of direct key: value)
    # This is a bit tricky with raw string parsing, a simpler approach is to count ':'
    # and assume many are exact, unless followed by '|contains' etc.
    exact_matches = logic_lower.count(':') - logic_lower.count('|') # Rough estimate
    if exact_matches > 0:
        specificity_score += exact_matches * SPECIFICITY_SCORE_IMPACT['exact_match']


    return max(0.0, min(1.0, specificity_score))

def get_data_source_noise_level(data_sources, tech_categories):
    """
    Estimates noise level based on data sources and tech categories.
    Returns a score between 0.0 (low noise) and 1.0 (high noise).
    """
    noise_level = 0.5 # Start neutral

    all_categories_and_sources = [item.lower() for item in data_sources + tech_categories if isinstance(item, str)]

    for item in all_categories_and_sources:
        if item in NOISE_IMPACT['high_noise_sources']:
            noise_level += NOISE_IMPACT['high_noise_impact']
        elif item in NOISE_IMPACT['low_noise_sources']:
            noise_level += NOISE_IMPACT['low_noise_impact']
    
    return max(0.0, min(1.0, noise_level))

def has_meaningful_correlation_logic(correlation_logic_str):
    """
    Checks if the correlation logic string indicates actual multi-tool/sequential correlation.
    """
    if not isinstance(correlation_logic_str, str) or \
       "No specific correlation suggestions" in correlation_logic_str:
        return False
    
    # Check for presence of correlation types
    if "type: same_technique_cross_tool" in correlation_logic_str or \
       "type: sequential_tactic_cross_tool" in correlation_logic_str:
        return True
    return False

# --- Main Scoring and Estimator Function ---
def main(rules_json_path=DEFAULT_RULES_JSON_PATH):
    """
    Estimates False Positive Rates and refines Correlation Scores for generated rules.

    Args:
        rules_json_path (str): Path to the consolidated rules JSON file (input/output).
    """
    log("Starting score and FPR estimation process.")

    try:
        # Load rules
        rules_data = load_data(rules_json_path, 'json')

        log(f"Processing {len(rules_data)} rules for scoring and FPR estimation...")

        for rule in tqdm(rules_data, desc="Estimating Scores and FPR"):
            # Initialize / Base FPR
            is_synthetic = rule.get("Synthetic", False)
            estimated_fpr = BASE_FPR_SYNTHETIC if is_synthetic else BASE_FPR_GENERIC
            refined_correlation_score = rule.get("Correlation Score", 0.0)

            # --- 1. Impact of Detection Logic on FPR ---
            detection_logic = rule.get("Rule Syntax 1", "")
            specificity = calculate_detection_logic_specificity(detection_logic)
            
            # Higher specificity means lower FPR
            estimated_fpr = max(0.0, min(1.0, estimated_fpr - (specificity * 0.15))) # Reduced by up to 0.15 based on specificity

            # --- 2. Impact of Data Sources / Tech Categories on FPR ---
            data_sources = rule.get("Data Sources", [])
            tech_categories = rule.get("Tech Categories", [])
            noise_level = get_data_source_noise_level(data_sources, tech_categories)

            # Higher noise means higher FPR
            estimated_fpr = max(0.0, min(1.0, estimated_fpr + (noise_level * 0.1))) # Increased by up to 0.1 based on noise

            # --- 3. Impact of Correlation Logic on Correlation Score and FPR ---
            correlation_logic_str = rule.get("Correlation Logic", "")
            if has_meaningful_correlation_logic(correlation_logic_str):
                # Boost Correlation Score
                refined_correlation_score = min(1.0, refined_correlation_score + CORRELATION_SCORE_BOOST)
                
                # Significantly reduce FPR due to correlation
                estimated_fpr = max(0.0, min(1.0, estimated_fpr * (1 - FPR_REDUCTION_VIA_CORRELATION))) # Multiplicative reduction

            # Clamp final FPR between 0 and 1
            estimated_fpr = round(max(0.0, min(1.0, estimated_fpr)), 4)
            refined_correlation_score = round(max(0.0, min(1.0, refined_correlation_score)), 4)

            rule["False Positive Rate"] = estimated_fpr
            rule["Correlation Score"] = refined_correlation_score

            # --- 4. Refine FP Reduction ---
            current_fp_reduction = rule.get("FP Reduction", "")
            additional_fp_suggestions = []

            if estimated_fpr > 0.3: # High FPR threshold
                additional_fp_suggestions.append("Consider stronger whitelisting, baselining, or specific tuning of detection parameters.")
            
            if has_meaningful_correlation_logic(correlation_logic_str):
                additional_fp_suggestions.append("Correlation itself significantly reduces false positives by requiring multiple indicators across different data sources or phases of an attack.")
            
            if additional_fp_suggestions:
                if current_fp_reduction and current_fp_reduction != "To be defined later":
                    rule["FP Reduction"] = f"{current_fp_reduction} {' '.join(additional_fp_suggestions)}"
                else:
                    rule["FP Reduction"] = ' '.join(additional_fp_suggestions)
            
            # Ensure "To be defined later" is removed if other suggestions are present
            if rule["FP Reduction"] == "To be defined later" and additional_fp_suggestions:
                 rule["FP Reduction"] = ' '.join(additional_fp_suggestions)
            elif rule["FP Reduction"] == "To be defined later" and not additional_fp_suggestions:
                 pass # Keep as is if no new suggestions are added.


        # Save the updated rules
        log(f"Saving rules with estimated scores and FPR to: {rules_json_path}")
        with open(rules_json_path, 'w', encoding='utf-8') as f:
            json.dump(rules_data, f, indent=4)
        log("Score and FPR estimation process completed successfully.")

    except FileNotFoundError as e:
        log(f"Required file not found: {e}", "CRITICAL")
        sys.exit(1)
    except json.JSONDecodeError as e:
        log(f"Invalid JSON format in input file: {e}", "CRITICAL")
        sys.exit(1)
    except Exception as e:
        log(f"An unhandled error occurred during score and FPR estimation: {e}", "CRITICAL")
        sys.exit(1)

if __name__ == "__main__":
    # Example usage if run directly:
    # python generators/score_and_fp_estimator.py outputs/rules.json

    if len(sys.argv) == 1: # No arguments, use defaults
        log("No arguments provided. Using default paths for score and FPR estimation.", "INFO")
        main()
    elif len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        log("Usage: python generators/score_and_fp_estimator.py <rules_json_path>", "ERROR")
        sys.exit(1)
