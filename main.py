import os
import sys
import json
import subprocess # To run other Python scripts as subprocesses

# Add project root to sys.path to allow imports from scripts/ and generators/
# Assumes main.py is in the project root
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'generators'))

# --- Configuration ---
DATA_DIR = 'data'
OUTPUTS_DIR = 'outputs'
TEMPLATES_DIR = 'templates'
GENERATORS_DIR = 'generators'
SCRIPTS_DIR = 'scripts'

MITRE_MATRIX_PATH = os.path.join(DATA_DIR, 'mitre_matrix.json')
TOOLS_CONFIG_PATH = os.path.join(DATA_DIR, 'tools_config.json')
TOOL_MITRE_MAPPING_PATH = os.path.join(DATA_DIR, 'tool_mitre_mapping.json') # Intermediate/Optional mapping

MITRE_EMBEDDINGS_PATH = os.path.join(OUTPUTS_DIR, 'mitre_technique_embeddings.npy')
TOOLS_EMBEDDINGS_PATH = os.path.join(OUTPUTS_DIR, 'tools_embeddings.npy')

RULES_JSON_OUTPUT_PATH = os.path.join(OUTPUTS_DIR, 'rules.json')
RULES_XLSX_OUTPUT_PATH = os.path.join(OUTPUTS_DIR, 'rules.xlsx')
GENERATED_SIGMA_RULES_DIR = os.path.join(OUTPUTS_DIR, 'generated_rules') # For individual .yaml files

def log(message, level="INFO"):
    """Prints a log message with a specified level."""
    print(f"[{level}] main.py: {message}", flush=True)

def run_script(script_path, *args):
    """
    Runs a Python script as a subprocess.

    Args:
        script_path (str): The path to the Python script to run.
        *args: Any command-line arguments to pass to the script.

    Returns:
        bool: True if the script ran successfully, False otherwise.
    """
    log(f"Running script: {script_path} {' '.join(args)}...")
    try:
        # Use sys.executable to ensure the correct Python interpreter (from venv) is used
        command = [sys.executable, script_path] + list(args)
        
        # Capture output for better debugging if needed, but for now, let it stream
        # For enterprise, consider capturing stdout/stderr to a log file
        process = subprocess.run(command, check=True, capture_output=False, text=True)
        log(f"Script '{script_path}' completed successfully.")
        return True
    except subprocess.CalledProcessError as e:
        log(f"Script '{script_path}' failed with exit code {e.returncode}.", "ERROR")
        log(f"Command: {' '.join(e.cmd)}", "ERROR")
        log(f"Stdout: {e.stdout}", "ERROR")
        log(f"Stderr: {e.stderr}", "ERROR")
        return False
    except FileNotFoundError:
        log(f"Error: Script '{script_path}' not found. Check path.", "ERROR")
        return False
    except Exception as e:
        log(f"An unexpected error occurred while running '{script_path}': {e}", "ERROR")
        return False

def main():
    log("Starting MITRE ATT&CK Sigma Rule Generator pipeline...")

    # --- Phase 1: Data Preparation & Embedding Generation ---
    log("\n--- Phase 1: Data Preparation & Embedding Generation ---")

    # 1. Build/Update MITRE Matrix (If you have a script for this, uncomment and run)
    # If your mitre_matrix.json is manually maintained, this step is skipped.
    # if not run_script(os.path.join(SCRIPTS_DIR, 'build_mitre_matrix.py'), MITRE_MATRIX_PATH): return

    # 2. Generate MITRE Technique Embeddings
    if not run_script(os.path.join(SCRIPTS_DIR, 'mitre_technique_embedding.py'), MITRE_MATRIX_PATH, MITRE_EMBEDDINGS_PATH): return

    # 3. Generate Tool Embeddings
    if not run_script(os.path.join(SCRIPTS_DIR, 'tools_embedding.py'), TOOLS_CONFIG_PATH, TOOLS_EMBEDDINGS_PATH): return

    # --- Phase 2: Tool-to-MITRE Mapping ---
    log("\n--- Phase 2: Tool-to-MITRE Mapping ---")

    # This script performs the semantic similarity mapping between tools and techniques.
    if not run_script(os.path.join(SCRIPTS_DIR, 'map_tools_to_mitre.py'),
                      MITRE_EMBEDDINGS_PATH,
                      TOOLS_EMBEDDINGS_PATH,
                      MITRE_MATRIX_PATH,
                      TOOLS_CONFIG_PATH,
                      TOOL_MITRE_MAPPING_PATH,
                      "0.7"): # Pass the threshold as a string argument
        return

    # --- Phase 3: Rule Generation ---
    log("\n--- Phase 3: Rule Generation ---")

    # This is the core rule generation.
    if not run_script(os.path.join(GENERATORS_DIR, 'rule_generator.py'),
                      MITRE_MATRIX_PATH,
                      TOOLS_CONFIG_PATH,
                      TOOL_MITRE_MAPPING_PATH,
                      os.path.join(TEMPLATES_DIR, 'rule_template.json'),
                      os.path.join(TEMPLATES_DIR, 'syntax_templates'),
                      GENERATED_SIGMA_RULES_DIR,
                      RULES_JSON_OUTPUT_PATH):
        return

    # --- Phase 4: Rule Enhancement, Correlation, Scoring, and Validation ---
    log("\n--- Phase 4: Rule Enhancement, Correlation, Scoring, and Validation ---")

    # Enhance rules (e.g., add more metadata, normalize fields)
    if not run_script(os.path.join(SCRIPTS_DIR, 'enhance_rules.py'), RULES_JSON_OUTPUT_PATH, MITRE_MATRIX_PATH): return

    # Build correlation logic
    if not run_script(os.path.join(GENERATORS_DIR, 'correlation_logic_builder.py'), RULES_JSON_OUTPUT_PATH, TOOLS_CONFIG_PATH): return

    # Estimate score and false positives
    if not run_script(os.path.join(GENERATORS_DIR, 'score_and_fp_estimator.py'), RULES_JSON_OUTPUT_PATH): return

    # Validate generated Sigma/YARA rules
    # Note: This script will still warn if pysigma/sigmatools are not found, but will use basic YAML validation.
    if not run_script('validate_rules.py', RULES_JSON_OUTPUT_PATH, GENERATED_SIGMA_RULES_DIR): return

    # --- Phase 5: Final Export ---
    log("\n--- Phase 5: Final Export ---")

    # Export to Excel
    if not run_script(os.path.join(SCRIPTS_DIR, 'export_rules_to_excel.py'), RULES_JSON_OUTPUT_PATH, RULES_XLSX_OUTPUT_PATH): return

    # --- Phase 6: Visualization (Optional) ---
    log("\n--- Phase 6: Visualization (Optional) ---")
    # If you implement a script for heatmap generation, uncomment and run it here.
    # Example: if not run_script(os.path.join(SCRIPTS_DIR, 'generate_heatmap.py'), RULES_JSON_OUTPUT_PATH, os.2.join(OUTPUTS_DIR, 'heatmap')): return

    log("\nPipeline finished successfully!")

if __name__ == "__main__":
    main()
