import json
import os
import sys
import pandas as pd # Import pandas

# --- Configuration ---
DEFAULT_RULES_JSON_PATH = 'outputs/rules.json'
DEFAULT_EXCEL_OUTPUT_PATH = 'outputs/rules.xlsx'

# --- Logging function for consistent output ---
def log(message, level="INFO"):
    """Prints a log message with a specified level."""
    print(f"[{level}] export_rules_to_excel.py: {message}", flush=True)

# --- Data Loading (re-used for consistency) ---
def load_json_data(file_path):
    """Loads JSON data from a file."""
    log(f"Attempting to load JSON data from: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        log(f"Successfully loaded JSON data from {file_path}.")
        return data
    except FileNotFoundError:
        log(f"Error: The file '{file_path}' was not found.", "CRITICAL")
        raise
    except json.JSONDecodeError as e:
        log(f"Error: Could not decode JSON from '{file_path}': {e}", "CRITICAL")
        raise
    except Exception as e:
        log(f"An unexpected error occurred while loading JSON from '{file_path}': {e}", "CRITICAL")
        raise

# --- Main Export Function ---
def main(rules_json_path=DEFAULT_RULES_JSON_PATH, excel_output_path=DEFAULT_EXCEL_OUTPUT_PATH):
    """
    Loads rules from a JSON file and exports them to an Excel (.xlsx) file.

    Args:
        rules_json_path (str): Path to the consolidated rules JSON file.
        excel_output_path (str): Path where the Excel file will be saved.
    """
    log("Starting Excel export process.")

    try:
        # Load the consolidated rules data
        rules_data = load_json_data(rules_json_path)
        
        if not rules_data:
            log("No rules found in the JSON file. Skipping Excel export.", "WARNING")
            sys.exit(0)

        # Convert the list of dictionaries to a pandas DataFrame
        df = pd.DataFrame(rules_data)

        # Define a desired column order (optional, but makes Excel more readable)
        # You can customize this order based on your preference
        desired_columns = [
            "Rule Name",
            "Rule Syntax 1",
            "Rule Syntax ref",
            "Rule Filename", # Include the filename for easy reference
            "MITRE Technique ID",
            "MITRE Technique",
            "MITRE Tactic",
            "Data Sources",
            "Tech Categories",
            "Recommended Technologies",
            "Correlation Score",
            "Correlation Logic",
            "False Positive Rate",
            "FP Reduction",
            "Synthetic",
            "Validation Status", # New column from validation
            "Validation Errors", # New column from validation
            "MITRE Description", # Make sure these are last if they are long
            "MITRE URL"
        ]
        
        # Reorder columns, adding any new ones at the end if not in desired_columns
        # And handling columns that might not exist in every entry
        actual_columns = [col for col in desired_columns if col in df.columns]
        # Add any columns from DataFrame that were not in desired_columns
        actual_columns.extend([col for col in df.columns if col not in desired_columns])
        
        df = df[actual_columns]

        # Save the DataFrame to an Excel file
        df.to_excel(excel_output_path, index=False, engine='openpyxl') # index=False prevents pandas from writing row numbers

        log(f"Successfully exported {len(rules_data)} rules to '{excel_output_path}'.")
        log("Excel export process completed successfully.")

    except FileNotFoundError as e:
        log(f"Required file not found: {e}", "CRITICAL")
        sys.exit(1)
    except Exception as e:
        log(f"An unhandled error occurred during Excel export: {e}", "CRITICAL")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        log("No arguments provided. Using default paths for Excel export.", "INFO")
        main()
    elif len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])
    else:
        log("Usage: python scripts/export_rules_to_excel.py <rules_json_path> <excel_output_path>", "ERROR")
        sys.exit(1)
