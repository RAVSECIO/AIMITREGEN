import json
import os
import sys
from tqdm import tqdm
import glob
import yaml

DEFAULT_RULES_JSON_PATH = 'outputs/rules.json'
GENERATED_RULES_DIR = 'outputs/generated_rules/'

def log(message, level="INFO"):
    print(f"[{level}] validate_rules.py: {message}", flush=True)

# --- Optional libraries ---
SigmaRule = None
SigmaParseError = Exception
try:
    from pysigma.rule import SigmaRule
    from pysigma.exceptions import SigmaParseError
    log("pysigma imported successfully.")
except ImportError:
    log("pysigma not found. Skipping pysigma validation.", "WARNING")

SigmaToolsRule = None
try:
    from sigmatools.sigma import Rule as SigmaToolsRule
    log("sigmatools imported successfully.")
except ImportError:
    log("sigmatools not found. Skipping sigmatools validation.", "WARNING")

def basic_yaml_sigma_validation(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            rule_content = yaml.safe_load(f)

        if not isinstance(rule_content, dict):
            return False, "Invalid YAML structure: top-level content is not a dictionary."

        keys_lower = {k.lower() for k in rule_content}
        required = {'title', 'id', 'detection', 'logsource', 'level'}
        missing = [f for f in required if f.lower() not in keys_lower]
        if missing:
            return False, f"Missing mandatory Sigma fields: {', '.join(missing)}"

        detection_val = rule_content.get('detection') or rule_content.get('Detection')
        if not isinstance(detection_val, dict) or not detection_val:
            return False, "'detection' field must be a non-empty dictionary."

        return True, "Basic YAML validation PASSED"
    except yaml.YAMLError as e:
        return False, f"Invalid YAML: {e}"
    except Exception as e:
        return False, f"Unexpected error during YAML validation: {e}"

def validate_with_pysigma(file_path):
    if SigmaRule is None:
        return None, "Skipped: pysigma not installed"
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        SigmaRule.from_yaml(content)
        return True, "pysigma validation PASSED"
    except SigmaParseError as e:
        return False, f"pysigma parse error: {e}"
    except Exception as e:
        return False, f"pysigma unexpected error: {e}"

def validate_with_sigmatools(file_path):
    if SigmaToolsRule is None:
        return None, "Skipped: sigmatools not installed"
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        SigmaToolsRule(data)
        return True, "sigmatools validation PASSED"
    except yaml.YAMLError as e:
        return False, f"sigmatools YAML error: {e}"
    except Exception as e:
        return False, f"sigmatools validation error: {e}"

def load_data(file_path, file_type):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f) if file_type == 'json' else yaml.safe_load(f)
    except Exception as e:
        log(f"Error loading {file_type} from {file_path}: {e}", "CRITICAL")
        raise

def main(rules_json_path=DEFAULT_RULES_JSON_PATH, generated_rules_dir=GENERATED_RULES_DIR):
    log("Starting validation of Sigma rules")

    use_pysigma = SigmaRule is not None
    use_sigmatools = SigmaToolsRule is not None

    if not use_pysigma and not use_sigmatools:
        log("No advanced validation libraries found. Only basic validation will run.", "WARNING")
    else:
        log(f"Advanced libraries: pysigma={use_pysigma}, sigmatools={use_sigmatools}")

    try:
        rules_data = load_data(rules_json_path, 'json') if os.path.exists(rules_json_path) else []
        rules_map = {rule.get('Rule Filename'): rule for rule in rules_data if rule.get('Rule Filename')}

        sigma_files = glob.glob(os.path.join(generated_rules_dir, '*.yaml'))
        if not sigma_files:
            log(f"No Sigma YAML files in {generated_rules_dir}. Exiting.", "WARNING")
            sys.exit(0)

        validated, failed = 0, 0

        for file_path in tqdm(sigma_files, desc="Validating Sigma Rules"):
            filename = os.path.basename(file_path)
            rule_entry = rules_map.get(filename) or {
                "Rule Filename": filename,
                "Validation Status": "",
                "Validation Errors": []
            }
            rules_map[filename] = rule_entry

            errors = []
            validations = []

            # Run all validations
            val_statuses = []

            status, msg = validate_with_pysigma(file_path)
            if status is False:
                errors.append(msg)
            elif status is True:
                validations.append("pysigma")
            elif status is None:
                log(f"{filename}: {msg}", "WARNING")

            status, msg = validate_with_sigmatools(file_path)
            if status is False:
                errors.append(msg)
            elif status is True:
                validations.append("sigmatools")
            elif status is None:
                log(f"{filename}: {msg}", "WARNING")

            status, msg = basic_yaml_sigma_validation(file_path)
            if status is False:
                errors.append(msg)
            elif status is True:
                validations.append("basic")

            passed = bool(validations)
            rule_entry["Validation Status"] = "Passed" if passed else "Failed"
            rule_entry["Validation Errors"] = errors if errors else ["No validation errors."]
            rule_entry["Validation Engines"] = validations or ["none"]

            if passed:
                validated += 1
            else:
                failed += 1

            if rule_entry not in rules_data:
                rules_data.append(rule_entry)

        # Final summary
        log(f"Validation complete: {len(sigma_files)} files checked — {validated} passed, {failed} failed.")

        with open(rules_json_path, 'w', encoding='utf-8') as f:
            json.dump(rules_data, f, indent=4)

        log(f"Validation results written to {rules_json_path}")

    except Exception as e:
        log(f"Fatal error: {e}", "CRITICAL")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        main()
    elif len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])
    else:
        log("Usage: python validate_rules.py <rules_json_path> <generated_rules_directory>", "ERROR")
        sys.exit(1)
