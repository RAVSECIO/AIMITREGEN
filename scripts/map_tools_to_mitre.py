import json
import numpy as np
import os
import sys
from sklearn.metrics.pairwise import cosine_similarity
from tqdm import tqdm

# --- Configuration ---
SIMILARITY_THRESHOLD = 0.7 # Starting threshold, can be tuned

# --- Logging function for consistent output ---
def log(message, level="INFO"):
    """Prints a log message with a specified level."""
    print(f"[{level}] map_tools_to_mitre.py: {message}")

# --- Data Loading ---
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

# --- Main function for script execution ---
def main(mitre_embeddings_path, tools_embeddings_path, mitre_matrix_path, tools_config_path, output_mapping_path, threshold=SIMILARITY_THRESHOLD):
    """
    Maps tools to MITRE ATT&CK techniques based on semantic similarity of their embeddings.

    Args:
        mitre_embeddings_path (str): Path to the MITRE technique embeddings .npy file.
        tools_embeddings_path (str): Path to the tool embeddings .npy file.
        mitre_matrix_path (str): Path to the MITRE ATT&CK matrix JSON file (for technique details).
        tools_config_path (str): Path to the tools_config JSON file (for tool details).
        output_mapping_path (str): Path to save the generated tool-MITRE mapping JSON file.
        threshold (float, optional): Cosine similarity threshold for a match to be considered relevant.
                                     Defaults to SIMILARITY_THRESHOLD.
    """
    log("Starting tool-to-MITRE mapping process.")

    try:
        # 1. Load Embeddings
        mitre_embeddings_data = load_data(mitre_embeddings_path, 'npy')
        mitre_ids = mitre_embeddings_data['ids']
        mitre_vectors = mitre_embeddings_data['embeddings']

        tools_embeddings_data = load_data(tools_embeddings_path, 'npy')
        tool_names = tools_embeddings_data['ids']
        tool_vectors = tools_embeddings_data['embeddings']

        # 2. Load MITRE Matrix (optional, but good for richer output if needed)
        mitre_matrix = load_data(mitre_matrix_path, 'json')
        # Create a quick lookup for technique details if needed later
        # For this script, we only use IDs from embeddings for mapping
        # and enrich using mitre_matrix if we wanted technique names in output.
        # As per user's request, output is just technique_id and score.

        # 3. Perform Cosine Similarity Calculation
        log(f"Calculating cosine similarities with threshold: {threshold}")
        
        # Initialize the technique-centric mapping dictionary
        technique_to_tools_mapping = {}

        # Iterate through each MITRE technique embedding
        for i, mitre_id in tqdm(enumerate(mitre_ids), total=len(mitre_ids), desc="Mapping Tools to MITRE Techniques"):
            mitre_vector = mitre_vectors[i].reshape(1, -1) # Reshape for cosine_similarity

            # Calculate similarity between this MITRE technique and all tools
            # Note: cosine_similarity expects 2D arrays (n_samples, n_features)
            # The result will be a 1xM array where M is the number of tools
            similarities = cosine_similarity(mitre_vector, tool_vectors)[0] # Get the first (and only) row

            relevant_tools_for_technique = []
            for j, tool_name in enumerate(tool_names):
                score = similarities[j]
                if score >= threshold:
                    relevant_tools_for_technique.append({"tool_name": tool_name, "score": float(score)}) # Convert numpy float to native float

            if relevant_tools_for_technique:
                # Sort tools by score in descending order
                relevant_tools_for_technique.sort(key=lambda x: x['score'], reverse=True)
                technique_to_tools_mapping[mitre_id] = relevant_tools_for_technique

        log(f"Found {len(technique_to_tools_mapping)} MITRE techniques with relevant tool mappings.")

        # 4. Save the mapping
        log(f"Saving technique-centric mapping to: {output_mapping_path}")
        os.makedirs(os.path.dirname(output_mapping_path), exist_ok=True)
        with open(output_mapping_path, 'w', encoding='utf-8') as f:
            json.dump(technique_to_tools_mapping, f, indent=4)
        log("Tool-to-MITRE mapping saved successfully.")

    except (FileNotFoundError, ValueError, KeyError) as e:
        log(f"Data processing error: {e}", "CRITICAL")
        sys.exit(1)
    except Exception as e:
        log(f"An unhandled error occurred during the mapping process: {e}", "CRITICAL")
        sys.exit(1)

if __name__ == "__main__":
    # Example usage if run directly:
    # python scripts/map_tools_to_mitre.py \
    #   outputs/mitre_technique_embeddings.npy \
    #   outputs/tools_embeddings.npy \
    #   data/mitre_matrix.json \
    #   data/tools_config.json \
    #   data/tool_mitre_mapping.json \
    #   [optional_threshold]

    if len(sys.argv) < 6 or len(sys.argv) > 7:
        log("Usage: python scripts/map_tools_to_mitre.py " \
            "<mitre_embeddings_npy_path> <tools_embeddings_npy_path> " \
            "<mitre_matrix_json_path> <tools_config_json_path> " \
            "<output_mapping_json_path> [optional_threshold]", "ERROR")
        sys.exit(1)

    mitre_emb_path = sys.argv[1]
    tools_emb_path = sys.argv[2]
    mitre_mat_path = sys.argv[3]
    tools_cfg_path = sys.argv[4]
    output_map_path = sys.argv[5]
    custom_threshold = float(sys.argv[6]) if len(sys.argv) == 7 else SIMILARITY_THRESHOLD

    main(mitre_emb_path, tools_emb_path, mitre_mat_path, tools_cfg_path, output_map_path, custom_threshold)

