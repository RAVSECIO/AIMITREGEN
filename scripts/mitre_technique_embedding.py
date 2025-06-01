import json
import numpy as np
import os
import sys
from sentence_transformers import SentenceTransformer
from tqdm import tqdm # For progress reporting

# --- Configuration ---
MODEL_NAME = 'ibm-research/CTI-BERT' # Or 'all-MiniLM-L6-v2', 'all-mpnet-base-v2' etc.
BATCH_SIZE = 32 # Adjust based on your system's memory

# --- Logging function for consistent output ---
def log(message, level="INFO"):
    """Prints a log message with a specified level."""
    print(f"[{level}] mitre_technique_embedding.py: {message}")

# --- Data Loading ---
def load_mitre_matrix(file_path):
    """
    Loads the MITRE ATT&CK matrix data from a JSON file.

    Args:
        file_path (str): The path to the mitre_matrix.json file.

    Returns:
        list: The loaded MITRE ATT&CK data.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        json.JSONDecodeError: If the file content is not valid JSON.
        Exception: For other unexpected errors during file loading.
    """
    log(f"Attempting to load MITRE matrix from: {file_path}")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"MITRE matrix file not found at: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        log("Successfully loaded MITRE matrix.")
        return data
    except json.JSONDecodeError as e:
        log(f"Error decoding JSON from {file_path}: {e}", "ERROR")
        raise
    except Exception as e:
        log(f"An unexpected error occurred while loading {file_path}: {e}", "ERROR")
        raise

# --- Text Preparation ---
def prepare_mitre_texts(mitre_data):
    """
    Prepares a list of descriptive texts for each MITRE ATT&CK technique
    and sub-technique, along with their IDs.

    Args:
        mitre_data (list): The loaded MITRE ATT&CK matrix data.

    Returns:
        tuple: A tuple containing:
            - list: A list of prepared text strings (description + name).
            - list: A corresponding list of MITRE IDs.
    """
    log("Preparing MITRE technique texts for embedding generation...")
    texts = []
    ids = []

    for technique in mitre_data:
        # Process main techniques
        tech_id = technique.get('technique_id')
        tech_name = technique.get('technique', 'N/A')
        tech_description = technique.get('description', '')
        
        if tech_id:
            texts.append(f"{tech_name}. {tech_description}".strip())
            ids.append(tech_id)

        # Process sub-techniques
        for sub_technique in technique.get('sub_techniques', []):
            sub_tech_id = sub_technique.get('sub_technique_id')
            sub_tech_name = sub_technique.get('technique', 'N/A')
            sub_tech_description = sub_technique.get('description', '')

            if sub_tech_id:
                texts.append(f"{sub_tech_name}. {sub_tech_description}".strip())
                ids.append(sub_tech_id)
    
    log(f"Prepared {len(texts)} MITRE technique texts for embedding.")
    return texts, ids

# --- Embedding Generation ---
def generate_embeddings(texts, model_name, batch_size):
    """
    Generates embeddings for a list of texts using the specified SentenceTransformer model.

    Args:
        texts (list): A list of text strings to embed.
        model_name (str): The name of the SentenceTransformer model to use.
        batch_size (int): The number of texts to process in each batch.

    Returns:
        numpy.ndarray: A 2D numpy array where each row is an embedding vector.

    Raises:
        Exception: If there's an error loading the model or encoding texts.
    """
    log(f"Loading SentenceTransformer model: {model_name}")
    try:
        model = SentenceTransformer(model_name)
        log("Model loaded successfully. Generating embeddings...")
        # Use tqdm for progress bar
        embeddings = model.encode(texts,
                                  batch_size=batch_size,
                                  show_progress_bar=True,
                                  convert_to_numpy=True)
        log("Embeddings generated.")
        return embeddings
    except Exception as e:
        log(f"Error during embedding generation: {e}", "ERROR")
        log("Ensure you have an active internet connection to download the model if it's not cached.", "ERROR")
        log("Also, check if your system has enough memory for the model and batch size.", "ERROR")
        raise

# --- Saving Embeddings ---
def save_embeddings(embeddings, ids, output_path):
    """
    Saves the generated embeddings and their corresponding IDs to a .npy file.
    The .npy file will store a dictionary containing 'ids' and 'embeddings'.

    Args:
        embeddings (numpy.ndarray): The 2D numpy array of embeddings.
        ids (list): The list of corresponding IDs.
        output_path (str): The path where the .npy file will be saved.
    """
    log(f"Saving embeddings to: {output_path}")
    try:
        # Create the output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        np.save(output_path, {'ids': ids, 'embeddings': embeddings})
        log("Embeddings saved successfully.")
    except Exception as e:
        log(f"Error saving embeddings to {output_path}: {e}", "ERROR")
        raise

# --- Main function for script execution ---
def main(mitre_matrix_path, output_embeddings_path):
    """
    Main function to orchestrate the MITRE technique embedding generation process.

    Args:
        mitre_matrix_path (str): Path to the mitre_matrix.json file.
        output_embeddings_path (str): Path to save the generated embeddings (.npy file).
    """
    log("Starting MITRE technique embedding generation process.")
    try:
        # 1. Load MITRE matrix
        mitre_data = load_mitre_matrix(mitre_matrix_path)

        # 2. Prepare texts for embedding
        texts, ids = prepare_mitre_texts(mitre_data)

        # 3. Generate embeddings
        embeddings = generate_embeddings(texts, MODEL_NAME, BATCH_SIZE)

        # 4. Save embeddings
        save_embeddings(embeddings, ids, output_embeddings_path)

        log("MITRE technique embedding generation completed successfully.")

    except FileNotFoundError as e:
        log(f"Required file not found: {e}", "CRITICAL")
        sys.exit(1)
    except json.JSONDecodeError as e:
        log(f"Invalid JSON format in input file: {e}", "CRITICAL")
        sys.exit(1)
    except Exception as e:
        log(f"An unhandled error occurred during the embedding process: {e}", "CRITICAL")
        sys.exit(1)

if __name__ == "__main__":
    # This block allows the script to be run directly for testing,
    # but it's primarily designed to be called by main.py with arguments.
    # Example usage if run directly:
    # python scripts/mitre_technique_embedding.py data/mitre_matrix.json outputs/mitre_technique_embeddings.npy

    if len(sys.argv) != 3:
        log("Usage: python scripts/mitre_technique_embedding.py <mitre_matrix_json_path> <output_embeddings_npy_path>", "ERROR")
        sys.exit(1)

    mitre_matrix_file = sys.argv[1]
    output_embeddings_file = sys.argv[2]

    main(mitre_matrix_file, output_embeddings_file)
