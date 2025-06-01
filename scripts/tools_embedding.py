import json
import numpy as np
import os
import sys
from sentence_transformers import SentenceTransformer
from tqdm import tqdm # For progress reporting

# --- Configuration ---
MODEL_NAME = 'ibm-research/CTI-BERT'
BATCH_SIZE = 32 # Consistent with mitre_technique_embedding.py

# --- Logging function for consistent output ---
def log(message, level="INFO"):
    """Prints a log message with a specified level."""
    print(f"[{level}] tools_embedding.py: {message}")

# --- Data Loading ---
def load_tools_config(file_path):
    """
    Loads the tools configuration data from a JSON file.

    Args:
        file_path (str): The path to the tools_config.json file.

    Returns:
        list: The loaded tools configuration data.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        json.JSONDecodeError: If the file content is not valid JSON.
        Exception: For other unexpected errors during file loading.
    """
    log(f"Attempting to load tools configuration from: {file_path}")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Tools configuration file not found at: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        log("Successfully loaded tools configuration.")
        return data
    except json.JSONDecodeError as e:
        log(f"Error decoding JSON from {file_path}: {e}", "ERROR")
        raise
    except Exception as e:
        log(f"An unexpected error occurred while loading {file_path}: {e}", "ERROR")
        raise

# --- Text Preparation ---
def prepare_tool_texts(tools_data):
    """
    Prepares a list of descriptive texts for each security tool
    from the loaded tools configuration data. All available fields are used
    to create a rich representation for embedding generation.

    Args:
        tools_data (list): The loaded tools configuration data.

    Returns:
        tuple: A tuple containing:
            - list: A list of prepared text strings.
            - list: A corresponding list of tool names (serving as IDs).
    """
    log("Preparing tool texts for embedding generation using all available fields...")
    texts = []
    ids = []

    for tool in tools_data:
        tool_name = tool.get('tool_name', 'Unknown Tool')
        data_sources = ', '.join(tool.get('data_sources', []))
        tech_categories = ', '.join(tool.get('tech_categories', []))
        # Ensure supported_techniques are handled as a list
        supported_techniques = ', '.join(tool.get('supported_techniques', []))
        fields = ', '.join(tool.get('fields', []))

        # Concatenate all relevant fields into a single descriptive string
        # Handle cases where a field might be empty
        description_parts = []
        if tool_name != 'Unknown Tool':
            description_parts.append(f"Security Tool: {tool_name}.")
        if data_sources:
            description_parts.append(f"Primary Data Sources: {data_sources}.")
        if tech_categories:
            description_parts.append(f"Technology Categories: {tech_categories}.")
        if supported_techniques:
            description_parts.append(f"Known Supported MITRE Techniques: {supported_techniques}.")
        if fields:
            description_parts.append(f"Key Log Fields: {fields}.")

        tool_text = " ".join(description_parts)
        
        # Fallback if somehow all fields are empty for a tool (shouldn't happen with proper config)
        if not tool_text:
            tool_text = f"Generic Security Tool: {tool_name} with no specific details provided."
            log(f"Warning: No descriptive text generated for tool '{tool_name}'. Using fallback.", "WARNING")

        texts.append(tool_text)
        ids.append(tool_name) # Using tool_name as the ID

    log(f"Prepared {len(texts)} texts for embedding.")
    return texts, ids

# --- Embedding Generation (re-used from mitre_technique_embedding.py) ---
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

# --- Saving Embeddings (re-used from mitre_technique_embedding.py) ---
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
def main(tools_config_path, output_embeddings_path):
    """
    Main function to orchestrate the tool embedding generation process.

    Args:
        tools_config_path (str): Path to the tools_config JSON file.
        output_embeddings_path (str): Path to save the generated embeddings (.npy file).
    """
    log("Starting tool embedding generation process.")
    try:
        # 1. Load tools configuration
        tools_data = load_tools_config(tools_config_path)

        # 2. Prepare texts for embedding
        texts, ids = prepare_tool_texts(tools_data)

        # 3. Generate embeddings
        embeddings = generate_embeddings(texts, MODEL_NAME, BATCH_SIZE)

        # 4. Save embeddings
        save_embeddings(embeddings, ids, output_embeddings_path)

        log("Tool embedding generation completed successfully.")

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
    # python scripts/tools_embedding.py data/tools_config.json outputs/tools_embeddings.npy

    if len(sys.argv) != 3:
        log("Usage: python scripts/tools_embedding.py <tools_config_json_path> <output_embeddings_npy_path>", "ERROR")
        sys.exit(1)

    tools_config_file = sys.argv[1]
    output_embeddings_file = sys.argv[2]

    main(tools_config_file, output_embeddings_file)
