import os
import sys
import pandas as pd
from extract import extract_features_from_file
import asyncio

async def main():
    # Check if the user has properly provided the paths for both the benign and malicious PDF files
    if len(sys.argv) != 3:
        print("Usage: python3 extract.py <benign_pdf_path> <malicious_pdf_path>")
        sys.exit(1)
    # if one of the paths cannot be read or does not contain at least one PDF file, exit the program
    if not os.path.exists(sys.argv[1]) or not os.path.exists(sys.argv[2]):
        print("One of the paths does not exist.")
        sys.exit(1)
    # Get the list of PDF files in the benign and malicious directories
    benign_files = [f for f in os.listdir(sys.argv[1]) if f.endswith('.pdf')]
    malicious_files = [f for f in os.listdir(sys.argv[2]) if f.endswith('.pdf')]
    # If there are no PDF files in the benign or malicious directories, exit the program
    if len(benign_files) == 0 :
        print("No PDF files in the benign directory.")
        sys.exit(1)
    if len(malicious_files) == 0:
        print("No PDF files in the malicious directory.")
        sys.exit(1)

    features = ["hashed_filename",'pdf_size', 'title_len', 'encryption', 'metadata_size', 'pages', 'header', 'image_count', 'text', 'object_count', 'font_count', 'embedded_files_count', 'embedded_files_average_size', 'stream_keyword_count', 'endstream_keyword_count', 'stream_average_size', 'xref_count', 'obfuscation_count', 'filter_count', 'nestedfilter_object_count', 'stream_object_count', 'javascript_keyword_count', 'js_keyword_count', 'uri_keyword_count', 'action_keyword_count', 'aa_keyword_count', 'openaction_keyword_count', 'launch_keyword_count', 'submitform_keyword_count', 'acroform_keyword_count', 'xfa_keyword_count', 'jbig2decode_keyword_count', 'richmedia_keyword_count', 'trailer_keyword_count', 'xref_keyword_count', 'startxref_keyword_count', 'children_count_average', 'children_count_median', 'children_count_variance', 'leaves_count', 'nodes_count', 'degree_average', 'degree_assortativity', 'average_shortest_path', 'average_clustering_coefficient', 'density', "is_malicious"]
    df = pd.DataFrame(columns=features)
    
    # Extract features from the benign PDF files
    print(f"Extracting features from {len(benign_files)} benign PDF files...")
    for benign_file in benign_files:
        await extract_features_from_file(benign_file, False, df)

    # Extract features from the malicious PDF files
    print(f"Extracting features from {len(malicious_files)} malicious PDF files...")
    for malicious_file in malicious_files:
        await extract_features_from_file(malicious_file, True, df)

    # Save the extracted features to a CSV file
    print(f"Feature extraction completed, saving {len(df)} samples to features.csv")
    df.to_csv('features.csv', index=False)

    print("Feature extraction completed.")

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())