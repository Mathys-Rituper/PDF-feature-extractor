import asyncio
import concurrent.futures
from extract import extract_features_from_file
from lib.threaded_dataframe import Threaded_dataframe
import logging
import os
import sys

import pandas as pd

def extract_then_add(pdf_path, is_malicious, dest_df):
    features = extract_features_from_file(pdf_path, is_malicious)
    features['is_malicious'] = is_malicious
    dest_df.add_entry(features)
    #logging.info(f"Number of samples: {len(dest_df)}")

def main():
    logging.basicConfig(level=logging.INFO)
    # Check if the user has properly provided the paths for both the benign and malicious PDF files
    if len(sys.argv) != 3:
        print("Usage: python3 extract.py <benign_pdf_path> <malicious_pdf_path>")
        sys.exit(1)
    # if one of the paths cannot be read or does not contain at least one PDF file, exit the program
    if (not os.path.exists(sys.argv[1]) or not os.path.exists(sys.argv[2]) or
       not os.path.isdir(sys.argv[1]) or not os.path.isdir(sys.argv[2])):
        print("One of the paths does not exist.")
        sys.exit(1)
    # Get the list of PDF files in the benign and malicious directories
    benign_files = [os.path.join(sys.argv[1], f) for f in os.listdir(sys.argv[1])
                                                    if f.endswith('.pdf')]
    malicious_files = [os.path.join(sys.argv[2], f) for f in os.listdir(sys.argv[2])
                                                    if f.endswith('.pdf')]

    # If there are no PDF files in the benign or malicious directories, warn user
    if len(benign_files) == 0 :
        print("Warning : No PDF files in the benign directory.")
    if len(malicious_files) == 0:
        print("Warning : No PDF files in the malicious directory.")

    features = ['hashed_file','pdf_size', 'title_len', 'encryption', 'metadata_size', 'pages', 'header', 'image_count', 'text', 'object_count', 'font_count', 'embedded_files_count', 'embedded_files_average_size', 'stream_keyword_count', 'endstream_keyword_count', 'stream_average_size', 'xref_count', 'obfuscation_count', 'filter_count', 'nestedfilter_object_count', 'stream_object_count', 'javascript_keyword_count', 'js_keyword_count', 'uri_keyword_count', 'action_keyword_count', 'aa_keyword_count', 'openaction_keyword_count', 'launch_keyword_count', 'submitform_keyword_count', 'acroform_keyword_count', 'xfa_keyword_count', 'jbig2decode_keyword_count', 'richmedia_keyword_count', 'trailer_keyword_count', 'xref_keyword_count', 'startxref_keyword_count', 'children_count_average', 'children_count_median', 'children_count_variance', 'leaves_count', 'nodes_count', 'degree_average', 'degree_assortativity', 'average_shortest_path', 'average_clustering_coefficient', 'density', "is_malicious"]
    df = Threaded_dataframe(features)

    files_iterator = [(file, True, df) for file in malicious_files] + [(file, False, df) for file in benign_files]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        for arg in files_iterator:
            executor.submit(extract_then_add, arg[0], arg[1], arg[2])

    # Save the extracted features to a CSV file
    print(f"Feature extraction completed, saving {len(df)} samples to features.csv")
    df.to_csv('features.csv', index=False)

    print("Feature extraction completed.")

if __name__ == "__main__":
    main()