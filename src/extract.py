import hashlib
import logging
import os
import sys
import threading

import pandas as pd
import pdfid
import pymupdf

from lib.pdf_genome import PdfGenome
import networkx as nx
import numpy as np

class Threaded_dataframe:
    def __init__(self, features: list[str]):
        self.dataframe = pd.DataFrame(columns=features)
        self._lock = threading.Lock()
        self.values = []

    def add_entry(self, entry):
        with self._lock:
            try:
                self.values.append(entry)
            except Exception as e:
                logging.exception(f"Could not write entry to dataframe" )

    def __len__(self):
        if len(self.dataframe) != len(self.values):
            self.dataframe = pd.DataFrame.from_records(self.values)
        return len(self.dataframe)

    def to_csv(self, features, index):
        self.dataframe = pd.DataFrame.from_records(self.values)
        return self.dataframe.to_csv(features, index=index)

def hash_file_sha256(filename: str):
    """ Returns the SHA256 hash of a file """
    with open(filename,"rb") as f:
        bytes = f.read()
        return hashlib.sha256(bytes).hexdigest()

def extract_features_from_file(pdf_path : str, is_malicious : bool,
                                     destination : Threaded_dataframe):
    features = {}
    features['is_malicious'] = is_malicious
    try:
        pymupdf_file = pymupdf.open(pdf_path)
        #logging.info(f"Processing {pdf_path}")
    except pymupdf.FileDataError:
        logging.exception(f"Exception while opening: {pdf_path}")
    else:
        features['pdf_size'] = round(os.path.getsize(pdf_path) / 1024, 2)
        features['hashed_file'] = hash_file_sha256(pdf_path)
        features['title_len'] = len(os.path.basename(pdf_path))
        try:
            features['encryption'] = pymupdf_file.needs_pass or pymupdf_file.metadata["encryption"] is not None
        except TypeError:
            logging.exception(f"encryption check error for {pdf_path}")
    
        features['metadata_size'] = 0
        if isinstance(pymupdf_file.metadata, dict):
            for key in pymupdf_file.metadata:
                features['metadata_size'] += len(key.encode("utf8")) + (len(pymupdf_file.metadata[key].encode("utf8")) if isinstance(pymupdf_file.metadata[key], str) else 0)

        features['pages'] = len(pymupdf_file)
        features['header'] = 0 # TODO Censé être fait avec pdfid mais il n'y a pas de documentation sur comment faire

        features['image_count'] = 0
        features['text'] = 0
        features['object_count'] = 0
        fonts = set()
        try:
            for page in pymupdf_file:
                features['image_count'] += len(page.get_images())
                features['text'] += len(page.get_text())
                fonts.update(page.get_fonts())

                features['object_count'] += len(page.get_xobjects())
            features['font_count'] = len(fonts)
        except Exception as e:
            logging.exception(f"Exception while processing {pdf_path}")
            features['image_count'] = -1
            features['text'] = -1
            features['object_count'] = -1
            features['font_count'] = -1

        features['embedded_files_count'] = pymupdf_file.embfile_count()
        embedded_files_total_size = 0
        for i in range(features['embedded_files_count']):
            embfile = pymupdf_file.embfile_get(i)
            if pymupdf_file.xref_is_stream(embfile.xref): #check if stream
                embedded_files_total_size += len(pymupdf_file.embfile_get(i))
        features['embedded_files_average_size'] = embedded_files_total_size / features['embedded_files_count'] if features['embedded_files_count'] > 0 else 0

        stream_sizes = [pymupdf_file.xref_length(i) for i in range(pymupdf_file.xref_length()) if pymupdf_file.xref_is_stream(i)]
        features['stream_average_size'] = sum(stream_sizes) / len(stream_sizes) if stream_sizes else 0
        features['xref_count'] = pymupdf_file.xref_length()
        features['obfuscation_count'] = 0 #TODO
        features['filter_count'] = sum(1 for i in range(pymupdf_file.xref_length()) if pymupdf_file.xref_is_stream(i) and '/Filter' in pymupdf_file.xref_object(i))
        features['nestedfilter_object_count'] = 0 #TODO
        features['stream_object_count'] = sum(1 for i in range(pymupdf_file.xref_length()) if pymupdf_file.xref_is_stream(i))

        features['stream_keyword_count'] = 0
        features['endstream_keyword_count'] = 0
        features['javascript_keyword_count'] = 0
        features['js_keyword_count'] = 0
        features['uri_keyword_count'] = 0
        features['action_keyword_count'] = 0
        features['aa_keyword_count'] = 0
        features['openaction_keyword_count'] = 0
        features['launch_keyword_count'] = 0
        features['submitform_keyword_count'] = 0
        features['acroform_keyword_count'] = 0
        features['xfa_keyword_count'] = 0
        features['jbig2decode_keyword_count'] = 0
        features['richmedia_keyword_count'] = 0
        features['trailer_keyword_count'] = 0
        features['xref_keyword_count'] = 0
        features['startxref_keyword_count'] = 0

        # The nodal properties are extracted from code inspired by Ran Liu et Al.'s work for their research paper "Evaluating Representativeness in PDF Malware Datasets: A Comparative Study and a New Dataset". We thank them for making this code available.
        features['children_count_average'] = -1
        features['children_count_median'] = -1
        features['children_count_variance'] = -1
        features['leaves_count'] = -1
        features['nodes_count'] = -1
        features['degree'] = -1
        features['degree_assortativity'] = -1
        features['average_shortest_path'] = -1
        features['average_clustering_coefficient'] = -1
        features['density'] = -1
        try:
            # TODO FIXME all of this is crap
            #logging.info(f"Extracting nodal features for {pdf_path}")
            genomeObj = PdfGenome.load_genome(pdf_path)
            paths = PdfGenome.get_object_paths(genomeObj)
            G = nx.DiGraph()
            for path in paths:
                for i in range(len(path)-1):
                    G.add_edge(path[i], path[i+1])
            children_count = [degree for _, degree in G.out_degree()]
            features['children_count_average'] = np.mean(children_count)
            features['children_count_median'] = np.median(children_count)
            features['children_count_variance'] = np.var(children_count)
            features['leaves_count'] = sum(1 for node in G.nodes() if G.out_degree(node) == 0)
            features['nodes_count'] = G.number_of_nodes()
            features['degree'] = sum(dict(G.degree()).values()) / G.number_of_nodes()
            features['degree_assortativity'] = nx.degree_assortativity_coefficient(G.to_undirected())
            features['average_shortest_path'] = nx.average_shortest_path_length(G.to_undirected())
            features['average_clustering_coefficient'] = nx.average_clustering(G.to_undirected())
            features['density'] = nx.density(G)
        except Exception as e:
            logging.exception(f"genome error for: {pdf_path}")
     

        # logging.info([hashed_file, pdf_size, title_len, encryption, metadata_size, pages, header, image_count, text, object_count, font_count, embedded_files_count, embedded_files_average_size, stream_keyword_count, endstream_keyword_count, stream_average_size, xref_count, obfuscation_count, filter_count, nestedfilter_object_count, stream_object_count, javascript_keyword_count, js_keyword_count, uri_keyword_count, action_keyword_count, aa_keyword_count, openaction_keyword_count, launch_keyword_count, submitform_keyword_count, acroform_keyword_count, xfa_keyword_count, jbig2decode_keyword_count, richmedia_keyword_count, trailer_keyword_count, xref_keyword_count, startxref_keyword_count, children_count_average, children_count_median, children_count_variance, leaves_count, nodes_count, degree, degree_assortativity, average_shortest_path, average_clustering_coefficient, density, is_malicious])
        # add the extracted features to the DataFrame
        destination.add_entry(features)
        # logging.info(f"Finished processing: {pdf_path}")