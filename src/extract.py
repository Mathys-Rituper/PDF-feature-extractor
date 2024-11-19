import hashlib
import logging
import os

import pandas as pd
import pymupdf

from lib.pdf_genome import PdfGenome
import networkx as nx
import numpy as np

from lib.pdfidnew import PDFiD
import re
from xml.dom.minidom import parseString

def hash_file_sha256(filename: str):
    """ Returns the SHA256 hash of a file """
    with open(filename,"rb") as f:
        bytes = f.read()
        return hashlib.sha256(bytes).hexdigest()

def extract_keyword_count(data, keyword_name):
    xml_data = data
    
    search_str = f'Keyword Name="{keyword_name}" Count="'
    count_start = xml_data.find(search_str) + len(search_str)
    if count_start > len(search_str) - 1:
        return int(xml_data[count_start:xml_data.find('"', count_start)])
    return 0

def count_indirect_objects(pdf_file):
    with open(pdf_file, 'rb') as file:
        content = file.read()
    indirect_objects = re.findall(rb'\d+ \d+ obj', content)
    return len(indirect_objects)

def is_base64(s):
    if len(s) % 4 == 0:
        base64_pattern = re.compile(b'^[A-Za-z0-9+/]+={0,2}$')
        return base64_pattern.match(s) is not None
    return False

def count_obfuscations(pdf_file):
    obfuscations = 0
    
    with open(pdf_file, 'rb') as file:
        content = file.read()

    hex_matches = re.findall(rb'<[0-9A-Fa-f]+>', content)
    obfuscations += len(hex_matches)
    
    filter_matches = re.findall(rb'/Filter\s*(\[.*?\]|\S+)', content)
    obfuscations += len(filter_matches)
    
    potential_base64_strings = re.findall(rb'[A-Za-z0-9+/]{4,}(?:={0,2})', content)
    
    for b64_string in potential_base64_strings:
        if is_base64(b64_string):
            obfuscations += 1

    return obfuscations

def count_nested_filters(pdf_file):
    nested_filters = 0
    
    with open(pdf_file, 'rb') as file:
        content = file.read()
    filter_matches = re.findall(rb'/Filter\s*(\[.*?\]|\S+)', content)
    
    for match in filter_matches:
        if match.startswith(b'[') and match.endswith(b']'):
            nested_filters += 1
        else:
            if b' ' in match:
                nested_filters += 1

    return nested_filters

def text_len(file):
    with open(file, 'rb') as pdf:
        contenu = pdf.read()
        texts = []
        start = 0
        while True:
            start = contenu.find("BT".encode("latin-1"), start)
            if start == -1:
                break
            end = contenu.find("ET".encode("latin-1"), start)
            if end == -1:
                break
            text_brut = contenu[start+2:end].strip()
            texts.append(text_brut)
            start = end + 2
        total_text = b"".join(texts)
        try:
            return len(total_text.decode("utf-8", errors="ignore"))
        except UnicodeDecodeError:
            return len(total_text)

def object_count(file):
    with open(file, 'rb') as pdf:
        contenu = pdf.read()
        return contenu.count("endobj".encode("latin-1"))

def embedded_file_count(file):
    with open(file, 'rb') as pdf:
        contenu = pdf.read()
        embedded_count = contenu.count("/EmbeddedFiles".encode("latin-1"))
        filespec_count = contenu.count("/Filespec".encode("latin-1"))
        return embedded_count + filespec_count

def stream_objects_count(file):
    with open(file, 'rb') as pdf:
        contenu = pdf.read()
        return contenu.count("stream".encode("latin-1"))

def xref_count(file):
    with open(file, 'rb') as pdf:
        contenu = pdf.read()
        return contenu.count("xref".encode("latin-1"))

def extract_features_from_file(pdf_path : str, is_malicious : bool):
    features = {}
    features['is_malicious'] = is_malicious
    try:
        features['pdf_size'] = round(os.path.getsize(pdf_path) / 1024, 2)
        features['hashed_file'] = hash_file_sha256(pdf_path)
        features['title_len'] = len(os.path.basename(pdf_path))

        features['text'] = text_len(pdf_path)
        features['object_count'] = object_count(pdf_path)
        features['embedded_files_count'] = embedded_file_count(pdf_path)


        # Duplicates de endxref_keyword_count et stream_keyword_count
        features['stream_object_count'] = stream_objects_count(pdf_path)
        features['xref_count'] = xref_count(pdf_path)


        features['indirect_objects_count'] = count_indirect_objects(pdf_path)
        features['obfuscation_count'] = count_obfuscations(pdf_path)
        features['nestedfilter_object_count'] = count_nested_filters(pdf_path)
    except Exception as e:
        logging.exception(f"manual_error:Error while processing file {pdf_path}")
        for key in ["pdf_size", "hashed_file", "title_len", "text", "object_count", "embedded_files_count", "stream_object_count", "xref_count", "indirect_objects_count", "obfuscation_count", "nestedfilter_object_count"]:
            if key not in features.keys():
                features[key] = -1


    try:
        with pymupdf.open(pdf_path) as pymupdf_file:
            try:
                features['pages'] = len(pymupdf_file)
                features['metadata_size'] = 0
                if isinstance(pymupdf_file.metadata, dict):
                    for key in pymupdf_file.metadata:
                        features['metadata_size'] += len(key.encode("utf8")) + (len(pymupdf_file.metadata[key].encode("utf8")) if isinstance(pymupdf_file.metadata[key], str) else 0)

                try:
                    embedded_files_total_size = 0
                    if features['embedded_files_count'] > 0:
                        for i in range(pymupdf_file.embfile_count()):
                            embedded_files_total_size += len(pymupdf_file.embfile_get(i))
                    features['embedded_files_average_size'] = embedded_files_total_size / features['embedded_files_count'] if features['embedded_files_count'] > 0 else 0
                except Exception as e:
                    logging.exception(f"pymupdf_error:Embedded file extracting failed for {pdf_path}")
                    features['embedded_files_average_size'] = -1
                

                try:
                    all_streams_xrefs = [i for i in range(pymupdf_file.xref_length()) if pymupdf_file.xref_is_stream(i)]
                    stream_sizes = [len(pymupdf_file.xref_stream(i)) for i in all_streams_xrefs]
                    features['stream_average_size'] = sum(stream_sizes) / len(stream_sizes) if len(stream_sizes) > 0 else 0
                except Exception as e:
                    logging.exception(f"pymupdf_error:Stream processing failed for {pdf_path}")
                    features['stream_average_size'] = -1
                
                
            except Exception as e:
                logging.exception(f"pymupdf_error:Error while processing file with PyMuPDF {pdf_path}")
    except:
        logging.exception(f"pymupdf_error:Failed to open {pymupdf_file} with PyMuPDF")
        
    try:
        pdfid_manip = PDFiD(pdf_path)
        try:
            xml_data_og = pdfid_manip.toxml()
            # attention, sensible à la casse !
            features['stream_keyword_count'] = extract_keyword_count(xml_data_og, 'stream')
            features['endstream_keyword_count'] = extract_keyword_count(xml_data_og, 'endstream')
            features['javascript_keyword_count'] = extract_keyword_count(xml_data_og, '/JavaScript')
            features['js_keyword_count'] = extract_keyword_count(xml_data_og, '/JS')
            features['uri_keyword_count'] = extract_keyword_count(xml_data_og, '/URI')
            features['action_keyword_count'] = extract_keyword_count(xml_data_og, '/Action')
            features['aa_keyword_count'] = extract_keyword_count(xml_data_og, '/AA')
            features['openaction_keyword_count'] = extract_keyword_count(xml_data_og, '/OpenAction')
            features['launch_keyword_count'] = extract_keyword_count(xml_data_og, '/Launch')
            features['submitform_keyword_count'] = extract_keyword_count(xml_data_og, '/SubmitForm')
            features['acroform_keyword_count'] = extract_keyword_count(xml_data_og, '/AcroForm')
            features['xfa_keyword_count'] = extract_keyword_count(xml_data_og, '/XFA')
            features['jbig2decode_keyword_count'] = extract_keyword_count(xml_data_og, '/JBIG2Decode')
            features['richmedia_keyword_count'] = extract_keyword_count(xml_data_og, '/RichMedia')
            features['trailer_keyword_count'] = extract_keyword_count(xml_data_og, 'trailer')
            features['xref_keyword_count'] = extract_keyword_count(xml_data_og, 'xref')
            features['startxref_keyword_count'] = extract_keyword_count(xml_data_og, 'startxref')
            features['filter_count'] = extract_keyword_count(xml_data_og, '/Filter')
            features['font_count'] = extract_keyword_count(xml_data_og, '/Font')
            features['image_count'] = extract_keyword_count(xml_data_og, '/Image')
            features['encryption'] = 1 if extract_keyword_count(xml_data_og, '/Encrypt') > 0 else 0

            features['header'] = re.search(r'Header="([^"]+)"', xml_data_og).group(1)
        except Exception as e:
            logging.exception(f"pdfid_error:Exception while analyzing with pdfid on {pdf_path}")
            for key in ["stream_keyword_count", "endstream_keyword_count", "javascript_keyword_count", "js_keyword_count", "uri_keyword_count",
                         "action_keyword_count", "aa_keyword_count", "openaction_keyword_count", "launch_keyword_count", "submitform_keyword_count", 
                         "acroform_keyword_count", "xfa_keyword_count", "jbig2decode_keyword_count", "richmedia_keyword_count", "trailer_keyword_count"
                         "xref_keyword_count", "startxref_keyword_count", "filter_count", "font_count", "image_count", "encryption", "header"]:
                if key not in features.keys():
                    features[key] = -1
    except Exception as e:
        logging.exception(f"pdfid_error:Exception while parsing file with pdfid on {pdf_path}")
        for key in ["stream_keyword_count", "endstream_keyword_count", "javascript_keyword_count", "js_keyword_count", "uri_keyword_count",
                         "action_keyword_count", "aa_keyword_count", "openaction_keyword_count", "launch_keyword_count", "submitform_keyword_count", 
                         "acroform_keyword_count", "xfa_keyword_count", "jbig2decode_keyword_count", "richmedia_keyword_count", "trailer_keyword_count"
                         "xref_keyword_count", "startxref_keyword_count", "filter_count", "font_count", "image_count", "encryption", "header"]:
                if key not in features.keys():
                    features[key] = -1

    # The nodal properties are extracted using code inspired by Ran Liu et Al.'s work for their research paper "Evaluating Representativeness in PDF Malware Datasets: A Comparative Study and a New Dataset". We thank them for making this code available for review and comparaison..
    try:
        #logging.info(f"Extracting nodal features for {pdf_path}")
        with PdfGenome(pdf_path) as genomeObj:
            try:
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
                features['degree'] = sum(dict(G.degree()).values()) / G.number_of_nodes() if G.number_of_nodes() > 0 else 0
                features['degree_assortativity'] = nx.degree_assortativity_coefficient(G.to_undirected())
                features['average_shortest_path'] = nx.average_shortest_path_length(G.to_undirected())
                features['average_clustering_coefficient'] = nx.average_clustering(G.to_undirected())
                features['density'] = nx.density(G)
            except:
                logging.exception(f"pdfrw_error:Genome processing error for: {pdf_path}")
                keys = ['children_count_average', 'children_count_median', 'children_count_variance', 'leaves_count', 'nodes_count', 'degree', 'degree_assortativity', 'average_shortest_path', 'average_clustering_coefficient', 'density']
                for key in keys:
                    if key not in features.keys():
                        features[key] = -1
    except Exception as e:
        logging.exception(f"pdfrw_error:opening error error for: {pdf_path}")
        keys = ['children_count_average', 'children_count_median', 'children_count_variance', 'leaves_count', 'nodes_count', 'degree', 'degree_assortativity', 'average_shortest_path', 'average_clustering_coefficient', 'density']
        for key in keys:
            if key not in features.keys():
                features[key] = -1
     

        # logging.info([hashed_file, pdf_size, title_len, encryption, metadata_size, pages, header, image_count, text, object_count, font_count, embedded_files_count, embedded_files_average_size, stream_keyword_count, endstream_keyword_count, stream_average_size, xref_count, obfuscation_count, filter_count, nestedfilter_object_count, stream_object_count, javascript_keyword_count, js_keyword_count, uri_keyword_count, action_keyword_count, aa_keyword_count, openaction_keyword_count, launch_keyword_count, submitform_keyword_count, acroform_keyword_count, xfa_keyword_count, jbig2decode_keyword_count, richmedia_keyword_count, trailer_keyword_count, xref_keyword_count, startxref_keyword_count, children_count_average, children_count_median, children_count_variance, leaves_count, nodes_count, degree, degree_assortativity, average_shortest_path, average_clustering_coefficient, density, is_malicious])
    logging.info(f"Finished processing: {pdf_path}")
    return features