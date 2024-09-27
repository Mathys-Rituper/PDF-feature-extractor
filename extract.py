import pdfid
import pymupdf
import os
import sys
import pandas as pd




async def extract_features_from_file(pdf_path : str, is_malicious : bool, destination : DataFrame):
    pdf_size = os.path.getsize(pdf_path) 
    hashed_filename = pdf_path
    title_len = 0
    encryption = 0
    metadata_size = 0
    pages = 0
    header = 0
    image_count = 0
    text = 0
    object_count = 0
    font_count = 0
    embedded_files_count = 0
    embedded_files_average_size = 0
    stream_keyword_count = 0
    endstream_keyword_count = 0
    stream_average_size = 0
    xref_count = 0
    obfuscation_count = 0
    filter_count = 0
    nestedfilter_object_count = 0
    stream_object_count = 0
    javascript_keyword_count = 0
    js_keyword_count = 0
    uri_keyword_count = 0
    action_keyword_count = 0
    aa_keyword_count = 0
    openaction_keyword_count = 0
    launch_keyword_count = 0
    submitform_keyword_count = 0
    acroform_keyword_count = 0
    xfa_keyword_count = 0
    jbig2decode_keyword_count = 0
    richmedia_keyword_count = 0
    trailer_keyword_count = 0
    xref_keyword_count = 0
    startxref_keyword_count = 0
    children_count_average = 0
    children_count_median = 0
    children_count_variance = 0
    leaves_count = 0
    nodes_count = 0
    degree = 0
    degree_assortativity = 0
    average_shortest_path = 0
    average_clustering_coefficient = 0
    density = 0

    # add the extracted features to the DataFrame
    destination.loc[len(destination)] = [hashed_filename, pdf_size, title_len, encryption, metadata_size, pages, header, image_count, text, object_count, font_count, embedded_files_count, embedded_files_average_size, stream_keyword_count, endstream_keyword_count, stream_average_size, xref_count, obfuscation_count, filter_count, nestedfilter_object_count, stream_object_count, javascript_keyword_count, js_keyword_count, uri_keyword_count, action_keyword_count, aa_keyword_count, openaction_keyword_count, launch_keyword_count, submitform_keyword_count, acroform_keyword_count, xfa_keyword_count, jbig2decode_keyword_count, richmedia_keyword_count, trailer_keyword_count, xref_keyword_count, startxref_keyword_count, children_count_average, children_count_median, children_count_variance, leaves_count, nodes_count, degree, degree_assortativity, average_shortest_path, average_clustering_coefficient, density, is_malicious]



