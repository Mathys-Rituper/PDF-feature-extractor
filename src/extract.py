import hashlib
import os
import sys

import pandas as pd
import pdfid
import pymupdf

def hash_file_sha256(filename: str):
    """ Returns the SHA256 hash of a file """
    with open(filename,"rb") as f:
        bytes = f.read()
        return hashlib.sha256(bytes).hexdigest();

async def extract_features_from_file(pdf_path : str, is_malicious : bool,
                                     destination : pd.DataFrame):
    try:
        pymupdf_file = pymupdf.open(pdf_path)
    except pymupdf.FileDataError:
        print("opening: ",pdf_path)
    else:
        pdf_size = round(os.path.getsize(pdf_path) / 1024, 2)
        hashed_file = hash_file_sha256(pdf_path)
        title_len = len(os.path.basename(pdf_path))
        try:
            encryption = pymupdf_file.needs_pass or pymupdf_file.metadata["encryption"] is not None
        except TypeError:
            print("encryption: ",pdf_path)
    
        metadata_size = 0
        if isinstance(pymupdf_file.metadata, dict):
            for key in pymupdf_file.metadata:
                metadata_size += len(key.encode("utf8")) + (len(pymupdf_file.metadata[key].encode("utf8")) if isinstance(pymupdf_file.metadata[key], str) else 0)

        pages = len(pymupdf_file)

        header = 0 # TODO Censé être fait avec pdfid mais il n'y a pas de documentation sur comment faire

        image_count = 0
        text = 0
        object_count = 0
        fonts = set()
        try:
            for page in pymupdf_file:
                image_count += len(page.get_images())
                text += len(page.get_text())
                fonts.update(page.get_fonts())

                object_count += len(page.get_xobjects())
            font_count = len(fonts)
        except Exception:
            image_count = -1
            text = -1
            object_count = -1
            font_count = -1

        embedded_files_count = pymupdf_file.embfile_count()
        embedded_files_total_size = 0
        for i in range(embedded_files_count):
            embedded_files_total_size += len(pymupdf_file.embfile_get(i))
        embedded_files_average_size = embedded_files_total_size / embedded_files_count if embedded_files_count > 0 else 0

        stream_average_size = 0
        xref_count = 0
        obfuscation_count = 0
        filter_count = 0
        nestedfilter_object_count = 0
        stream_object_count = 0

        stream_keyword_count = 0
        endstream_keyword_count = 0
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

        # print([hashed_file, pdf_size, title_len, encryption, metadata_size, pages, header, image_count, text, object_count, font_count, embedded_files_count, embedded_files_average_size, stream_keyword_count, endstream_keyword_count, stream_average_size, xref_count, obfuscation_count, filter_count, nestedfilter_object_count, stream_object_count, javascript_keyword_count, js_keyword_count, uri_keyword_count, action_keyword_count, aa_keyword_count, openaction_keyword_count, launch_keyword_count, submitform_keyword_count, acroform_keyword_count, xfa_keyword_count, jbig2decode_keyword_count, richmedia_keyword_count, trailer_keyword_count, xref_keyword_count, startxref_keyword_count, children_count_average, children_count_median, children_count_variance, leaves_count, nodes_count, degree, degree_assortativity, average_shortest_path, average_clustering_coefficient, density, is_malicious])
        # add the extracted features to the DataFrame
        destination.loc[len(destination)] = [hashed_file, pdf_size, title_len, encryption, metadata_size, pages, header, image_count, text, object_count, font_count, embedded_files_count, embedded_files_average_size, stream_keyword_count, endstream_keyword_count, stream_average_size, xref_count, obfuscation_count, filter_count, nestedfilter_object_count, stream_object_count, javascript_keyword_count, js_keyword_count, uri_keyword_count, action_keyword_count, aa_keyword_count, openaction_keyword_count, launch_keyword_count, submitform_keyword_count, acroform_keyword_count, xfa_keyword_count, jbig2decode_keyword_count, richmedia_keyword_count, trailer_keyword_count, xref_keyword_count, startxref_keyword_count, children_count_average, children_count_median, children_count_variance, leaves_count, nodes_count, degree, degree_assortativity, average_shortest_path, average_clustering_coefficient, density, is_malicious]



