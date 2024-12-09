# Towards an improved, open source feature extractor for CIC-Evasive-PDFMal2022

## Context

The CIC-Evasive-PDFMal2022 dataset is a dataset of PDF files that have been collected from the internet and labeled as either benign or malicious. The dataset is intended to be used for training machine learning models to detect malicious PDF files. The dataset is available for download from the Canadian Institute for Cybersecurity (CIC) website (https://www.unb.ca/cic/datasets/pdfmal-2022.html). More information about the dataset can be found in the following paper: Maryam Issakhani, Princy Victor, Ali Tekeoglu, and Arash Habibi Lashkari1, “PDF Malware Detection Based on Stacking Learning”, The International Conference on Information Systems Security and Privacy, February 2022

The dataset is published on the CIC website as 2 zip files, one for benign PDF files and one for malicious PDF files, but no feature extraction code is provided, the only information provided in the research paper about feature extraction is that the Python package pdfid and PyMuPDF were used to extract the features listed in the paper, which is insufficient to reproduce the feature extraction process.

Furthermore, other research papers highlight limitations of the dataset's feature extraction, such as Haj Abdel Khaleq et Al "Improving Malicious PDF Detection with a Robust Stacking Ensemble Approach", which highlights major flaws in the reliablity of the initial feature extraction process, and proposes an improved feature extraction process that unfortunately is unfortunately no longer available online.

*Note : we acknowledge that the CIC-Evasive-PDFMal2022 dataset in itself has limitations such as the lack of new techniques for PDF evasion, but we chose to focus our work on the feature extraction process for this dataset rather than having to create a new dataset from scratch.*

## Purpose

The objective of this project is to provide cybersecurity and ML researchers with an improved, open source feature extractor for the CIC-Evasive-PDFMal2022 dataset, that will take into consideration the limitations of the initial feature extraction process that were highlighted in the previously mentioned research papers, as far as reliability of the features.

### Table of features

| Column name                 | Description                                 | Type/Unit       | Extraction method |
| --------------------------- | ------------------------------------------- | --------------- | ----------------- |
| pdf_size                    | size of the PDF file                        | Float/kilobytes | Manual            |
| title_len                   | length of the title                         | int/chars       | Manual            |
| encryption                  | is the document password protected          | bool            | PDFid             |
| metadata_size               | size of the metadata                        | int/bytes       | PyMuPDF           |
| pages                       | number of pages of the document             | int             | PyMuPDF           |
| header                      | Content of the header                       | string          | PDFid             |
| image_count                 | Number of images in the file                | int             | PDFid             |
| text                        | total length of all text fields in the file | int/chars       | Manual            |
| object_count                | Total number of objects in the file         | int/bytes       | Manual            |
| font_count                  | Number of fonts used in the document        | int             | PDFid             |
| embedded_files_count        | Number of embedded files                    | int             | Manual            |
| embedded_files_average_size | Average size of embedded medias             | float/bytes     | PyMuPDF           |
| stream_keyword_count        | Number of "stream" keywords                 | int             | PDFid             |
| endstream_keyword_count     | Number of "endstream" keywords              | int             | PDFid             |
| stream_average_size         | Average size of streams in the file         | float/bytes     | PyMuPDF           |
| obfuscation_count           | Number of obfuscations used in the document | int             | Manual            |
| indirect_object_count       | Number of indirect objects                  | int             | Manual            |
| filter_count                | Total number of filter used in the file     | int             | PDFid             |
| nestedfilter_object_count   | Number of objects with nested filters       | int             | Manual            |
| javascript_keyword_count    | Number of JavaScript keywords in the file   | int             | PDFid             |
| js_keyword_count            | Number of JS keywords in the file           | int             | PDFid             |
| uri_keyword_count           | Number of URI keywords in the file          | int             | PDFid             |
| action_keyword_count        | Number of Action keywords in the file       | int             | PDFid             |
| aa_keyword_count            | Number of AA Keywords in the file           | int             | PDFid             |
| openaction_keyword_count    | Number of OpenAction keywords in the file   | int             | PDFid             |
| launch_keyword_count        | Number of launch keywords in the file       | int             | PDFid             |
| submitform_keyword_count    | Number of SubmitForm Keywords in the file   | int             | PDFid             |
| acroform_keyword_count      | Number of Acroform keywords int he file     | int             | PDFid             |
| xfa_keyword_count           | Number of XFA Keywords in the file          | int             | PDFid             |
| jbig2decode_keyword_count   | Number of JBig2Decode keywords in the file  | int             | PDFid             |
| richmedia_keyword_count     | Number of Richmedia keywords in the file    | int             | PDFid             |
| trailer_keyword_count       | Number of Trailer keywords in the file      | int             | PDFid             |
| xref_keyword_count          | Number of Xref keywords in the file         | int             | PDFid             |
| startxref_keyword_count     | Number of Startxref keywords in the file    | int             | PDFid             |
| is_malicious                | Is the file malicious                       | bool            | Ground Truth      |

### Note :

We tried implementing R. Liu et Al's approach of using a tree structure to extract features, but we found that the current version of pdfrw for Python 3 is very unreliable and often crashes when trying to extract features from the tree structure of the PDF file. 

### Usage

- Install the requirements in requirements.txt using pip
```bash
pip install -r requirements.txt
```
- Run the feature extraction script
```bash
python3 src/main.py datasets/cic/malicious/ datasets/cic/benign/
```