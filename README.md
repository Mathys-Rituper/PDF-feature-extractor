# Towards an improved, open source feature extractor for CIC-Evasive-PDFMal2022

## Context

The CIC-Evasive-PDFMal2022 dataset is a dataset of PDF files that have been collected from the internet and labeled as either benign or malicious. The dataset is intended to be used for training machine learning models to detect malicious PDF files. The dataset is available for download from the Canadian Institute for Cybersecurity (CIC) website (https://www.unb.ca/cic/datasets/pdfmal-2022.html). More information about the dataset can be found in the following paper: Maryam Issakhani, Princy Victor, Ali Tekeoglu, and Arash Habibi Lashkari1, “PDF Malware Detection Based on Stacking Learning”, The International Conference on Information Systems Security and Privacy, February 2022

The dataset is published on the CIC website as 2 zip files, one for benign PDF files and one for malicious PDF files, but no feature extraction code is provided, the only information provided in the research paper about feature extraction is that the Python package pdfid and PyMuPDF were used to extract the features listed in the paper, which is insufficient to reproduce the feature extraction process.

Furthermore, other research papers highlight limitations of the dataset's feature extraction, such as Haj Abdel Khaleq et Al "Improving Malicious PDF Detection with a Robust Stacking Ensemble Approach", which highlights major flaws in the reliablity of the initial feature extraction process, and proposes an improved feature extraction process that unfortunately is unfortunately no longer available online.

Eventually, other research papers highlight the need for the addition of more features, such as "R. Liu, R. Joyce, C. Matuszek and C. Nicholas, "Evaluating Representativeness in PDF Malware Datasets: A Comparative Study and a New Dataset", which suggests a  new approach focused on PDF structural analysis as a tree structure, and focuses its features on the nodal properties of the files.

*Note : we acknowledge that the CIC-Evasive-PDFMal2022 dataset in itself has limitations such as the lack of new techniques for PDF evasion, but we chose to focus our work on the feature extraction process for this dataset rather than having to create a new dataset from scratch.*

## Objective

The objective of this project is to provide cybersecurity and ML researchers with an improved, open source feature extractor for the CIC-Evasive-PDFMal2022 dataset, that will take into consideration the limitations of the initial feature extraction process that were highlighted in the previously mentioned research papers, as far as reliability of the features and the addition of nodal features.

## Methodology

Before diving on the technical aspects of the project, let's first define the features that we will extract from the PDF files. We have chosen to reuse the features from “PDF Malware Detection Based on Stacking Learning” and to add the nodal features from "Evaluating Representativeness in PDF Malware Datasets: A Comparative Study and a New Dataset".

### Table of features



| Column name                    | Description                                 | Type/Unit       |
| ------------------------------ | ------------------------------------------- | --------------- |
| pdf_size                       | size of the PDF file                        | Float/kilobytes |
| title_len                      | length of the title                         | int/chars       |
| encryption                     | is the document password protected          | bool            |
| metadata_size                  | size of the metadata                        | int/bytes       |
| pages                          | number of pages of the document             | int             |
| header                         | Content of the header                       | string          |
| image_count                    | Number of images in the file                | int             |
| text                           | total length of all text fields in the file | int/chars       |
| object_count                   | Total number of objects in the file         | int/bytes       |
| font_count                     | Number of fonts used in the document        | int             |
| embedded_files_count           | Number of embedded files                    | int             |
| embedded_files_average_size    | Average size of embedded medias             | float/bytes     |
| stream_keyword_count           | Number of "stream" keywords                 | int             |
| endstream_keyword_count        | Number of "endstream" keywords              | int             |
| stream_average_size            | Average size of streams in the file         | float/bytes     |
| xref_count                     | Number of xref entries                      | int             |
| obfuscation_count              | Number of obfuscations used in the document | int             |
| indirect_object_count          | Number of indirect objects                  | int             |
| filter_count                   | Total number of filter used in the file     | int             |
| nestedfilter_object_count      | Number of objects with nested filters       | int             |
| stream_object_count            | Number of stream objects in the file        | int             |
| javascript_keyword_count       | Number of JavaScript keywords in the file   | int             |
| js_keyword_count               | Number of JS keywords in the file           | int             |
| uri_keyword_count              | Number of URI keywords in the file          | int             |
| action_keyword_count           | Number of Action keywords in the file       | int             |
| aa_keyword_count               | Number of AA Keywords in the file           | int             |
| openaction_keyword_count       | Number of OpenAction keywords in the file   | int             |
| launch_keyword_count           | Number of launch keywords in the file       | int             |
| submitform_keyword_count       | Number of SubmitForm Keywords in the file   | int             |
| acroform_keyword_count         | Number of Acroform keywords int he file     | int             |
| xfa_keyword_count              | Number of XFA Keywords in the file          | int             |
| jbig2decode_keyword_count      | Number of JBig2Decode keywords in the file  | int             |
| richmedia_keyword_count        | Number of Richmedia keywords in the file    | int             |
| trailer_keyword_count          | Number of Trailer keywords in the file      | int             |
| xref_keyword_count             | Number of Xref keywords in the file         | int             |
| startxref_keyword_count        | Number of Startxref keywords in the file    | int             |
| children_count_average         | Average number of children per node         | float           |
| children_count_median          | Median number of children per node          | float           |
| children_count_variance        | Variance of number of children per node     | float           |
| leaves_count                   | Number of leaves in the tree                | int             |
| nodes_count                    | Number of nodes in the tree                 | int             |
| degree_average                 | Average degree                              | float           |
| degree_assortativity           | Degree assortativity coefficient            | float           |
| average_shortest_path          | The average shortest path length            | float           |
| average_clustering_coefficient | Average clustering coefficient of nodes     | float           |
| density                        | Graph density                               | float           |

### Technical aspects

The feature extraction process will be done in Python, using the following libraries:
- PyMuPDF: to extract the text and metadata from the PDF files
- pdfid: to extract the header and other features from the PDF files
- networkx: to extract the nodal features from the PDF files

For the obfuscation_count feature, we focus on 3 specifications :
- Number of base64 encoded strings
- Number compression filters
- Number of hex strings

### Usage

- Install the requirements in requirements.txt using pip
```bash
pip install -r requirements.txt
```
- Download the custom version of pdfrw : 
```bash
git clone https://github.com/Blushsard/PDF-Malware-Parser
cd PDF-Malware-Parser
pip install .
```
