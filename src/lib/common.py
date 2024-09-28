import os
import copy
import hashlib
# NOTE FROM PROJECT AUTHORS : WE ARE NOT ORIGINAL AUTHORS NEITHER CONTRIBUTORS OF THIS FILE. IT IS A NECESSARY DEPENDENCY FOR Ran Liu et Al.'s work for their research paper "Evaluating Representativeness in PDF Malware Datasets: A Comparative Study and a New Dataset", AND WE HAD NO CHOICE BUT TO INCLUDE IT IN OUR PROJECT SICE IT IS NOT PUBLISHED ON PYPI.
# PLEASE FIND THE GITHUB LINK TO THE ORIGINAL PROJECT BELOW:
# https://github.com/uvasrg/EvadeML/blob/master/lib/pdf_genome.py

LOW_SCORE = -65535

finished_flag = "evaded.flag"
visited_flag = "dev.log"
result_flag = "fitness_%.2f.flag"
error_flag = "error.flag"

# Make the order of file list deterministic.
def list_file_paths(dir_name, size_limit=None):
    fnames = os.listdir(dir_name)
    fnames.sort()

    ret = [os.path.join(dir_name, fname) for fname in fnames]
    if size_limit:
        return ret[:size_limit]
    else:
        return ret

def touch(fname):
    try:
        os.utime(fname, None)
    except:
        open(fname, 'a').close()

def deepcopy(obj):
    return copy.deepcopy(obj)

def hash_file(filepath):
    sha1 = hashlib.sha1()
    f = open(filepath, 'rb')
    try:
        sha1.update(f.read())
    finally:
        f.close()
    return sha1.hexdigest()


