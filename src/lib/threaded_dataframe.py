# src/lib/threaded_dataframe.py
import threading
import pandas as pd
import logging

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
                logging.exception("Could not write entry to dataframe")
    
    def __len__(self):
        if len(self.dataframe) != len(self.values):
            self.dataframe = pd.DataFrame.from_records(self.values)
        return len(self.dataframe)
    
    def to_csv(self, features, index):
        self.dataframe = self.dataframe.sample(frac=1)
        return self.dataframe.to_csv(features, index=index)

