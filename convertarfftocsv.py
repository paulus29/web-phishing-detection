import pandas as pd
from scipy.io import arff

# Baca file ARFF
data = arff.loadarff('Training Dataset (1).arff')
df = pd.DataFrame(data[0])

# Simpan ke dalam file CSV
df.to_csv('file.csv', index=False)
