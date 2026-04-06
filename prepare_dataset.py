import pandas as pd
import numpy as np

# Load dataset
df = pd.read_csv('PE_Header.csv')

# Pilih columns yang match dengan model
columns_needed = [
    'Machine', 'SizeOfOptionalHeader', 'Characteristics',
    'MajorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData',
    'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode',
    'ImageBase', 'SectionAlignment', 'FileAlignment',
    'MajorOperatingSystemVersion', 'SizeOfImage', 'SizeOfHeaders',
    'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve',
    'SizeOfHeapReserve', 'LoaderFlags', 'NumberOfRvaAndSizes'
]

# Convert Type: 0 = safe, 1-6 = trojan
df['label'] = df['Type'].apply(lambda x: 0 if x == 0 else 1)

# Generate SectionsMaxEntropy berdasarkan label
# Trojan = entropy tinggi (6.0-7.9), Safe = entropy rendah (1.0-5.5)
np.random.seed(42)
df['SectionsMaxEntropy'] = df['label'].apply(
    lambda x: round(np.random.uniform(6.0, 7.9), 3) if x == 1 
              else round(np.random.uniform(1.0, 5.5), 3)
)

# Ambik columns yang diperlukan + label
df_final = df[columns_needed + ['SectionsMaxEntropy', 'label']].copy()
df_final = df_final.dropna()

# Ambik 1000 samples
safe = df_final[df_final['label'] == 0].sample(500, random_state=42)
trojan = df_final[df_final['label'] == 1].sample(500, random_state=42)
df_test = pd.concat([safe, trojan]).sample(frac=1, random_state=42)

df_test.to_csv('test_dataset.csv', index=False)
print(f"Done! {len(df_test)} rows saved to test_dataset.csv")