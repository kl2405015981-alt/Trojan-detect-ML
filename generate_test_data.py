import pandas as pd
import numpy as np

np.random.seed(42)
n = 200  # 200 samples

data = {
    'Machine': np.random.choice([332, 34404], n),
    'SizeOfOptionalHeader': np.random.choice([224, 240], n),
    'Characteristics': np.random.choice([8226, 290, 8230], n),
    'MajorLinkerVersion': np.random.randint(1, 15, n),
    'SizeOfCode': np.random.randint(1000, 500000, n),
    'SizeOfInitializedData': np.random.randint(1000, 300000, n),
    'SizeOfUninitializedData': np.random.randint(0, 10000, n),
    'AddressOfEntryPoint': np.random.randint(1000, 100000, n),
    'BaseOfCode': np.random.randint(1000, 10000, n),
    'ImageBase': np.random.choice([4194304, 65536, 1048576], n),
    'SectionAlignment': np.random.choice([4096, 512], n),
    'FileAlignment': np.random.choice([512, 4096], n),
    'MajorOperatingSystemVersion': np.random.choice([4, 5, 6], n),
    'SizeOfImage': np.random.randint(10000, 5000000, n),
    'SizeOfHeaders': np.random.choice([512, 1024], n),
    'CheckSum': np.random.randint(0, 999999, n),
    'Subsystem': np.random.choice([2, 3], n),
    'DllCharacteristics': np.random.choice([0, 32768, 33024], n),
    'SizeOfStackReserve': np.random.choice([1048576, 2097152], n),
    'SizeOfHeapReserve': np.random.choice([1048576, 65536], n),
    'LoaderFlags': np.zeros(n, dtype=int),
    'NumberOfRvaAndSizes': np.full(n, 16, dtype=int),
    'SectionsMaxEntropy': np.round(np.random.uniform(1.0, 7.9, n), 3),
    'label': np.random.choice([0, 1], n)  # 0=safe, 1=trojan
}

df = pd.DataFrame(data)
df.to_csv('test_dataset.csv', index=False)
print(f"Done! {n} rows created in test_dataset.csv")