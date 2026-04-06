import pandas as pd
import random
import os

# generate_dataset.py - CLEAN VERSION WITHOUT EMOJI
# Purpose: Build 5,000 simulated data records for model training

def create_mock_dataset():
    data = []
    print("Starting dataset generation process...")
    
    # Generate 5,000 records (2,500 Safe, 2,500 Trojan)
    for i in range(5000):
        is_malicious = 1 if i >= 2500 else 0
        
        row = {
            'Name': f"file_{i}.exe",
            'md5': f"hash_{i}",
            'Machine': 332 if random.random() > 0.1 else 34404,
            'SizeOfOptionalHeader': 224,
            'Characteristics': 258 if is_malicious == 0 else 34,
            'MajorLinkerVersion': random.randint(8, 14),
            'SizeOfCode': random.randint(10000, 500000),
            'SizeOfInitializedData': random.randint(10000, 500000),
            'SizeOfUninitializedData': 0,
            'AddressOfEntryPoint': random.randint(4096, 100000),
            'BaseOfCode': 4096,
            'ImageBase': 4194304,
            'SectionAlignment': 4096,
            'FileAlignment': 512,
            'MajorOperatingSystemVersion': 6,
            'SizeOfImage': random.randint(50000, 1000000),
            'SizeOfHeaders': 1024,
            'CheckSum': random.randint(0, 1000000) if is_malicious == 0 else 0,
            'Subsystem': 2,
            'DllCharacteristics': 33088 if is_malicious == 0 else 0,
            'SizeOfStackReserve': 1048576,
            'SizeOfHeapReserve': 1048576,
            'LoaderFlags': 0,
            'NumberOfRvaAndSizes': 16,
            'SectionsMaxEntropy': random.uniform(2.0, 5.0) if is_malicious == 0 else random.uniform(6.5, 7.9),
            'legitimate': 1 if is_malicious == 0 else 0 
        }
        data.append(row)
    
    df = pd.DataFrame(data)
    df.to_csv('malware_dataset.csv', index=False)
    # Use plain text, not emoji to avoid Unicode errors
    print("SUCCESS: File 'malware_dataset.csv' successfully created with 5,000 records!")

if __name__ == "__main__":
    create_mock_dataset()