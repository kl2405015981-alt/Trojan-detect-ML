#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Add file hashes to whitelist
"""

import hashlib
import json
import os
import sys

def get_file_hash(filepath):
    """Calculate SHA-256 hash"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def add_to_whitelist(filepath):
    """Add file hash to whitelist"""
    
    if not os.path.exists(filepath):
        print(f"❌ Error: File not found: {filepath}")
        return False
    
    # Calculate hash
    print(f"📊 Calculating hash for: {os.path.basename(filepath)}")
    file_hash = get_file_hash(filepath)
    print(f"✅ Hash: {file_hash}")
    
    # Load existing whitelist
    whitelist_path = 'whitelist.json'
    if os.path.exists(whitelist_path):
        with open(whitelist_path, 'r') as f:
            whitelist = json.load(f)
    else:
        whitelist = {
            "whitelisted_hashes": [],
            "whitelisted_publishers": [],
            "whitelisted_patterns": []
        }
    
    # Check if already whitelisted
    if file_hash in whitelist['whitelisted_hashes']:
        print("⚠️  Hash already in whitelist!")
        return True
    
    # Add hash
    whitelist['whitelisted_hashes'].append(file_hash)
    
    # Save updated whitelist
    with open(whitelist_path, 'w') as f:
        json.dump(whitelist, f, indent=2)
    
    print(f"✅ Hash added to whitelist!")
    print(f"📝 Total whitelisted hashes: {len(whitelist['whitelisted_hashes'])}")
    
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python add_to_whitelist.py <filepath>")
        print("\nExample:")
        print("  python add_to_whitelist.py Git-2.53.0-64-bit.exe")
        sys.exit(1)
    
    filepath = sys.argv[1]
    add_to_whitelist(filepath)