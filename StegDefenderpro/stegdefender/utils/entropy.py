import math
from collections import Counter

def calculate_entropy(data):
    """
    Calculates the Shannon entropy of a byte sequence.
    Returns a float value between 0 and 8.
    """
    if not data:
        return 0

    entropy = 0
    total_len = len(data)
    
    # Count frequency of each byte
    counts = Counter(data)
    
    for count in counts.values():
        p_i = count / total_len
        entropy -= p_i * math.log2(p_i)
        
    return entropy

def calculate_entropy_chunks(data, target_chunks=100):
    """
    Calculates entropy for chunks of the data for visualization.
    Returns a list of {'offset': int, 'entropy': float}.
    """
    if not data:
        return []

    data_len = len(data)
    if data_len == 0:
        return []

    # specific block size for very small files, otherwise dynamic
    if data_len < target_chunks * 64:
         chunk_size = 64
    else:
         chunk_size = max(64, data_len // target_chunks)

    chunks = []
    for i in range(0, data_len, chunk_size):
        chunk = data[i:i + chunk_size]
        entropy = calculate_entropy(chunk)
        chunks.append({
            'offset': i,
            'entropy': round(entropy, 4)
        })
    
    return chunks
