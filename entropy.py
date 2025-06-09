
import math

def calculate_entropy(data):
    if not data:
        return 0
    prob = [float(data.count(byte)) / len(data) for byte in set(data)]
    entropy = -sum(p * math.log2(p) for p in prob)
    return round(entropy, 2)

def calculate_file_entropy(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    return calculate_entropy(data)
