def xor(data, key=0xAA):
    return bytes(b ^ key for b in data)
