import gzip
import io

def compress(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode='wb') as f:
        f.write(data)
    return buf.getvalue()

def decompress(data: bytes) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode='rb') as f:
        return f.read()
