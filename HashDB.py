import sys, json
# config Ga1axy path
sys.path.append(r'Ga1axy_path')
import Ga1axy
a = {}
# dic file
result = Ga1axy.collect_File('base/dic.txt')
for i in result:
    # Encryption mode
    a[i] = Ga1axy.Encode_sha256(i.strip())
js = json.dumps(a)
    # output path
file = open('config/sha256.txt', 'a')
file.write(js)
file.close()