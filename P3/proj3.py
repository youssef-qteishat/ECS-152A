import requests
from pip._vendor import requests as requests_with_certs
import os

# # Set the path to your custom CA certificate bundle (replace '/path/to/your/cacert.pem' with the actual path)
custom_ca_bundle_path = '/Users/youssefqteishat/.mitmproxy/mitmproxy-ca-cert.pem'
os.environ['REQUESTS_CA_BUNDLE'] = custom_ca_bundle_path

headers = {'Student-Id': '921481041'}
r = requests.get('https://kartik-labeling-cvpr-0ed3099180c2.herokuapp.com/ecs152a_ass1', verify=False, headers=headers)
print(r.text)





# headers = {'Student-Id': '921481041'}
# r = requests.get('https://kartik-labeling-cvpr-0ed3099180c2.herokuapp.com/ecs152a_ass1', headers=headers, verify=False)
# print(r.text)

