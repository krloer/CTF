import io
import torch
import base64

print(banner)
base64_string = input("Send the base64 encoded model: ")
bytes_data = base64.b64decode(base64_string)

print("Evaluating the model ...")
device = torch.device("cpu")
model = torch.load(io.BytesIO(bytes_data), map_location=device)
model.eval()
print("Finished evaluating the model!")