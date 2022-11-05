import pickle
import base64
import io

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if name == "Rick":
            return super().find_class(module, name)
        print(f"No hacking please")
        exit(0)

def restricted_loads(s):
    return RestrictedUnpickler(io.BytesIO(s)).load()

def Rick():
    print("Thank you for feeding me Morty!")

if __name__ == '__main__':
    user_inp = restricted_loads(base64.b64decode(input("Please provide me with a pickle:")))
