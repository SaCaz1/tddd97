import string
import random

def generate_token():
    random_characters = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 36))
    return str(random_characters)
