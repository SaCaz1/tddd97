import string
import random

def generate_token():
    """Generates and returns a token from a randomized sequence of uppercase characters and digits.

    Returns
    -------
    str
        Token
    """
    random_characters = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 36))
    return str(random_characters)
