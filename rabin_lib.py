import random
import string
import itertools
import math
import hashlib
from datetime import datetime

# Check if a number is prime
def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

# Generate prime numbers p and q, satisfying p != q and p ≡ q ≡ 3 mod 4
def miyao():
    while True:
        p = 4 * random.randint(100, 10000) + 3
        q = 4 * random.randint(100, 10000) + 3
        if p != q and is_prime(p) and is_prime(q):
            return p, q

# Convert string to Unicode code list
def string_to_unicode(s):
    return [ord(c) for c in s]

# Encryption process

def JiaMi(unicode_ints, p, q):
    """
    Encrypt the input Unicode integer list using given prime numbers p and q.
    
    Parameters:
        unicode_ints (list of int): Input Unicode integer list.
        p (int): Prime number p.
        q (int): Prime number q.
    
    Returns:
        tuple: A tuple containing ciphertext list and quotient list. shang[] can be used when plaintext
        Unicode code value is much greater than p*q, saving the multiple relationship for easier recovery: m=k*n+c, where m is plaintext, k is quotient, n is p*q, c is ciphertext
    """
    n = p * q
    miwen = []
    shang = []
    for m in unicode_ints:
        c_m = pow(m, 2, n)
        k_m = m // n
        miwen.append(c_m)
        shang.append(k_m)
    return miwen, shang


# Decryption process
def JieMi(miwen, p, q, shang):
    n = p * q
    characters = []     # Store decrypted characters
    
    def Getst(a, b):   # Extended Euclidean algorithm for calculating inverse
        if b == 0:
            return 1, 0
        else:
            s1, t1 = Getst(b, a % b)
            s = t1
            t = s1 - (a // b) * t1
            return s, t
    
    s, t = Getst(p, q)   # Get extended Euclidean result
    
    for i in range(len(miwen)):
        c = miwen[i]
        k = shang[i]
        m_mod_p = c % p
        m_mod_q = c % q
        
        try:
            m_sqrt_p = pow(m_mod_p, (p + 1) // 4, p)  # Calculate square root modulo p
            m_sqrt_q = pow(m_mod_q, (q + 1) // 4, q)  # Calculate square root modulo q
        except:
            characters.append([])  # If unable to calculate square root, return empty list
            continue
        
        M1 = (m_sqrt_p * t * q + m_sqrt_q * s * p) % n + n * k
        M2 = (m_sqrt_p * t * q - m_sqrt_q * s * p) % n + n * k
        M3 = (-m_sqrt_p * t * q + m_sqrt_q * s * p) % n + n * k
        M4 = (-m_sqrt_p * t * q - m_sqrt_q * s * p) % n + n * k
        
        characters.append([M1, M2, M3, M4])
    
    return characters


# Tag Method 1: Add a random letter after each character
def add_random_letter_to_string(input_string, letter_range):
    result = ''
    for char in input_string:
        random_letter = random.choice(letter_range)
        random_letter_code = f"{ord(random_letter):04d}"
        combined_code = f"{ord(char)}{random_letter_code}"
        combined_code_int = int(combined_code)
        result += str(combined_code_int) + " "
    return result.strip()

# Return each combined code of string Unicode codes as integers for encryption/decryption calculation
def string_to_unicode_with_tuple(s):
    unicode_ints = []
    for code_str in s.split():
        try:
            code_int = int(code_str)
            unicode_ints.append(code_int)
        except ValueError:
            pass
    return unicode_ints

# Split decrypted integer into character and letter Unicode codes
def split_code(m, letter_digits=4):
    m_str = str(m)
    if len(m_str) <= letter_digits:
        return None, None  # Not enough to split into character and letter parts
    
    letter_code_str = m_str[-letter_digits:]
    char_code_str = m_str[:-letter_digits]
    try:
        char_code = int(char_code_str)
        letter_code = int(letter_code_str)
        return char_code, letter_code
    except ValueError:
        return None, None


# Tag Method 1: Filter decryption results, return all valid combinations
def filter_decrypt_combinations(decrypted_chars, mark_range, letter_digits=4):
    valid_combinations = []
    valid_options_per_char = []
    
    for decryptions in decrypted_chars:
        valid_options = []
        for m in decryptions:
            char_code, letter_code = split_code(m, letter_digits)
            if char_code is None or letter_code is None:
                continue
            try:
                letter = chr(letter_code)
                char = chr(char_code)
            except ValueError:
                continue
            # If letter is within the specified marker range, save this solution
            if letter in mark_range:
                valid_options.append(char + letter)
        if not valid_options:
            # If no valid solution exists for a character, entire combination is invalid
            return []
        valid_options_per_char.append(valid_options)
    
    all_combinations = list(itertools.product(*valid_options_per_char))
    for combination in all_combinations:
        combination_str = ''.join(combination)
        valid_combinations.append(combination_str)
    
    return valid_combinations

# Get restricted letter range
def get_reduced_alphabet(start='a', end='f'):
    return string.ascii_lowercase[string.ascii_lowercase.index(start):string.ascii_lowercase.index(end) + 1]

# Remove specified range letters from string, since each character has a random letter added, take even positions as result, index starts from 0
def remove_letters_from_string(s):
    result = ''
    for index,char in enumerate(s):
        if index%2==1:
            continue       
        result += char
    return result


# Tag Method 2: Add sequence number and checksum before each character
def add_sequence_and_checksum_to_string(input_string):
    result = []
    for i, char in enumerate(input_string):
        seq_num = int(f"{i:04d}")
        char_code = int(ord(char))
        checksum_full = hashlib.sha256(f"{seq_num}{char_code}".encode()).hexdigest()
        checksum_int = int(checksum_full[:4], 16)
        checksum = f"{checksum_int:04d}"[-4:]
        combined_code = f"{seq_num}:{checksum}:{char_code}"
        result.append(combined_code)
    return ' '.join(result)

# Split combined encoding into first eight digits and char_code part
def split_encoding(encoded_string):
    """
    Split each character's combined encoding into first eight digits (seq_num:checksum) and the subsequent encoding (char_code).
    Returns two lists: prefixes and char_codes.
    """
    prefixes = []
    char_codes = []
    for part in encoded_string.split():
        try:
            seq_num, checksum, char_code = part.split(':')
            prefixes.append(f"{seq_num}:{checksum}")
            char_codes.append(int(char_code))
        except ValueError:
            # If format is incorrect, skip this part
            continue
    return prefixes, char_codes

# Tag Method 2: Concatenate first eight digits with decrypted encoding and verify
def combine_and_verify(prefixes, decrypted_char_codes):
    valid_combinations = []
    
    for i, (prefix, decryptions) in enumerate(zip(prefixes, decrypted_char_codes)):
        try:
            seq_num, checksum = prefix.split(':')
            seq_num = int(seq_num)
        except ValueError:
            return []
        
        valid_options = []
        for m in decryptions:
            char_code = int(m)
            checksum_full = hashlib.sha256(f"{seq_num}{char_code}".encode()).hexdigest()
            calculated_checksum_int = int(checksum_full[:4], 16)
            calculated_checksum = f"{calculated_checksum_int:04d}"[-4:]
            
            if checksum == calculated_checksum:
                try:
                    char = chr(char_code)
                    valid_options.append(char)
                except ValueError:
                    continue
        
        if not valid_options:
            return []
        
        valid_combinations.append(valid_options)
    
    all_combinations = [''.join(p) for p in itertools.product(*valid_combinations)]
    return all_combinations

# Tag Method 3: Timestamp

def generate_timestamp():
    """
    Generate a 12-digit timestamp of current time, format: YYYYMMDDHHMM.
    """
    return datetime.now().strftime('%Y%m%d%H%M')

def add_timestamp_to_unicode(input_text):
    """
    Add a 12-digit timestamp after each Unicode encoding, return Unicode encoding list with timestamps and timestamp list.
    
    Parameters:
        unicode_ints (list of int): Original Unicode encoding list.
    
    Returns:
        tuple: (Unicode encoding list with timestamps, timestamp list)
    """
    unicode_with_timestamps = []
    timestamps = []
    # Convert input string to Unicode encoding list
    unicode_ints = [ord(c) for c in input_text]

    for m in unicode_ints:
        timestamp = generate_timestamp()
        combined_code = int(f"{m}{timestamp}")
        unicode_with_timestamps.append(combined_code)
        timestamps.append(timestamp)
    return unicode_with_timestamps, timestamps

def strip_timestamp_from_unicode(unicode_with_timestamps):
    """
    Strip out original Unicode encoding and timestamp from Unicode encoding with timestamps.
    
    Parameters:
        unicode_with_timestamps (list of int): Unicode encoding list with timestamps.
    
    Returns:
        tuple: (Original Unicode encoding list, timestamp list)
    """
    original_unicode = []
    extracted_timestamps = []
    for combined in unicode_with_timestamps:
        combined_str = str(combined)
        if len(combined_str) <= 12:
            # Unable to strip out timestamp
            original_unicode.append(None)
            extracted_timestamps.append(None)
            continue
        timestamp = combined_str[-12:]
        unicode_str = combined_str[:-12]
        try:
            unicode_val = int(unicode_str)
            original_unicode.append(unicode_val)
            extracted_timestamps.append(timestamp)
        except ValueError:
            original_unicode.append(None)
            extracted_timestamps.append(None)
    return original_unicode, extracted_timestamps

def verify_and_extract_characters(correct_timestamps, decrypted_chars):
    """
    Compare stripped timestamps with stored timestamps, return list of correct characters.
    
    Parameters:
        correct_timestamps (list of str): Original timestamp list.
        decrypted_unicode_with_timestamps (list of int): Decrypted Unicode encoding list with timestamps.
    
    Returns:
        list: Correct character list matching timestamps (with timestamps) and stripped character list.
    """
    valid_chars_with_timestamps = []
    valid_chars = []
    
    for idx, decryptions in enumerate(decrypted_chars):
        current_valid_chars_with_ts = []
        current_valid_chars = []
        expected_ts = correct_timestamps[idx]

        for decrypted in decryptions:
            decrypted_str = str(decrypted)
            if len(decrypted_str) <= 12:
                continue  # Unable to strip out timestamp
            timestamp = decrypted_str[-12:]
            unicode_str = decrypted_str[:-12]

            if timestamp != expected_ts:
                continue  # Timestamp doesn't match

            try:
                unicode_val = int(unicode_str)
                char = chr(unicode_val)
                current_valid_chars_with_ts.append(f"{char}{timestamp}")
                current_valid_chars.append(char)
            except (ValueError, OverflowError):
                continue  # Invalid Unicode encoding

        if not current_valid_chars:
            # If no valid solution exists for a character position, entire decryption is invalid
            return [], [], []

        valid_chars_with_timestamps.append(current_valid_chars_with_ts)
        valid_chars.append(current_valid_chars)

    # Generate all possible decryption combinations
    all_combinations = list(itertools.product(*valid_chars))
    all_valid_combinations = [''.join(comb) for comb in all_combinations]

    return valid_chars_with_timestamps, valid_chars, all_valid_combinations