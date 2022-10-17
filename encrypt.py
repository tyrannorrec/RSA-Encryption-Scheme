""" CS5001-5003, Spring 2022
    Final Project (encrypt module)
    Norrec Nieh
"""

import Keygen
import base64
import math


def encrypt(file_handle, key_size):
    """ Function: encrypt
        Parameters: file_handle (str)
                    key_size    (int)
        Returns: True/False     (bool)
        Notes: Encrypts a file and exports the cipher into encrypted.txt
    """
    key = Keygen.RSAKey(key_size)  # generates keys

    # print statement for demonstration purposes. Comment out if not needed.
    print("\n", key, "\n", sep="")

    n, e = get_public_key()  # retrieves public key from private_key.txt

    data = file_handle.read()  # reads the text to be encrypted into a string
    data_numeric = str_to_int(data)  # converts text to int value

    # Check whether bit_size of data_numeric is larger than key_size.
    # Return False if larger than key_size, as decryption will result in
    # scrambled text due to overflow.
    if is_oversized(data_numeric, key_size):
        return False

    ciphertext = Keygen.RSAKey.exp_mod_iter(data_numeric, e, n)  # encrypt

    if export_ciphertext(ciphertext):  # writes ciphertext to encrypted.txt
        return True  # if export successful, return True
    else:
        return False  # if export failed, return False


def get_public_key():
    """ Function: get_public_key
        Parameters: None
        Returns: n, e (ints)
        Notes: Parses public_key.pem for the modulus (n) and encryption
               exponent (e)
    """
    try:  # defensive measure to check file validity for public_key.pem
        public_key_handle = open("keys/public_key.pem", "r")
        public_key = public_key_handle.read().split("\n")

        n = Keygen.RSAKey.base64_to_int(public_key[1])
        e = Keygen.RSAKey.base64_to_int(public_key[2])

        public_key_handle.close()
        return n, e

    except FileNotFoundError:
        print("File public_key.pem was not found.")

    except PermissionError:
        print("Permission denied for public_key.pem.", sep="")

    except IOError:
        print("Error occurred while reading public_key.pem.", sep="")


def str_to_int(data_str):
    """ Function: str_to_int
        Parameters: data_str (str)
        Returns: data_numeric (int)
        Note: Converts string data to byte values and byte values to int
              Implementation not secure. Discussion found on following link.
              https://crypto.stackexchange.com/questions/42344/convert-plain-text-as-numbers-to-encrypt-using-rsa
    """
    # converts string to utf-8 value
    data_bytes = data_str.encode('utf-8')
    # converts utf-8 value to base64 encoding
    data_b64 = base64.urlsafe_b64encode(data_bytes)
    # passes in string of base64 value and converts to int value
    data_numeric = Keygen.RSAKey.base64_to_int(str(data_b64))
    return data_numeric


def export_ciphertext(ciphertext):
    """ Function: export_ciphertext
        Parameter: ciphertext (int)
        Returns: True/False (bool)
        Notes: Writes ciphertext to encrypted.txt. If failed due to
               exceptions, return False. Otherwise, return True.
    """
    try:  # defensive try block to check file validity
        out_file = open("files/encrypted.txt", "w")
        # converts cipher to base64 for storage
        cipher_base64 = Keygen.RSAKey.int_to_base64(ciphertext)
        out_file.write("-----BEGIN ENCRYPTED MESSAGE-----\n" +
                       str(cipher_base64) +
                       "\n-----END ENCRYPTED MESSAGE-----")
        out_file.close()
        return True

    except PermissionError:
        print("Permission denied for encrypted.txt.", sep="")
        return False

    except IOError:
        print("Error occurred while writing to encrypted.txt.", sep="")
        return False


def is_oversized(int_value, key_size):
    """ Function: is_oversized
        Parameters: int_value (int)
                    key_size (int)
        Returns: True/False (bool)
        Notes: If numeric value of text is greater than key_size,
               return True. Otherwise, return False.
               Function used to check if the size of the text will
               cause an overflow and result in failed decryption.
    """
    bit_size = math.ceil(int_value.bit_length())
    if bit_size >= key_size:
        return True
    return False


def main():
    file_name = input("\nEnter the file to encrypt: ")

    while True:  # break when file passes exception blocks and
        # encryption either succeeds or fails due to content issues.

        try:  # defensive measure to check file validity.
            file_handle = open(file_name, "r")
            key_size = int(input("Enter the encryption key size "
                                 "(1024 or 2048): "))
            # defensive while block to get key_size from user input.
            while key_size != 1024 and key_size != 2048:
                print("Invalid key size. Please enter 1024 or 2048.")
                key_size = int(input("Enter the encryption key size "
                                     "(1024 or 2048): "))
            # if encryption is successful, print success message.
            if encrypt(file_handle, key_size):
                print("File ", file_name, " was successfully encrypted.",
                      sep="")
            else:  # else if encryption fails, print fail message.
                print("Failed to encrypt.")
            file_handle.close()
            break

        except FileNotFoundError:
            print("File", file_name, "was not found.")
            file_name = input("\nEnter the file to encrypt: ")

        except PermissionError:
            print("Permission denied for ", file_name, ".", sep="")
            file_name = input("\nEnter the file to encrypt: ")

        except IOError:
            print("Error occurred while reading ", file_name, ".", sep="")
            file_name = input("\nEnter the file to encrypt: ")


if __name__ == "__main__":
    main()
