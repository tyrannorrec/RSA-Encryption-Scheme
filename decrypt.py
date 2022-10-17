""" CS5001-5003, Spring 2022
    Final Project (decrypt module)
    Norrec Nieh
"""

import Keygen
import encrypt
import base64


def decrypt(file_handle):
    """ Function: decrypt
        Parameter: file_handle (str)
        Returns: True/False (bool)
        Notes: Returns True if decryption successful. Else, returns False.
    """
    try:  # failsafe for unacceptable or corrupted ciphertext.
        data = file_handle.read().split("\n")
        ciphertext = Keygen.RSAKey.base64_to_int(data[1])

        # retrieves modulus (and e) from public_key.pem
        n, e = encrypt.get_public_key()
        d = get_private_key()  # retrieves d from private_key.pem

        m = Keygen.RSAKey.exp_mod_iter(ciphertext, d, n)  # decrypt
        decrypted_text = int_to_str(m)  # convert int value to original text

        # writes decrypted text to decrypted.txt
        out_file = open("files/decrypted.txt", "w")
        out_file.write("-----BEGIN DECRYPTED MESSAGE-----\n" +
                       decrypted_text +
                       "\n-----END DECRYPTED MESSAGE-----")
        out_file.close()

    except ValueError:
        return False

    except SyntaxError:
        return False

    return True


def get_private_key():
    """ Function: get_private_key
        Parameters: None
        Returns: d (int)
        Notes: Parses public_key.pem for the decryption exponent (d)
    """
    try:  # defensive measure to check file validity for private_key.pem
        private_key_handle = open("keys/private_key.pem", "r")
        private_key = private_key_handle.read()
        private_key = private_key.split("\n")

        d = Keygen.RSAKey.base64_to_int(private_key[1])

        private_key_handle.close()
        return d

    except FileNotFoundError:
        print("File private_key.pem was not found.")

    except PermissionError:
        print("Permission denied for private_key.pem.", sep="")

    except IOError:
        print("Error occurred while reading private_key.pem.", sep="")


def int_to_str(data_int):
    """ Function: int_to_str
        Parameter: data_int (int)
        Returns: decrypted_text (str)
        Notes: Discussion on data type conversions for RSA found at link:
               https://crypto.stackexchange.com/questions/42344/convert-plain-text-as-numbers-to-encrypt-using-rsa
    """
    # converts int to base64
    data_b64 = Keygen.RSAKey.int_to_base64(data_int)
    # decodes base64 to byte value
    data_bytes = base64.urlsafe_b64decode(data_b64)
    # decodes bytes to string value
    decrypted_text = data_bytes.decode(errors='replace')
    return decrypted_text


def main():
    file_name = input("\nEnter the file to decrypt: ")

    while True:  # break when file passes exception blocks and
        # decryption succeeds.

        try:  # defensive measure to check file validity.
            file_handle = open(file_name, "r")
            if decrypt(file_handle):
                file_handle.close()
                print("File ", file_name, " was successfully decrypted.",
                      sep="")
                break  # decryption success; end main()
            else:  # decryption failed.
                print("Failed to decrypt. Try another file name "
                      "or enter q to quit.")
                file_handle.close()
                file_name = input("\nEnter the file to decrypt: ")
                if file_name == "q":
                    quit(1)

        except FileNotFoundError:
            print("File", file_name, "was not found.")
            file_name = input("\nEnter the file to decrypt: ")

        except PermissionError:
            print("Permission denied for ", file_name, ".", sep="")
            file_name = input("\nEnter the file to decrypt: ")

        except IOError:
            print("Error occurred while reading ", file_name, ".", sep="")
            file_name = input("\nEnter the file to decrypt: ")


if __name__ == "__main__":
    main()
