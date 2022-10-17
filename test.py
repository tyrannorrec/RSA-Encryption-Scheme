""" CS5001-5003, Spring 2022
    Final Project (test module)
    Norrec Nieh
"""

import encrypt
import decrypt

test_number = 0
test_pass_count = 0
test_fail_count = 0


def test_suite(file_name, key_size):
    """ Function: test_suite
        Parameters: file_name (str)
                    key_size (int)
                    expected_text (str) -- for testing purposes
        Returns: True/False (bool)
        Notes: Prints results of the test, and the current success/fail counts.
               This test suite bypasses the main() functions within the
               encrypt.py and decrypt.py modules, directly calling their
               respective core functions. This is because the main() functions
               in the modules act only as file management / driver functions,
               and the file paths are predetermined in the main() of the
               test suite.
    """

    original_text = extract_text(file_name)
    file_handle = open(file_name)

    global test_number
    global test_pass_count
    global test_fail_count

    test_number += 1

    print("***** Testing: ", file_name, " *****\n\n",
          "...encrypting ", file_name, "...", sep="")

    # encrypt.encrypt calls a method to check that the bit size of the file
    # to be encrypted is smaller than the key size. If it is larger, the
    # function rejects the file and returns False to the main() function.
    # Since this test function continues to call decrypt.decrypt, the following
    # lines will return False and exit the test function if the file fails
    # the key_size comparison in encrypt.encrypt.
    if not encrypt.encrypt(file_handle, key_size):
        test_fail_count += 1
        print("Bit size of file is larger than key size.\n"
              "Decryption failed.\n", test_pass_count, " tests passed, ",
              test_fail_count, " tests failed.\n", sep="")
        return False

    print("-----BEGIN ORIGINAL TEXT-----\n",
          original_text, "\n",
          "-----END ORIGINAL TEXT-----\n", sep="")

    encrypted_text = extract_text("files/encrypted.txt")
    print(encrypted_text, "\n")  # prints encrypted.txt

    # opens the encrypted.txt file to decrypt it
    encrypted_text_handle = open("files/encrypted.txt")
    decrypt.decrypt(encrypted_text_handle)

    # prints resultant decrypted.txt
    decrypted_text = extract_text("files/decrypted.txt")
    print(decrypted_text, "\n")

    # splits the file into a list to remove banners for later comparison
    # of decrypted_text with original_text.
    decrypted_text = decrypted_text.split("\n")
    del decrypted_text[len(decrypted_text) - 1]
    del decrypted_text[0]
    decrypted_text = "\n".join(decrypted_text)  # restores to str

    # if the two strings are equivalent, then the test passes.
    if decrypted_text == original_text:
        test_pass_count += 1
        print("Decryption successful.")
    else:  # if the two strings are not equivalent, then the test fails.
        test_fail_count += 1
        print("Decryption failed.")

    # prints current pass/fail counts.
    print(test_pass_count, " tests passed, ", test_fail_count,
          " tests failed.\n************************************\n", sep="")

    file_handle.close()
    return True  # test passed the key_size check and executed in full.


def extract_text(file_name):
    """ Function: extract_text
        Parameter: file_name (str)
        Returns: file_text (str)
    """
    file_handle = open(file_name)
    file_text = file_handle.read()
    file_handle.close()
    return file_text


def main():
    # Testing an empty message.
    test_suite("files/test0.txt", 1024)

    # Testing a simple message.
    test_suite("files/test1.txt", 1024)

    # Testing a message with mixed characters.
    test_suite("files/test2.txt", 2048)

    # Testing a longer message.
    test_suite("files/test3.txt", 2048)

    # Testing a message with numbers, punctuations, and formatting.
    test_suite("files/test4.txt", 2048)

    # Testing a message that fails the key_size test.
    test_suite("files/test5.txt", 1024)
    print("[Expected: 5 tests passed, 1 tests failed.]")


if __name__ == "__main__":
    main()
