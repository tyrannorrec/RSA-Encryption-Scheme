""" CS5001-5003, Spring 2022
    Final Project (Keygen module)
    Norrec Nieh
"""

import secrets
import base64
import ast
import math

ENCRYPTION_EXPONENT = 65537  # by RSA convention


class RSAKey:
    """ Class: RSAKey
        Attributes: __key_size (int)
                    __public_key (dict of two ints containing
                                  ["n"] (modulus) and
                                  ["e"] (encryption exponent))
                    __private_key (int) (decryption exponent)
        Notes: All attributes and most methods (except export_keys,
               the exponentiation methods, and type conversion methods.)
               are private. The static methods are utility methods called by
               __generate_keys and __generate_primes, which are used by
               the constructor to determine and set the __public_key and
               __private_key attributes.
    """

    def __init__(self, key_size):
        """ Method: __init__ (constructor)
            Parameter: key_size (int)
            Returns: None
            Notes: creates a new RSAKey of size key_size;
                   generates __public_key and __private_key attributes
        """
        self.__key_size = key_size
        self.__generate_keys()
        self.export_keys()

    def __generate_keys(self):
        """ RSAKey Method: __generate_keys (private)
            Parameters: None
            Returns: public key (dict of two ints) and private key (int)
        """
        p, q = self.__generate_primes()
        n = p * q
        phi = (p - 1) * (q - 1)
        e = ENCRYPTION_EXPONENT
        gcd, e_inverse, phi_inverse = self.__extended_euclid(e, phi)
        d = e_inverse

        # if the coefficient of e is a negative number,
        # add phi to determine the coefficient of e in
        # the inverse linear combination of gcd(e, phi).
        if d < 0:
            d = d + phi

        self.__public_key = {"n": n, "e": e}
        self.__private_key = d

        # intermediate values saved for demonstration purposes;
        # comment out when not needed.
        self.__p = p
        self.__q = q
        self.__phi = phi

    def __generate_primes(self):
        """ RSAKey Method: __generate_primes (private)
            Parameters: None
            Returns: two primes, p and q (ints)
            Note: called by RSAKey.__generate_keys on self
        """
        # Determines the value range from which p and q will be drawn.
        # Chosen so that the length of p * q will equal the key_size.
        ceiling = self.exp_iter(2, (self.__key_size // 2))
        floor = self.exp_iter(2, (self.__key_size // 2) - 1)

        # Removes possibility of n = key_size - 1. Theory discussed at:
        # https://stackoverflow.com/questions/12192116/rsa-bitlength-of-p-and-q
        # Floor is also set to first odd number of the range by adding 1.
        floor = int(float(floor) * 1.5) + 1

        # Determines number of tests to run based on key size.
        # See following link for a theoretical discussion.
        # https://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
        if self.__key_size == 1024:
            num_of_tests = 40
        elif self.__key_size == 2048:
            num_of_tests = 56
        else:
            num_of_tests = 64

        # Generates a random odd value between floor and ceiling.
        # Keeps generating odd values until one passes the prime test.
        secrets_rand = secrets.SystemRandom()
        prime_candidate = secrets_rand.randrange(floor, ceiling, 2)
        while not self.__is_prime(prime_candidate, num_of_tests):
            prime_candidate = secrets_rand.randrange(floor, ceiling, 2)
        p = prime_candidate

        # Repeat for the second prime number.
        prime_candidate = secrets_rand.randrange(floor, ceiling, 2)
        while not self.__is_prime(prime_candidate,
                                  num_of_tests) or prime_candidate == p:
            prime_candidate = secrets_rand.randrange(floor, ceiling, 2)
        q = prime_candidate

        return p, q

    def export_keys(self):
        """ RSAKey Method: export_keys (public)
            Parameters: None
            Returns: None
            Notes: Creates/overwrites private_key.pem and public_key.pem
        """
        public_key = self.__public_key
        private_key = self.__private_key

        # Writes public key to public_key.pem, enclosed in banners.
        # modulus (n) and encryption exponent (e) separated by line break.
        public_key_file = open("keys/public_key.pem", "w")
        public_key_file.write("-----BEGIN RSA PUBLIC KEY-----\n" +
                              str(self.int_to_base64(public_key["n"])) + "\n" +
                              str(self.int_to_base64(public_key["e"])) +
                              "\n-----END RSA PUBLIC KEY-----")
        public_key_file.close()

        # Writes private key to private_key.pem, enclosed in banners.
        private_key_file = open("keys/private_key.pem", "w")
        private_key_file.write("-----BEGIN RSA PRIVATE KEY-----\n" +
                               str(self.int_to_base64(private_key)) +
                               "\n-----END RSA PRIVATE KEY-----")
        private_key_file.close()

    def __str__(self):
        """ RSAKey Method: __str__ (print)
            Parameters: None
            Returns: print string containing the key size,
                     n and e (Public Key) and d (Private Key) as
                     attributes of the object.
        """
        print_str = "Key Size: " + str(self.__key_size) + \
                    "\n\nN (Public Key): " + str(self.__public_key["n"]) + \
                    "\n\ne (Public Key): " + str(self.__public_key["e"]) + \
                    "\n\nd (Private Key): " + str(self.__private_key)

        # intermediate values saved for demonstration purposes;
        # comment out when not needed.
        print_str += "\n\np: " + str(self.__p) + \
                     "\n\nq: " + str(self.__q) + \
                     "\n\nphi: " + str(self.__phi)

        return print_str

    # ----- RSA Utility Methods ----- #
    # -----       (Private)     ----- #

    @staticmethod
    def __is_prime(prime_candidate, num_of_tests):
        """ RSAKey Method: __is_prime (private, static)
            Parameters: prime_candidate (int)
                        num_of_tests (int)
            Returns: True/False (bool)
            Note: Driver function for miller_rabin.
                  Theory on the following links:
                  https://crypto.stanford.edu/pbc/notes/numbertheory/millerrabin.html
                  https://cryptography.fandom.com/wiki/Primality_test
                  Sample algorithm / pseudocode:
                  https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/
        """
        # Base case
        if prime_candidate < 2 or prime_candidate % 2 == 0:
            return False
        elif prime_candidate == 3:
            return True
        else:
            # Determines value of d in [n - 1 = a^((2^s)d)]
            # Passes into miller_rabin as a constant
            d = prime_candidate - 1
            while d % 2 == 0:
                d //= 2

            # Calls the miller_rabin test on candidate in a loop
            # until one fails, in which case the candidate is composite,
            # or else all tests pass, in which case the candidate
            # is probably prime.
            for test in range(num_of_tests):
                if not RSAKey.__miller_rabin(prime_candidate, d):
                    return False
            return True

    @staticmethod
    def __miller_rabin(prime_candidate, d):
        """ RSAKey Method: __miller_rabin (private, static)
            Parameters: prime_candidate (int)
                        d: from n - 1 = a^((2^s)d) (int)
            Returns: True/False (bool)
            Note: Tests the primality of prime_candidate.
        """
        # Generates a random number [2 <= a <= n - 2] to act as a base.
        secrets_random = secrets.SystemRandom()
        a = secrets_random.randint(2, prime_candidate - 2)

        # Evaluates the last element in the sequence, a^q.
        # If a^q mod n == 1 or a^q mod n == n - 1, candidate is prime.
        curr_element = RSAKey.exp_mod_iter(a, d, prime_candidate)
        if curr_element == 1 or curr_element == prime_candidate - 1:
            return True

        # Else, move from last element to the first by squaring each element.
        # The loop will evaluate each element. The value of an element
        # a^((2^s-k)d) mod n should not be 1 before the value n - 1 is seen.
        while d < prime_candidate - 1:  # Uses d as counter.
            curr_element = (curr_element * curr_element) % prime_candidate
            if curr_element == prime_candidate - 1:  # if n - 1 seen first,
                return True  # is prime.
            elif curr_element == 1:  # if 1 seen first,
                return False  # is composite.
            d *= 2

    @staticmethod
    def __extended_euclid(first, second):
        """ RSAKey Method: __extended_euclid (private, static)
            Parameters: two integers, first and second (ints)
            Returns: the gcd, and the coefficients of both ints
                     (x and y) in its linear combination (ints)
                     gcd(first, second) = x(first) + y(second)
            Notes: consulted pseudocode from
                   https://www.geeksforgeeks.org/euclidean-algorithms-basic-and-extended/
        """
        # Base case; when first = 0(0) + first; ie. second = 0
        if second == 0:
            return first, 1, 0
        else:
            gcd, x_new, y_new = RSAKey.__extended_euclid(second,
                                                         first % second)
            x = y_new
            y = x_new - y_new * (first // second)
            return gcd, x, y

    # ----- Exponentiation Methods ----- #
    # -----       (Public)         ----- #

    @staticmethod
    def exp_iter(x, y):
        """ RSAKey Method: exp_iter (private, static)
            Parameters: x: base     (int)
                        y: exponent (int)
            Returns: x^y            (int)
            Notes: based on the zyBooks example of fast exponentiation.
        """
        result = 1
        curr_element = x  # current x^2j
        value_left = y  # used to compute binary expansion of y
        while value_left > 0:
            if value_left % 2 == 1:
                result = result * curr_element
            curr_element = curr_element * curr_element
            value_left //= 2
        return result

    @staticmethod
    def exp_mod_iter(x, y, n):
        """ RSAKey Method: exp_mod_iter (private, static)
            Parameters: x: base     (int)
                        y: exponent (int)
                        n: modulus  (int)
            Returns: x^y mod n      (int)
            Notes: based on the zyBooks example of fast modular exponentiation.
        """
        result = 1
        curr_element = x  # current x^2j
        value_left = y  # used to compute binary expansion of y
        while value_left > 0:
            if value_left % 2 == 1:
                result = result * curr_element % n
            curr_element = curr_element * curr_element % n
            value_left //= 2
        return result

    # ----- Type Conversion Methods ----- #
    # -----       (Public)          ----- #

    @staticmethod
    def int_to_base64(int_value):
        """ Method: int_to_base64 (public, static)
            Parameter: value (int)
            Returns: the value encoded in base64 (bytes)
        """
        # Determines byte length of value
        length_of_text = math.ceil(int_value.bit_length() / 8)
        # Converts int to bytes
        value_bytes = int_value.to_bytes(length_of_text, byteorder='little')
        # Encodes bytes in base64
        value_base64 = base64.urlsafe_b64encode(value_bytes)

        return value_base64

    @staticmethod
    def base64_to_int(byte_string):
        """ Method: base64_to_int (public, static)
            Parameter: byte_string (str)
            Returns: the value of the byte_string (int)
        """
        # Evaluate strings for byte literals
        byte_literal = ast.literal_eval(byte_string)
        # Decodes bytes
        value_bytes = base64.urlsafe_b64decode(byte_literal)
        # Converts bytes to int
        value_int = int.from_bytes(value_bytes, byteorder='little')

        return value_int
