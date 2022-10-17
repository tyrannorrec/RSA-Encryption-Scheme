CS5001-5003, Spring 2022
Final Project (readme.txt)
Norrec Nieh

           #####   RSA Encryption Scheme Implementation   #####

Goals --------------------------------------------------------------------

    My CS5001 final project is an implementation of the RSA encryption scheme
    from scratch, without using relevant libraries such as python-rsa or
    cryptography (fernet). The reasoning behind this choice was two-fold:
    (1) first, it provided an opportunity to converge material encountered
    in both CS5001 and CS5002; (2) second, it allowed me to further develop
    my preexisting interests in cybersecurity / cryptography.

Contents -----------------------------------------------------------------

    The project file includes four modules and two folders.

        > Keygen.py
            - Contains RSAKey class.
            - A key object is created by calling the RSAKey class constructor,
              passing in the desired key size (either 1024 or 2048). The
              constructor generates new values for the private_key and
              public_key attributes, exporting them as separate .pem files.
            - Most methods are static utility methods, and are either called
              by the constructor or by methods called by the constructor.
            - *** For the purposes of demonstration, intermediary variables
              p, q, and phi have also been saved as attributes in order to
              be printed by the __str__ method. These are not necessary to
              the program's functionality, and are included for visibility. ***

        > encrypt.py
            - Prompts the user for the file to be encrypted, as well as for
              the desired key size. A key is generated and exported as .pem
              files. public_key.pem is then parsed for the modulus and
              encryption exponent, with which the numeric value of the input
              file is encrypted as ciphertext. The cipher is written to and
              exported as files/encrypted.txt.

        > decrypt.py
            - Prompts the user for the file to be decrypted. public_key.pem
              and private_key.pem are respectively parsed for the modulus and
              decryption exponent, with which the ciphertext is decrypted and
              rendered as text. The text is written to and exported as
              files/decrypted.txt.

        > test.py
            - Provides a test suite that runs encrypt.py and decrypt.py,
              bypassing the main() functions of each module.
            - Runs six tests using the test suite. Test files contained in
              files/ as testX.txt.

        > /files
            - Includes source.txt as well as six test files, numbered 0 to 5.
            - Running encrypt.py and decrypt.py will write/overwrite
              encrypted.txt, and decrypted.txt, correspondingly.

        > /keys
            - will contain private_key.pem and public_key.pem.
            - Running encrypt.py writes/overwrites both keys.


Tools & Techniques -------------------------------------------------------

    > Defensive programming and file management. Used try/except blocks,
      while loops, and conditionals to prevent unexpected errors.

    > Classes and objects. Implemented RSAKey as a class, where each object
      represents an instance of a public/private key pair.

    > Recursion. The extended_euclid method in the RSAKey class uses recursion
      to return the gcd of two numbers as well as its linear combination.

    > Efficiency. Exponentiation methods found in the RSAKey class needed to be
      efficient in order to handle very large numbers.

    > Code organization. Separated functionalities into modules, depending on
      which functions/methods would be called on by other modules.

    > Built-in libraries: read documentation for and used new preexisting
      libraries, including secrets, base64, ast, and math.

    > Documentation. Program was dense enough that comments were needed to
      keep the code clear for future reference.

    > Testing. Wrote a test suite exhibiting each step of the program,
      printing intermediary values, encrypted text, and comparisons of original
      and decrypted text.

Challenges & Takeaways ----------------------------------------------------

    > Stack overflow and int overflow. Performing operations on large integers
      (up to 2048 bits) required more attention paid to efficiency of code and
      to computational bottlenecks. I took many hours debugging a problem wherein
      my decrypted text was scrambled, only to find that it was due to the
      input text being too long, such that certain calculations overflowed.
      This ultimately resulted in the numeric value of the decrypted text being
      corrupted, mapping to the wrong utf-8 values and producing scrambled text.
      As a solution, I used defensive programming to limit the bit size of the
      file to be encrypted, in proportion to the key size.

    > Primality testing. I learned about algorithms and theory underlying the
      Fermat and Miller-Rabin tests, including their treatment of Carmichael
      numbers (Lynn). I eventually implemented the Miller-Rabin test within the
      RSAKey class as a method, based on theory and pseudocode found in my
      research (Lynn; GeeksforGeeks; Crypto Wiki). I was surprised by the
      number of times the test had to be run on a single number to adequately
      reduce the probability of it being a false positive (Pornin).

    > Key storage. Without deeper knowledge of networking and SSH protocols,
      I had difficulty managing the proper storage of public and private keys
      generated during encryption. I mimicked the format of a .pem file to
      store the keys, but effectively parsed those files as if they were .txt
      files, since I could not implement a way to sign the .pem certificates.
      This also meant that my current key storage mechanism is unsafe, and is
      acting primarily only as a string representation of the contents of a
      proper key file. Furthermore, generating a new key pair overwrites the
      previous pair by default, so there is no way in my current implementation
      to have two keys at the same time, or to identify one key from another.

    > Python classes. I learned about how Python classes work differently than
      other OOP languages, specifically in the realm of private and public
      methods, as well as how it treats static methods. I implemented my
      static methods with the @staticmethod flag, but wonder if it would have
      been cleaner/better to make a static "Utility" class from which to call
      those methods.

    > Efficiency. The general efficiency of my Keygen module is not ideal, such
      that scaling my RSA key size to 4096 bits has been made impossible. Again,
      working with such large numbers made clear how important it was to reduce
      unnecessary overhead.

    > Organizing code. This project drove home the importance of proper file
      management and documentation, if only due to the large number of elements
      working in tandem. I found that the more I documented, the easier it was
      to find something I needed, to refactor code or to debug a faulty function.

Future Extensions --------------------------------------------------------

    > Key format. Instead of essentially using a .pem file as a text file,
      I would implement a proper key padding and storage mechanism, in
      accordance with RSA standards. Different keys would be able to be securely
      stored and retrieved by the program as necessary.

    > Safe conversion. My current conversion method of text files into numeric
      values is unsafe. This was partially because I avoided using the rsa
      library, which provides methods to interpret bytes securely (Bodewes).
      I would find a way to integrate built-in libraries into my program while
      still using my own key generation module.

    > 4096 key size extension. I would revise the RSAKey class, with efficiency
      in mind, to be able to handle the creation of 4096 size keys within a
      reasonable timeframe.

Works Cited --------------------------------------------------------------

Bodewes, Maarten. "Convert plain text as numbers to encrypt using RSA," Stack
    Exchange. #42357. Forum post. https://crypto.stackexchange.com/a/42357.
    Accessed 20 Apr, 2022.

Boyd, Ian. "How to store/retrieve RSA public/private key." Stack Overflow.
    #12104466. Forum post. https://stackoverflow.com/a/13104466.
    Accessed 20 Apr, 2022.

Dickinson, Mark. "RSA - bitlength of p and q." Stack Overflow. #12195783.
    Forum post. https://stackoverflow.com/a/12195783. Accessed 14 Apr, 2022.

Lynn, Ben. "Primality Tests." PBC Library, Stanford Applied Cryptography Group.
    Web. https://crypto.stanford.edu/pbc/notes/numbertheory/millerrabin.html.
    Accessed 14 Apr, 2022.

Pornin, Thomas. "How many iterations of Rabin-Miller should I use for
    cryptographic safe primes?" Stack Overflow. #6330138. Forum post.
    https://stackoverflow.com/a/6330138. Accessed 15 Apr, 2022

"Euclidean algorithms (Basic and Extended)." GeeksforGeeks. Web.
    https://www.geeksforgeeks.org/euclidean-algorithms-basic-and-extended/.
    Accessed 15 Apr, 2022.

"Primality test." Crypto Wiki. DSZQUP XJLJ. Web.
    https://cryptography.fandom.com/wiki/Primality_test. Accessed 15 Apr, 2022

"Primality Test | Set 3 (Miller–Rabin)." GeeksforGeeks. Web.
    https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/.
    Accessed 14 Apr, 2022.