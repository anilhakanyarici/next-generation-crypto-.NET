# next-generation-crypto
ECDsa, ECDH and AES encryption solutions for .NET2.0, Mono and Unity.

This Project contains 2 cryptographic algorithms denote NextGenerationCryptography and 2 key derivation functions. One of the key derivation function is in accordance wih RFC2898, the other one is in accordance with NIST SP800-90A standart. 
            Usage of the Rfc2898KeyDeriver Class
Rfc2898KeyDeriver class only has one constructor for the determining key derivation parameters. That class inherited from System.Security.Cryptography.DeriveBytes.
Constructors :
Rfc2898KeyDeriver(byte[] password, ulong salt, int iterations, DerivationFunction function)
For generating pseudo-random key, Rfc2898KeyDeriver.GetBytes(int cb) must be called. The cb paremeter is the number of pseudo random key bytes to be generated. 
	Example:
byte[] password = Encoding.ASCII.GetBytes(“password”);
ulong salt = 28734871234;
iterations = 1000;
DerivationFunction function = DerivationFunction.PBKDF2;
Rfc2898KeyDeriver deriver = new Rfc2898KeyDeriver(password, salt, iterations, function);
byte[] key = deriver.GetBytes(32); //Generated 32 byte key. 
	(Note: DerivationFunction has two standart algorithms which PBKDF1 and PBKDF2. PBKDF2 is recommended by NIST.)
            Usage of the DRBytesGenerator Class (NIST SP800-90A)
	DRBytesGenerator has five constructors and each constructor denotes seed and entropy. Seed is a value used to generate a starting key for the random key sequence. Entropy denotes randomness of the key generation process. If value of entropy is zero, generation process will be entirely deterministic. (For more information about entropy see Information Theory.) Class inherited from System.Security.Cryptography.DeriveBytes.
	Constructors:
DRBytesGenerator(byte[] seedMaterial, int entropy)
DRBytesGenerator(string seedMaterial, int entropy)
DRBytesGenerator(byte[] seedMaterial) //Entropy is zero.
DRBytesGenerator(string seedMaterial) //Entropy is zero.
DRBytesGenerator() //Entropy is zero and random seed.
For generating pseudo-random key, DRBytesGenerator.GetBytes(int cb) must be called as Rfc2898KeyDeriver. The cb parameter is the number of pseudo random key bytes to generate. 
	Example:
string seed = “seed”;
int entropy = 32;
DRBytesGenerator deriver = new DRBytesGenerator(seed, entropy);
byte[] key = deriver.GetBytes(32);
	(Note: DRBytesGenerator is defined in FIPS 186-3 for the Oracle Random Model (ORM) used in Elliptic Curve Digital Signature Algorithm.)

    Usage of the AESCryptoServiceProvider Class
	AESCryptoServiceProvider provides the Advanced Encryption Standard symmetric algorithm. This provider supports five cipher modes and four padding modes. These are Cipher Block Chaining (CBC), Electronic Codebook (ECB), Output Feedback (OFB), Cipher Feedback (CFB) and Cipher Text Stealing (CTS) with ANSIX923 padding, PCKS7 padding, ISO10126 padding and Zero padding. In exceptional, Padding mode does not supported on the CTS mode. AESCryptoServiceProvider has only default constructor. Class inherited from System.Security.Cryptography.SymmetricAlgorithm.
	Lengths of AES key:
Provider supports 128, 192 and 256 bits length of the key. Choose your key and assign to AESCryptoServiceProvider.Key property. 
	Example:
byte[] password = Encoding.ASCII.GetBytes(“password”);
ulong salt = 28734871234;
iterations = 1000;
DerivationFunction function = DerivationFunction.PBKDF2;
Rfc2898KeyDeriver deriver = new Rfc2898KeyDeriver(password, salt, iterations, function);
AESCryptoServiceProvider aes = new AESCryptoServiceProvider();
aes.Mode = CipherMode.CBC; //Default cipher mode.
aes.Padding = PaddingMode.PCKS7; //Default padding mode.
aes.Key = deriver.GetBytes(16); //For 128bit AES.
aes.Key = deriver.GetBytes(24); //For 192bit AES.
aes.Key = deriver.GetBytes(32); //For 256bit AES.
aes.IV = deriver.GetBytes(16);
IV Length must be equal to block length and AES algorithm’s block length is 128 bit for each key. Now, we have an instance name “aes” for managing implementation of AES symmetric algorithm. 
Encryption process:
ICryptoTransform transform = aes.CreateEncryptor();
byte[] message = Encoding.ASCII.GetBytes(“message string”);
byte[] cipherText = transform.TransformFinalBlock(message, 0, message.Length);
Decryption process:
ICryptoTransform transform = aes.CreateDecryptor();
byte[] message = transform.TransformFinalBlock(cipherText, 0, cipherText.Length);
            Usage of the ECDSACryptoServiceProvider Class
	ECDSACryptoServiceProvider provides the Elliptic Curve Digital Signature Algorithm and Diffie-Hellman Key Exchange. Provider supports all of the GF(p) group curves. (Microsofts provider only supports SECP256R1, SECP384R1 and SECP521R1) ECDSACryptoServiceProvider has five constructors for choosing curve, setting private key and importing RFC4050 XML of public parameters. (For more information about RFC4050 see https://www.ietf.org/rfc/rfc4050.txt) Class inherited from System.Security.Cryptography.AsymmetricAlgorithm.
	Constructors:
ECDSACryptoServiceProvider(byte[] privateKey, CurveName name);
ECDSACryptoServiceProvider(byte[] privateKey); //Set default curve. (SECP256R1)
ECDSACryptoServiceProvider(CurveName name); //Random private key.
ECDSACryptoServiceProvider(string rfc4050xml);
ECDSACryptoServiceProvider(); //Random private key and set default curve. (SECP256R1)
	Parameters managing of ECDSACryptoServiceProvider:
You define private key during constraction of ECDSACryptoServiceProvider. Process creates public key according to define private key. We have 2 ways to access public key from the ECDSACryptoServiceProvider instance. One way is calling ECDSACryptoServiceProvider.To4050XmlString() method, other way is using ECDSACryptoServiceProvider.PublicKey property. ECDSACryptoServiceProvider.PublicKey is not an XML, it is just an encoded form of elliptic curve point of the public key and it uses generally during the Key Exchange progress.
	Example of KeyExchange:
ECDSACryptoServiceProvider alicesDsa = new ECDSACryptoServiceProvider(alicesPrivateKey);
byte[] alicesPublicKey = alicesDsa.PublicKey;
//Now, Alice send her public key to Bob.
ECDSACryptoServiceProvider bobsDsa = new ECDSACryptoServiceProvider(bobsPrivateKey);
byte[] bobsPublicKey = bobsDsa.PublicKey;
//Now, Bob send his public key to Alice.
byte[] alicesKey = alicesDsa.DeriveKeyMaterial(bobsPublicKey);
byte[] bobsKey = bobsDsa.DeriveKeyMaterial(alicesPublicKey);
At the end of this process, generated alicesKey and bobsKey and they are identical. From now on you can use DeriveBytes algorithm, such as RFC2898, for the generating symmetric algorithm key and IV. (If you can use ECDSACryptoServiceProvider.CreateKeyGenerator() instead of ECDSACryptoServiceProvider.DeriveKeyMaterial(), you have DeriveBytes instance easily.) 
	Signing data with ECDsa:
byte[] data = Encoding.ASCII.GetBytes(“some data”);
ECDSACryptoServiceProvider  dsa = new ECDSACryptoServiceProvider(CurveName.SECP521R1);
dsa.HashAlgorithm = SHA256.Create(); //Default hash algorithm.
byte[] hash = dsa.HashAlgorithm.ComputeHash(data);
byte[] signature = dsa.SignHash(hash);
//Or you can use byte[] signature = dsa.SignData(data); without computing hash.
	Verifying data with ECDsa:
string rfc4050xml = Encoding.ASCII.GetString(File.ReadAllBytes(“path\\publicDsa.xml”));
byte[] data = Encoding.ASCII.GetBytes(“some data”);
ECDSACryptoServiceProvider  dsa = new ECDSACryptoServiceProvider(rfc4050xml);
dsa.HashAlgorithm = SHA256.Create(); //Default hash algorithm.
byte[] hash = dsa.HashAlgorithm.ComputeHash(data);
bool isVerified = dsa.VerifyHash(hash, sign);
//Or you can use bool isVerified = dsa.VerifyData(data, sign); without computing hash.
            Elliptic Curve mathematical implementation details
Doing point addition and point doubling over the Jacobian Coordinates.
	Using windowed non-adjacent form multiplication for scalar multiplication without precomputes.
	Using Interleaving With non-adjacent form multiplication for the multiple point multiplication without precomputes.
	GFpGroupCurves class has also FixedBase Comb multiplication method. If you will compute the precomputes of FixedBase method and save this computes, you can sign any data very fast. 
