using System.Diagnostics;
namespace System.Security.Cryptography
{
    public class ECDSACryptoServiceProvider : AsymmetricAlgorithm, IDisposable
    {
        private GFpGroupCurves _curve;
        private HashAlgorithm _hashAlg;
        private byte[] _privateKey;
        private ECPoint _publicKey;
        private bool _disposed;

        public override string KeyExchangeAlgorithm
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException("ECDSACryptoServiceProvider");
                return "ECDiffieHellman";
            }
        }
        public override string SignatureAlgorithm
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException("ECDSACryptoServiceProvider");
                return "ECDsa";
            }
        }
        public HashAlgorithm HashAlgorithm
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException("ECDSACryptoServiceProvider");
                return this._hashAlg;
            }
            set
            {
                if (this._disposed)
                    throw new ObjectDisposedException("ECDSACryptoServiceProvider");
                this._hashAlg = value;
            }
        }
        public bool PublicOnly
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException("ECDSACryptoServiceProvider");
                return this._privateKey == null;
            }
        }
        public byte[] PublicKey
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException("ECDSACryptoServiceProvider");
                return this._curve.Encode(this._publicKey);
            }
        }
        public byte[] PrivateKey
        {
            get
            {
                if (this.PublicOnly)
                    throw new InvalidOperationException("Key not found.");
                return this._privateKey;
            }
        }
        public int SignatureSize
        {
            get
            {
                if (this.PublicOnly)
                    throw new InvalidOperationException("Key not found.");
                return (this._curve.BitLength << 1 + 7) >> 3;
            }
        }
        public CurveName CurveName
        {
            get
            {
                if (this.PublicOnly)
                    throw new InvalidOperationException("Key not found.");
                return this._curve.CurveName;
            }
        }

        public ECDSACryptoServiceProvider()
        {
            this._curve = GFpGroupCurves.FromName(CurveName.SECP256R1);
            int byteLength = (this._curve.BitLength + 7) >> 3;
            byte[] privateKey = RandomGenerator.GenerateBytes(byteLength - 1);

            this.ctor(privateKey, CurveName.SECP256R1);
        }
        public ECDSACryptoServiceProvider(string rfc4050xml)
        {
            if (rfc4050xml == null)
                throw new ArgumentNullException("rfc4050xml");
            try
            {
                string[] lines = rfc4050xml.Split('\n');
                string urn = lines[2];
                urn = urn.Split("\"".ToCharArray())[1];
                string x = lines[5];
                x = x.Split("\"".ToCharArray())[1];
                string y = lines[6];
                y = y.Split("\"".ToCharArray())[1];

                ECScalar X = ECScalar.Parse(x);
                ECScalar Y = ECScalar.Parse(y);
                GFpGroupCurves curve = GFpGroupCurves.FromURN(urn);
                ECPoint pk = new ECPoint(X, Y);
                this.HashAlgorithm = SHA256.Create();

                if (curve.ValidPoint(pk))
                {
                    this._curve = curve;
                    this.KeySizeValue = this._curve.BitLength;
                    this._publicKey = pk;
                    this._privateKey = null;
                }
                else
                    throw new CryptographicException("Invalid Public Key.");
            }
            catch (CryptographicException e) { throw e; }
            catch (ArgumentException e) { throw e; }
            catch (Exception) { throw new XmlSyntaxException(); }
        }
        public ECDSACryptoServiceProvider(CurveName name)
        {
            this._curve = GFpGroupCurves.FromName(name);
            int byteLength = (this._curve.BitLength + 7) >> 3;
            byte[] privateKey = RandomGenerator.GenerateBytes(byteLength - 1);

            this.ctor(privateKey, name);
        }
        public ECDSACryptoServiceProvider(byte[] privateKey)
        {
            this._curve = GFpGroupCurves.FromName(CurveName.SECP256R1);

            this.ctor(privateKey, CurveName.SECP256R1);
        }
        public ECDSACryptoServiceProvider(byte[] privateKey, CurveName name)
        {
            this._curve = GFpGroupCurves.FromName(name);

            this.ctor(privateKey, name);
        }

        private void ctor(byte[] privateKey, CurveName name)
        {
            if (privateKey == null)
                throw new ArgumentNullException("privateKey");
            if (privateKey.Length == 0)
                throw new ArgumentException("Invalid key length.", "privateKey");
            int byteLength = (this._curve.BitLength + 7) >> 3;
            if (byteLength - 1 < privateKey.Length)
                throw new ArgumentException("Length of private key must be less than " + byteLength + ".");

            this.HashAlgorithm = SHA256.Create();
            ECScalar pk = new ECScalar(privateKey, true, false);
            if (pk < 65536)
                throw new ArgumentException("Private key must be greater than 65535.");
            this._privateKey = privateKey;
            this.KeySizeValue = this._curve.BitLength;
            this._publicKey = this._curve.JacobianToAffine(this._curve.wNAFMultiplication(this._curve.G, pk, 4));
        }

        public byte[] SignData(byte[] data)
        {
            byte[] hash = this.HashAlgorithm.ComputeHash(data);
            return this.SignHash(hash);
        }
        public byte[] SignHash(byte[] hash)
        {
            if (this._disposed)
                throw new ObjectDisposedException("ECDSACryptoServiceProvider");
            if (this.PublicOnly)
                throw new InvalidOperationException("Key not found.");
            if (hash.Length != (this._hashAlg.HashSize + 7) >> 3)
                throw new CryptographicException("Invalid hash.");

            DRBytesGenerator byteDeriver = new DRBytesGenerator(hash, 32);
            int byteLen = (this._curve.BitLength + 7) >> 3;

            ECScalar e = new ECScalar(hash, true, false);
            ECScalar r = ECScalar.Zero;
            ECScalar k = ECScalar.Zero;
            ECScalar invK = ECScalar.Zero, s = ECScalar.Zero;
            ECPoint m = this._curve.Infinity;

            ECScalar d = new ECScalar(this._privateKey, true, false);

            while (s.IsZero)
            {
                while (invK.IsZero)
                {
                    while (m.X.IsZero)
                    {
                        k = new ECScalar(byteDeriver.GetBytes(byteLen - 1), true, false);
                        m = this._curve.wNAFMultiplication(this._curve.G, k, 4);
                    }
                    invK = ECScalar.ModInverse(k, this._curve.N);
                }
                m = this._curve.JacobianToAffine(m);
                s = (invK * (e + m.X * d)) % this._curve.N;
            }
            r = m.X % this._curve.N;
            byte[] rsPair = new byte[byteLen * 2];
            byte[] randBytes = r.GetUnsignedBytes(true);
            byte[] signBytes = s.GetUnsignedBytes(true);

            Array.Copy(randBytes, 0, rsPair, byteLen - randBytes.Length, randBytes.Length);
            Array.Copy(signBytes, 0, rsPair, rsPair.Length - signBytes.Length, signBytes.Length);

            return rsPair;
        }
        public bool VerifyData(byte[] data, byte[] sign)
        {
            byte[] hash = this.HashAlgorithm.ComputeHash(data);
            return this.VerifyHash(hash, sign);
        }
        public bool VerifyHash(byte[] hash, byte[] sign)
        {
            if (this._disposed)
                throw new ObjectDisposedException("ECDSACryptoServiceProvider");
            if (hash.Length != (this._hashAlg.HashSize + 7) >> 3)
                throw new CryptographicException("Invalid hash.");

            ECScalar e = new ECScalar(hash, true, false);

            int pairLength = (this._curve.BitLength + 7) >> 3;
            if (sign.Length != pairLength * 2)
                return false;

            byte[] randBytes = new byte[pairLength];
            byte[] signBytes = new byte[pairLength];

            Array.Copy(sign, 0, randBytes, 0, pairLength);
            Array.Copy(sign, pairLength, signBytes, 0, pairLength);

            ECScalar r = new ECScalar(randBytes, true, false);
            ECScalar s = new ECScalar(signBytes, true, false);
            if (s.IsZero || r.IsZero)
                return false;

            ECScalar w = ECScalar.ModInverse(s, this._curve.N);
            ECScalar u1 = (e * w) % this._curve.N;
            ECScalar u2 = (r * w) % this._curve.N;

            ECPoint ss = this._curve.InterleavingWithwNAF(u1, this._curve.G, 4, u2, this._publicKey, 4);
            ss = this._curve.JacobianToAffine(ss);
            ECScalar v = ss.X % this._curve.N;

            bool verified = v.Equals(r);
            return verified;
        }
        public byte[] DeriveKeyMaterial(byte[] otherPublicKey)
        {
            if (this._disposed)
                throw new ObjectDisposedException("ECDSACryptoServiceProvider");

            if (this.PublicOnly)
                throw new InvalidOperationException("Key not found.");

            int blockLen = otherPublicKey.Length >> 1;

            ECPoint publicKey = this._curve.Decode(otherPublicKey);
            ECScalar privateKey = new ECScalar(this._privateKey, true, false);

            ECPoint keyMaterial = this._curve.JacobianToAffine(this._curve.wNAFMultiplication(publicKey, privateKey, 4));

            byte[] keyBlock = new byte[blockLen];
            byte[] key = (keyMaterial.X % this._curve.N).GetUnsignedBytes(true);
            Array.Copy(key, 0, keyBlock, 0, key.Length);
            return keyBlock;
        }
        public DeriveBytes CreateKeyGenerator(byte[] otherPublicKey, ulong salt, DerivationFunction function)
        {
            return new Rfc2898KeyDeriver(this.DeriveKeyMaterial(otherPublicKey), salt, 1000, function);
        }
        public DeriveBytes CreateKeyGenerator(byte[] otherPublicKey, ulong salt, int iteration, DerivationFunction function)
        {
            return new Rfc2898KeyDeriver(this.DeriveKeyMaterial(otherPublicKey), salt, iteration, function);
        }
        public override void FromXmlString(string xmlString)
        {
            throw new NotSupportedException("Use From4050XmlString() method.");
        }
        public override string ToXmlString(bool includePrivateParameters)
        {
            throw new NotSupportedException("Use To4050XmlString() method.");
        }
        public string To4050XmlString()
        {
            if (this._disposed)
                throw new ObjectDisposedException("ECDSACryptoServiceProvider");

            if (!this._publicKey.Z.IsOne)
                this._publicKey = this._curve.JacobianToAffine(this._publicKey);
            string xml =
                "<ECDSAKeyValue xmlns=\"http://www.w3.org/2001/04/xmldsig-more#\">\n"
              + "  <DomainParameters>\n"
              + "    <NamedCurve URN=\"" + this._curve.URN + "\" />\n"
              + "  </DomainParameters>\n"
              + "  <PublicKey>\n"
              + "    <X Value=\"" + this._publicKey.X.ToString() + "\" xsi:type=\"PrimeFieldElemType\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" />\n"
              + "    <Y Value=\"" + this._publicKey.Y.ToString() + "\" xsi:type=\"PrimeFieldElemType\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" />\n"
              + "  </PublicKey>\n"
              + "</ECDSAKeyValue>";
            return xml;
        }
        public void From4050XmlString(string xml)
        {
            if (this._disposed)
                throw new ObjectDisposedException("ECDSACryptoServiceProvider");
            if (xml == null)
                throw new ArgumentNullException("xml");
            try
            {
                string[] lines = xml.Split('\n');
                string urn = lines[2];
                urn = urn.Split("\"".ToCharArray())[1];
                string x = lines[5];
                x = x.Split("\"".ToCharArray())[1];
                string y = lines[6];
                y = y.Split("\"".ToCharArray())[1];

                ECScalar X = ECScalar.Parse(x);
                ECScalar Y = ECScalar.Parse(y);
                GFpGroupCurves curve = GFpGroupCurves.FromURN(urn);
                ECPoint pk = new ECPoint(X, Y);
                if (curve.ValidPoint(pk))
                {
                    this._curve = curve;
                    this.KeySizeValue = this._curve.BitLength;
                    this._publicKey = pk;
                    this._privateKey = null;
                }
                else
                    throw new CryptographicException("Geçersiz açık anahtar.");
            }
            catch (CryptographicException e) { throw e; }
            catch (ArgumentException e) { throw e; }
            catch (Exception) { throw new XmlSyntaxException(); }
        }

        protected override void Dispose(bool disposing)
        {
            if (this._disposed)
                throw new ObjectDisposedException("ECDSACryptoServiceProvider");

            if (disposing)
            {
                this._privateKey = null;
                this._curve = null;
                this._publicKey = null;
                this._disposed = true;
            }
        }

        internal static void ECDSAStressTest(CurveName curve, bool stopIfNotVerified)
        {
            int i = 0;
            ECDSACryptoServiceProvider dsa = new ECDSACryptoServiceProvider(curve);
            while (true)
            {
                i++;
                byte[] m = RandomGenerator.GenerateBytes(32);
                Stopwatch sw = Stopwatch.StartNew();
                byte[] s = dsa.SignData(m);
                Console.Write("SignatureTime: " + ((1000000 * sw.ElapsedTicks) / Stopwatch.Frequency).ToString("00000") + "us " + s.Length);
                sw.Reset();
                sw.Start();
                bool v = dsa.VerifyData(m, s);
                Console.WriteLine(" VerifyTime: " + ((1000000 * sw.ElapsedTicks) / Stopwatch.Frequency).ToString("00000") + "us " + i.ToString("0000") + " " + v);
                if (!v && stopIfNotVerified)
                    break;
            }
        }
    }
}
