
namespace System.Security.Cryptography
{
    public enum CurveName { SECP112R1, SECP112R2, SECP128R1, SECP128R2, SECP160K1, SECP160R1, SECP160R2, SECP192K1, SECP192R1, SECP224K1, SECP224R1, SECP256K1, SECP256R1, SECP384R1, SECP521R1 }
    internal abstract class GFpGroupCurves
    {
        public ECScalar A { get; protected set; }
        public ECScalar B { get; protected set; }
        public ECScalar P { get; protected set; }
        public ECScalar N { get; protected set; }
        public ECScalar H { get; protected set; }
        public ECPoint G { get; protected set; }
        public virtual CurveName CurveName { get; protected set; }
        public virtual string URN { get { return null; } }
        public int BitLength { get; protected set; }
        public ECPoint Infinity { get { return new ECPoint(); } }

        public virtual bool ValidPoint(ECPoint point)
        {
            if (!point.Z.IsOne)
                point = this.JacobianToAffine(point);
            return ECScalar.Square(point.Y) % this.P == (point.X * ECScalar.Square(point.X) + this.A * point.X + this.B) % this.P;
        }

        protected internal ECPoint DoubleAndAdd(ECPoint P, ECPoint Q) //17M + 10S
        {
            P = this.JacobianDoubling(P);
            return this.JacobianAddition(P, Q);
        }

        protected internal ECPoint AffineDoubling(ECPoint P)
        {
            if (P.Y.IsZero)
                return this.Infinity;

            ECScalar px2 = ECScalar.Square(P.X);
            ECScalar px2c = px2.Copy();
            px2.LeftShift(1);
            px2 += px2c + this.A;

            ECScalar m = ((px2) * ECScalar.ModInverse((P.Y << 1), this.P)) % this.P;
            ECScalar X = (ECScalar.Square(m) - (P.X << 1)) % this.P;
            ECScalar Y = (m * (P.X - X) - P.Y) % this.P;
            if (X.IsNegative)
                X += this.P;
            if (Y.IsNegative)
                Y += this.P;
            return new ECPoint(X, Y);
        }
        protected internal ECPoint AffineAddition(ECPoint P, ECPoint Q)
        {
            if (P.IsZero)
                return Q;
            if (Q.IsZero)
                return P;

            ECScalar den = Q.X - P.X;
            ECScalar num = Q.Y - P.Y;
            if (den.IsZero)
            {
                if (num.IsZero)
                    this.AffineDoubling(P);
                return this.Infinity;
            }
            if (den.Sign == -1)
                den += this.P;

            ECScalar m = (num * ECScalar.ModInverse(den, this.P)) % this.P;
            ECScalar X = (ECScalar.Square(m) - (P.X + Q.X)) % this.P;
            ECScalar Y = (m * (P.X - X) - P.Y) % this.P;

            if (X.IsNegative)
                X += this.P;
            if (Y.IsNegative)
                Y += this.P;

            return new ECPoint(X, Y);
        }
        protected internal ECPoint JacobianDoubling(ECPoint P) //4M + 6S //A = -3 => 4M + 5S //A = 0 => 4M + 4S
        {
            if (P.Y.IsZero)
                return this.Infinity;

            ECScalar X = P.X, Y = P.Y, Z = P.Z;
            ECScalar N;

            if (this.A.IsZero)
            {
                N = this.Modulo(3 * X * X);
            }
            else if (this.A.Sign == -1 && this.A.DigitsLength == 1 && this.A.FirstDigit == 3)
            {
                ECScalar Z2 = this.Modulo(Z * Z);
                N = this.Modulo(3 * (X + Z2) * (X - Z2));
            }
            else
            {
                ECScalar Z4 = this.Modulo(ECScalar.Square(this.Modulo(Z * Z)));
                N = this.Modulo(3 * X * X + this.A * Z4);
            }

            ECScalar Y2 = this.Modulo(Y * Y), T = this.Modulo(X * (Y2 << 2));

            ECScalar Xr = this.Modulo(N * N - (T << 1));
            ECScalar Yr = this.Modulo(N * (T - Xr) - ((Y2 << 3) * Y2));
            ECScalar Zr = this.Modulo(Y * (Z << 1));

            if (Xr.IsNegative)
                Xr += this.P;
            if (Yr.IsNegative)
                Yr += this.P;
            if (Zr.IsNegative)
                Zr += this.P;

            return new ECPoint(Xr, Yr, Zr);
        }
        protected internal ECPoint JacobianAddition(ECPoint P, ECPoint Q) //13M + 4S
        {
            if (P.IsZero)
                return Q;
            if (Q.IsZero)
                return P;

            ECScalar Xp = P.X, Yp = P.Y, Zp = P.Z, Zp2 = this.Modulo(Zp * Zp), Zp3 = this.Modulo(Zp2 * Zp);// % this.P;
            ECScalar Xq = Q.X, Yq = Q.Y, Zq = Q.Z, Zq2 = this.Modulo(Zq * Zq), Zq3 = this.Modulo(Zq2 * Zq);// % this.P;
            ECScalar Xt = this.Modulo(Xq * Zp2), Xg = this.Modulo(Xp * Zq2), YPZQ3 = this.Modulo(Yp * Zq3);// % this.P;

            ECScalar D = Xg - Xt, N = (YPZQ3 - Yq * Zp3) % this.P;

            if (D.IsZero)
            {
                if (N.IsZero)
                    return this.JacobianDoubling(P);
                return this.Infinity;
            }

            ECScalar D2 = this.Modulo(D * D);

            ECScalar Xr = this.Modulo(N * N - (Xg + Xt) * D2);
            ECScalar Yr = this.Modulo(N * (this.Modulo(Xg * D2 - Xr)) - (this.Modulo(YPZQ3 * D2) * D));
            ECScalar Zr = this.Modulo(this.Modulo(Zp * Zq) * D);

            if (Xr.IsNegative)
                Xr += this.P;
            if (Yr.IsNegative)
                Yr += this.P;
            if (Zr.IsNegative)
                Zr += this.P;

            return new ECPoint(Xr, Yr, Zr);
        }
        protected internal ECPoint ModifiedJacobianDoubling(ECPoint P, ref ECScalar aZ4)
        {
            if (P.Y.IsZero)
            {
                aZ4 = ECScalar.One;
                return this.Infinity;
            }

            ECScalar X = P.X, Y = P.Y, Z = P.Z;
            ECScalar N = this.Modulo((3 * X * X) + aZ4);

            ECScalar Y2 = this.Modulo(Y * Y), Y4 = this.Modulo(Y2 * Y2), T = this.Modulo(X * (Y2 << 2));

            ECScalar Xr = this.Modulo(N * N - (T << 1));
            ECScalar Yr = this.Modulo((N * (T - Xr) - (Y4 << 3)));
            ECScalar Zr = this.Modulo(Y * (Z << 1));

            if (!aZ4.IsZero)
                aZ4 = this.Modulo(16 * Y4 * aZ4);

            if (Xr.IsNegative)
                Xr += this.P;
            if (Yr.IsNegative)
                Yr += this.P;
            if (Zr.IsNegative)
                Zr += this.P;

            return new ECPoint(Xr, Yr, Zr);
        }

        protected internal ECPoint BinaryMultiplication(ECPoint point, ECScalar d)
        {
            d %= this.N;
            if (d.IsZero)
                return this.Infinity;
            else if (d.IsOne)
                return point;
            ECPoint res;
            int bit = d.GetBit(0);
            if (bit == 1)
                res = point;
            else
                res = this.Infinity;
            int bitLength = (int)d.BitsLength;
            for (int i = 1; i < bitLength; i++)
            {
                point = this.JacobianDoubling(point);
                bit = d.GetBit(i);
                if (bit == 1)
                    res = this.JacobianAddition(point, res);
            }
            return res;
        }
        protected internal ECPoint wNAFMultiplication(ECPoint point, ECScalar d, int w)
        {
            d %= this.N;
            if (d.IsZero)
                return this.Infinity;
            else if (d.IsOne)
                return point;
            else if (d.FirstDigit == 2 && d.DigitsLength == 1)
                return this.JacobianDoubling(point);
            else if (d.FirstDigit == 2 && d.DigitsLength == 1)
                return this.JacobianDoubling(point);

            int[] naf = d.NonAdjacentForm(w);
            ECPoint[] preCompPoints = this.PointPrecomputationsForNAF(point, w);

            ECPoint Q = this.Infinity;
            for (int i = naf.Length - 1; i >= 0; i--)
            {
                Q = this.JacobianDoubling(Q);
                int nafBit = naf[i];
                if (nafBit > 0)
                    Q = this.JacobianAddition(preCompPoints[nafBit], Q);
                else if (nafBit < 0)
                    Q = this.JacobianAddition(preCompPoints[-nafBit - 1], Q);
            }
            return Q;
        }
        protected internal ECPoint FixedBaseMultiplication(ECPoint P, ECScalar k, int w)
        {
            int bitLen = (int)this.BitLength;
            int d = (bitLen + w - 1) / w;
            ECPoint[] preComputes = this.FixedPointCombPreComputes(P, w);

            return this.FixedBaseMultiplication(preComputes, k, w);
        }
        protected internal ECPoint FixedBaseMultiplication(ECPoint[] preComputes, ECScalar k, int w)
        {
            int bitLen = this.BitLength;
            int d = (bitLen + w - 1) / w;

            ECPoint mul = this.Infinity;

            int t = d * w - 1;
            for (int i = 0; i < d; ++i)
            {
                int preCompIndex = 0;
                for (int j = t - i; j > -1; j -= d)
                {
                    preCompIndex <<= 1;
                    preCompIndex |= k.GetBit(j);
                }
                mul = this.DoubleAndAdd(mul, preComputes[preCompIndex]);
            }
            return mul;
        }

        protected internal ECPoint ShamirsTrick(ECScalar u1, ECPoint G, ECScalar u2, ECPoint D)
        {
            u1 %= this.N;
            u2 %= this.N;

            int u1BitLen = (int)u1.BitsLength;
            int u2BitLen = (int)u2.BitsLength;
            int bitLen = u1BitLen < u2BitLen ? u2BitLen : u1BitLen;

            ECPoint GD = this.JacobianAddition(G, D);

            ECPoint res = this.Infinity;

            for (int i = bitLen - 1; i > 0; i--)
            {
                int bits = u1.GetBit(i) << 1;
                bits |= u2.GetBit(i);

                if (bits == 2)
                    res = this.JacobianAddition(G, res);
                else if (bits == 1)
                    res = this.JacobianAddition(D, res);
                else if (bits == 3)
                    res = this.JacobianAddition(GD, res);
                res = this.JacobianDoubling(res);
            }
            {
                int bits = u1.GetBit(0) << 1;
                bits |= u2.GetBit(0);

                if (bits == 2)
                    res = this.JacobianAddition(G, res);
                else if (bits == 1)
                    res = this.JacobianAddition(D, res);
                else if (bits == 3)
                    res = this.JacobianAddition(GD, res);
            }
            return res;
        }
        protected internal ECPoint InterleavingWithNAF(ECScalar u1, ECPoint G, ECScalar u2, ECPoint D)
        {
            u1 %= this.N;
            u2 %= this.N;

            if (u1.BitsLength < u2.BitsLength)
            {
                ECScalar tempB = u2;
                u2 = u1;
                u1 = tempB;
                ECPoint tempEC = D;
                D = G;
                G = tempEC;
            }

            ECPoint nG = this.Negate(G);
            ECPoint nD = this.Negate(D);
            ECPoint GD = this.JacobianAddition(G, D);
            ECPoint nGD = this.Negate(GD);
            ECPoint GminD = this.JacobianAddition(G, nD);
            ECPoint DminG = this.Negate(GminD);

            int[] u1Naf = u1.NonAdjacentForm(2);
            int[] u2Naf = u2.NonAdjacentForm(2);

            ECPoint res = this.Infinity;

            for (int i = u1Naf.Length - 1; i > -1; i--)
            {
                res = this.JacobianDoubling(res);

                int minBit = 0, maxBit = u1Naf[i];
                if (i < u2Naf.Length)
                    minBit = u2Naf[i];
                if (minBit == -1)
                {
                    if (maxBit == -1)
                        res = this.JacobianAddition(nGD, res);
                    else if (maxBit == 1)
                        res = this.JacobianAddition(GminD, res);
                    else
                        res = this.JacobianAddition(nD, res);
                }
                else if (minBit == 0)
                {
                    if (maxBit == -1)
                        res = this.JacobianAddition(nG, res);
                    else if (maxBit == 1)
                        res = this.JacobianAddition(G, res);
                }
                else if (minBit == 1)
                {
                    if (maxBit == -1)
                        res = this.JacobianAddition(DminG, res);
                    else if (maxBit == 1)
                        res = this.JacobianAddition(GD, res);
                    else
                        res = this.JacobianAddition(D, res);
                }
            }
            return res;
        }
        protected internal ECPoint InterleavingWithwNAF(ECScalar u1, ECPoint G, int w1, ECScalar u2, ECPoint D, int w2)
        {
            u1 %= this.N;
            u2 %= this.N;

            if (u1.BitsLength < u2.BitsLength)
            {
                ECScalar tempB = u2;
                u2 = u1;
                u1 = tempB;
                ECPoint tempEC = D;
                D = G;
                G = tempEC;
            }

            int[] u1Naf = u1.NonAdjacentForm(w1);
            int[] u2Naf = u2.NonAdjacentForm(w2);

            ECPoint[] u1PreComputes = this.PointPrecomputationsForNAF(G, w1);
            ECPoint[] u2PreComputes = this.PointPrecomputationsForNAF(D, w2);

            return this.InterleavingWithwNAF(u1Naf, u1PreComputes, u2Naf, u2PreComputes);
        }
        protected internal ECPoint InterleavingWithwNAF(int[] u1Naf, ECPoint[] precomputesOfG, int[] u2Naf, ECPoint[] precomputesOfD)
        {
            ECPoint res = this.Infinity;

            for (int i = u1Naf.Length - 1; i >= u2Naf.Length; i--)
            {
                int maxBit = u1Naf[i];
                if (maxBit == 0)
                    res = this.JacobianDoubling(res);
                else
                    if (maxBit > 0)
                        res = this.DoubleAndAdd(res, precomputesOfG[maxBit]);
                    else
                        res = this.DoubleAndAdd(res, precomputesOfG[-maxBit - 1]);
            }
            for (int i = u2Naf.Length - 1; i > -1; i--)
            {
                bool added = false;
                ECPoint adder = this.Infinity;
                int minBit = u2Naf[i], maxBit = u1Naf[i];
                if (minBit != 0)
                {
                    if (minBit > 0)
                        adder = precomputesOfD[minBit];
                    else
                        adder = precomputesOfD[-minBit - 1];
                    added = true;
                }
                if (maxBit != 0)
                {
                    if (maxBit > 0)
                        adder = this.JacobianAddition(adder, precomputesOfG[maxBit]);
                    else
                        adder = this.JacobianAddition(adder, precomputesOfG[-maxBit - 1]);
                    added = true;
                }
                if (added)
                    res = this.DoubleAndAdd(res, adder);
                else
                    res = this.JacobianDoubling(res);
            }
            return res;
        }

        protected internal ECScalar Calculate_aZ4(ECPoint P)
        {
            return this.A * ECScalar.Square(P.Z * P.Z % this.P) % this.P;
        }
        protected internal ECPoint[] PointPrecomputationsForNAF(ECPoint point, int w)
        {
            int preCompCount = 1 << (w - 2);
            ECPoint[] preCompPoints = new ECPoint[preCompCount * 2];
            preCompPoints[1] = point;
            preCompPoints[0] = this.Negate(point);
            for (int i = 1; i < preCompCount; i++)
            {
                int bit = 2 * i + 1;
                ECPoint P = this.BinaryMultiplication(point, (ECScalar)bit);
                preCompPoints[bit] = P;
                preCompPoints[bit - 1] = this.Negate(P);
            }
            return preCompPoints;
        }
        protected internal ECPoint[] FixedPointCombPreComputes(ECPoint point, int w)
        {
            int n = 1 << w;

            int bits = (int)this.P.BitsLength;

            int bitLen = this.BitLength;
            int d = (bitLen + w - 1) / w;
            ECPoint[] twoPowNList = new ECPoint[w];
            twoPowNList[0] = point;
            for (int i = 1; i < w; ++i)
            {
                ECPoint Q = twoPowNList[i - 1];
                for (int j = 0; j < d; j++)
                    Q = this.JacobianDoubling(Q);
                twoPowNList[i] = Q;
            }

            ECPoint[] preComputes = new ECPoint[n];
            preComputes[0] = this.Infinity;

            for (int bit = w - 1; bit > -1; bit--)
            {
                ECPoint pow2 = twoPowNList[bit];

                int adderIndex = 1 << bit;
                int i = adderIndex;
                while (i < n)
                {
                    preComputes[i] = this.JacobianAddition(preComputes[i - adderIndex], pow2);
                    i += (adderIndex << 1);
                }
            }
            return preComputes;
        }

        protected virtual ECScalar Modulo(ECScalar value)
        {
            return ECScalar.Remainder(value, this.P);
        }

        public ECPoint Negate(ECPoint R)
        {
            ECScalar Y = this.P - R.Y;
            return new ECPoint(R.X, Y, R.Z);
        }
        public ECPoint JacobianToAffine(ECPoint point)
        {
            ECScalar invZ = ECScalar.ModInverse(point.Z, this.P), invZ2 = (invZ * invZ) % this.P, invZ3 = (invZ2 * invZ) % this.P;

            ECScalar X = point.X * invZ2 % this.P;
            ECScalar Y = point.Y * invZ3 % this.P;
            return new ECPoint(X, Y, 1);
        }
        public byte[] Encode(ECPoint P)
        {
            int pairLength = (this.BitLength + 7) >> 3;
            P = this.JacobianToAffine(P);
            ECScalar x = P.X;
            ECScalar y = P.Y;

            byte[] xyPair = new byte[pairLength * 2];
            byte[] xBytes = x.GetUnsignedBytes(true);
            byte[] yBytes = y.GetUnsignedBytes(true);

            Array.Copy(xBytes, 0, xyPair, pairLength - xBytes.Length, xBytes.Length);
            Array.Copy(yBytes, 0, xyPair, xyPair.Length - yBytes.Length, yBytes.Length);
            return xyPair;
        }
        public ECPoint Decode(byte[] bytes)
        {
            int pairLen = (this.BitLength + 7) >> 3;

            byte[] xBytes = new byte[pairLen];
            byte[] yBytes = new byte[pairLen];

            Array.Copy(bytes, 0, xBytes, 0, pairLen);
            Array.Copy(bytes, pairLen, yBytes, 0, pairLen);

            ECScalar x = new ECScalar(xBytes, true, false);
            ECScalar y = new ECScalar(yBytes, true, false);

            return new ECPoint(x, y);
        }

        public static GFpGroupCurves FromURN(string urn)
        {
            if (urn == "urn:oid:1.3.132.0.6")
                return new SECP112R1();
            if (urn == "urn:oid:1.3.132.0.7")
                return new SECP112R2();
            if (urn == "urn:oid:1.3.132.0.28")
                return new SECP128R1();
            if (urn == "urn:oid:1.3.132.0.29")
                return new SECP128R2();
            if (urn == "urn:oid:1.3.132.0.9")
                return new SECP160K1();
            if (urn == "urn:oid:1.3.132.0.8")
                return new SECP160R1();
            if (urn == "urn:oid:1.3.132.0.30")
                return new SECP160R2();
            if (urn == "urn:oid:1.3.132.0.31")
                return new SECP192K1();
            if (urn == "urn:oid:1.2.840.10045.3.1.1")
                return new SECP192R1();
            if (urn == "urn:oid:1.3.132.0.32")
                return new SECP224K1();
            if (urn == "urn:oid:1.3.132.0.33")
                return new SECP224R1();
            if (urn == "urn:oid:1.3.132.0.10")
                return new SECP256K1();
            if (urn == "urn:oid:1.2.840.10045.3.1.7")
                return new SECP256R1();
            if (urn == "urn:oid:1.3.132.0.34")
                return new SECP384R1();
            if (urn == "urn:oid:1.3.132.0.35")
                return new SECP521R1();

            throw new ArgumentException("Unknown Elliptic Curve.");
        }
        public static GFpGroupCurves FromName(CurveName name)
        {
            switch (name)
            {
                case CurveName.SECP112R1:
                    return new SECP112R1();
                case CurveName.SECP112R2:
                    return new SECP112R2();
                case CurveName.SECP128R1:
                    return new SECP128R1();
                case CurveName.SECP128R2:
                    return new SECP128R2();
                case CurveName.SECP160K1:
                    return new SECP160K1();
                case CurveName.SECP160R1:
                    return new SECP160R1();
                case CurveName.SECP160R2:
                    return new SECP160R2();
                case CurveName.SECP192K1:
                    return new SECP192K1();
                case CurveName.SECP192R1:
                    return new SECP192R1();
                case CurveName.SECP224K1:
                    return new SECP224K1();
                case CurveName.SECP224R1:
                    return new SECP224R1();
                case CurveName.SECP256K1:
                    return new SECP256K1();
                case CurveName.SECP256R1:
                    return new SECP256R1();
                case CurveName.SECP384R1:
                    return new SECP384R1();
                case CurveName.SECP521R1:
                    return new SECP521R1();
                default:
                    throw new ArgumentException("Unknown Elliptic Curve.");
            }
        }
    }
    internal class ECPoint : ICloneable
    {
        public ECScalar X;
        public ECScalar Y;
        public ECScalar Z;

        public bool IsZero { get { return this.X.IsZero && this.Y.IsZero; } }

        public ECPoint()
        {
            this.X = ECScalar.Zero;
            this.Y = ECScalar.Zero;
            this.Z = ECScalar.One;
        }
        public ECPoint(ECScalar x, ECScalar y)
        {
            this.X = x;
            this.Y = y;
            this.Z = ECScalar.One;
        }
        public ECPoint(ECScalar x, ECScalar y, ECScalar z)
        {
            this.X = x;
            this.Y = y;
            this.Z = z;
        }

        public override string ToString()
        {
            return "(" + this.X.ToString() + ", " + this.Y.ToString() + ")";
        }

        public object Clone()
        {
            return new ECPoint(this.X, this.Y, this.Z);
        }
    }

    internal class ECScalar
    {
        private uint[] _digits;
        private int _digitLength;
        private int _sign;

        internal uint[] digitsRef { get { return this._digits; } }

        public static ECScalar Zero { get { return new ECScalar(); } }
        public static ECScalar One { get { return new ECScalar { _digitLength = 1, _digits = new uint[] { 1 }, _sign = 1 }; } }

        public int BytesLength { get { return ECNumInternalOp.SignedBytesLength(this._digits, this._digitLength, this._sign); } }
        public long BitsLength { get { return ECNumInternalOp.SignedBitsLength(this._digits, this._digitLength, this._sign); } }
        public int DigitsLength { get { return this._digitLength; } }
        public int Sign { get { return this._sign; } }
        public bool IsEven { get { return (this._digits[0] & 1) == 0; } }
        public bool IsOdd { get { return (this._digits[0] & 1) == 1; } }
        public bool IsZero { get { return this._sign == 0; } }
        public bool IsOne { get { return this._digitLength == 1 && this._digits[0] == 1 && this._sign == 1; } }
        public bool IsNegative { get { return this._sign == -1; } }
        public uint FirstDigit { get { return this._digits[0]; } }

        public ECScalar()
        {
            this._digits = new uint[1];
            this._digitLength = 1;
            this._sign = 0;
        }
        public ECScalar(sbyte value)
        {
            if (value == 0)
            {
                this._sign = 0;
                this._digitLength = 1;
                this._digits = new uint[1];
            }
            else if (value < 0)
            {
                this._sign = -1;
                this._digitLength = 1;
                this._digits = new uint[1] { (byte)(-value) };
            }
            else
            {
                this._sign = 1;
                this._digitLength = 1;
                this._digits = new uint[1] { (byte)value };
            }
        }
        public ECScalar(byte value)
        {
            if (value == 0)
            {
                this._sign = 0;
                this._digitLength = 1;
                this._digits = new uint[1];
            }
            else
            {
                this._sign = 1;
                this._digitLength = 1;
                this._digits = new uint[1] { value };
            }
        }
        public ECScalar(short value)
        {
            if (value == 0)
            {
                this._sign = 0;
                this._digitLength = 1;
                this._digits = new uint[1];
            }
            else if (value < 0)
            {
                this._sign = -1;
                this._digitLength = 1;
                this._digits = new uint[1] { (ushort)(-value) };
            }
            else
            {
                this._sign = 1;
                this._digitLength = 1;
                this._digits = new uint[1] { (ushort)value };
            }
        }
        public ECScalar(ushort value)
        {
            if (value == 0)
            {
                this._sign = 0;
                this._digitLength = 1;
                this._digits = new uint[1];
            }
            else
            {
                this._sign = 1;
                this._digitLength = 1;
                this._digits = new uint[1] { value };
            }
        }
        public ECScalar(int value)
        {
            if (value == 0)
            {
                this._sign = 0;
                this._digitLength = 1;
                this._digits = new uint[1];
            }
            else if (value < 0)
            {
                this._sign = -1;
                this._digitLength = 1;
                this._digits = new uint[1] { (uint)(-value) };
            }
            else
            {
                this._sign = 1;
                this._digitLength = 1;
                this._digits = new uint[1] { (uint)value };
            }
        }
        public ECScalar(uint value)
        {
            if (value == 0)
            {
                this._sign = 0;
                this._digitLength = 1;
                this._digits = new uint[1];
            }
            else
            {
                this._sign = 1;
                this._digitLength = 1;
                this._digits = new uint[1] { value };
            }
        }
        public ECScalar(long value)
        {
            if (value == 0)
            {
                this._sign = 0;
                this._digitLength = 1;
                this._digits = new uint[1];
            }
            else if (value < 0)
            {
                this._sign = -1;
                ulong uVal = (ulong)-value;
                this._digits = new uint[2] { (uint)uVal, (uint)(uVal >> 32) };
                if (this._digits[1] == 0)
                    this._digitLength = 1;
                else
                    this._digitLength = 2;
            }
            else
            {
                this._sign = 1;
                ulong uVal = (ulong)value;
                this._digits = new uint[2] { (uint)uVal, (uint)(uVal >> 32) };
                if (this._digits[1] == 0)
                    this._digitLength = 1;
                else
                    this._digitLength = 2;
            }
        }
        public ECScalar(ulong value)
        {
            if (value == 0)
            {
                this._sign = 0;
                this._digitLength = 1;
                this._digits = new uint[1];
            }
            else
            {
                this._sign = 1;
                this._digits = new uint[2] { (uint)value, (uint)(value >> 32) };
                if (this._digits[1] == 0)
                    this._digitLength = 1;
                else
                    this._digitLength = 2;
            }
        }
        public ECScalar(byte[] bytes, bool bigEndian, bool isSignedBytes)
        {
            if (isSignedBytes)
                this._digits = ECNumInternalOp.FromSignedBytes(bytes, bigEndian, out this._digitLength, out this._sign);
            else
            {
                this._digits = ECNumInternalOp.FromUnsignedBytes(bytes, bigEndian, out this._digitLength);
                this._sign = this._digitLength == 1 && this._digits[0] == 0 ? 0 : 1;
            }
        }
        public ECScalar(uint[] digits, int sign)
        {
            int digitLength = digits.Length;

            while (digitLength > 1 && digits[digitLength - 1] == 0)
                digitLength--;

            if (digitLength == 0)
            {
                this._sign = 0;
                this._digits = new uint[1];
                this._digitLength = 1;
            }
            else
            {
                this._digits = new uint[digitLength];
                this._sign = sign;
                this._digitLength = digitLength;
                Array.Copy(digits, this._digits, digitLength);
            }
        }
        public ECScalar(uint[] digits, int digitLength, int sign)
        {
            if (digitLength > digits.Length)
                digitLength = digits.Length;
            while (digitLength > 1 && digits[digitLength - 1] == 0)
                digitLength--;

            if (digitLength == 0)
            {
                this._sign = 0;
                this._digits = new uint[1];
                this._digitLength = 1;
            }
            else
            {
                this._digits = new uint[digitLength];
                this._sign = sign;
                this._digitLength = digitLength;
                Array.Copy(digits, this._digits, digitLength);
            }
        }

        public static ECScalar Abs(ECScalar value)
        {
            value = value.Copy();
            if (value._sign != 0)
                value._sign = 1;
            return value;
        }
        public static ECScalar Add(ECScalar left, ECScalar right)
        {
            if (left._sign == 0)
                return right.Copy();
            if (right._sign == 0)
                return left.Copy();

            if (left._sign == right._sign)
            {
                int resultLength;
                uint[] sum;
                if (right._digitLength == 1)
                {
                    sum = left._digits.Clone() as uint[];
                    resultLength = left._digitLength;
                    ECNumInternalOp.AddSingle(ref sum, ref resultLength, right._digits[0]);
                }
                else
                    sum = ECNumInternalOp.Add(left._digits, left._digitLength, right._digits, right._digitLength, out resultLength);

                return new ECScalar() { _sign = left._sign, _digits = sum, _digitLength = resultLength };
            }
            else
            {
                int c = ECNumInternalOp.Compare(left._digits, left._digitLength, right._digits, right._digitLength);
                if (c == 1)
                {
                    if (left._sign == 1)
                    {
                        int resultLength;
                        uint[] sum;
                        if (right._digitLength == 1)
                        {
                            sum = left._digits.Clone() as uint[];
                            resultLength = left._digitLength;
                            ECNumInternalOp.SubSingle(ref sum, ref resultLength, right._digits[0]);
                        }
                        else
                            sum = ECNumInternalOp.Sub(left._digits, left._digitLength, right._digits, right._digitLength, out resultLength);
                        return new ECScalar() { _digitLength = resultLength, _digits = sum, _sign = 1 };
                    }
                    else
                    {
                        int resultLength;
                        uint[] sum;
                        if (right._digitLength == 1)
                        {
                            sum = left._digits.Clone() as uint[];
                            resultLength = left._digitLength;
                            ECNumInternalOp.SubSingle(ref sum, ref resultLength, right._digits[0]);
                        }
                        else
                            sum = ECNumInternalOp.Sub(left._digits, left._digitLength, right._digits, right._digitLength, out resultLength);
                        return new ECScalar() { _digitLength = resultLength, _digits = sum, _sign = -1 };
                    }
                }
                else if (c == -1)
                {
                    if (left._sign == 1)
                    {
                        int resultLength;
                        uint[] sum;
                        if (left._digitLength == 1)
                        {
                            sum = right._digits.Clone() as uint[];
                            resultLength = right._digitLength;
                            ECNumInternalOp.SubSingle(ref sum, ref resultLength, left._digits[0]);
                        }
                        else
                            sum = ECNumInternalOp.Sub(right._digits, right._digitLength, left._digits, left._digitLength, out resultLength);
                        return new ECScalar() { _digitLength = resultLength, _digits = sum, _sign = -1 };
                    }
                    else
                    {
                        int resultLength;
                        uint[] sum;
                        if (left._digitLength == 1)
                        {
                            sum = right._digits.Clone() as uint[];
                            resultLength = right._digitLength;
                            ECNumInternalOp.SubSingle(ref sum, ref resultLength, left._digits[0]);
                        }
                        else
                            sum = ECNumInternalOp.Sub(right._digits, right._digitLength, left._digits, left._digitLength, out resultLength);
                        return new ECScalar() { _digitLength = resultLength, _digits = sum, _sign = 1 };
                    }
                }
                else
                {
                    return ECScalar.Zero;
                }
            }
        }
        public static ECScalar Divide(ECScalar left, ECScalar right)
        {
            if (left._sign == 0)
                return ECScalar.Zero;
            if (right._sign == 0)
                throw new ArithmeticException("0'a bölme yapılamaz.");
            int c = ECNumInternalOp.Compare(left._digits, left._digitLength, right._digits, right._digitLength);
            if (c == -1)
            {
                return ECScalar.Zero;
            }
            else if (c == 0)
            {
                if (left._sign == right._sign)
                    return new ECScalar(1);
                else
                    return new ECScalar(-1);
            }
            else
            {
                if (right._digitLength == 1)
                {
                    int resultLength;
                    uint rem;
                    uint[] div = ECNumInternalOp.DivRemSingle(left._digits, left._digitLength, right._digits[0], out resultLength, out rem);
                    if (left._sign == right._sign)
                        return new ECScalar() { _digits = div, _digitLength = resultLength, _sign = 1 };
                    else
                        return new ECScalar() { _digits = div, _digitLength = resultLength, _sign = -1 };
                }
                else
                {
                    uint[] num = left._digits.Clone() as uint[];
                    int resultLength;
                    uint[] div = ECNumInternalOp.Div(num, left._digitLength, right._digits, right._digitLength, out resultLength);
                    if (left._sign == right._sign)
                        return new ECScalar() { _sign = 1, _digitLength = resultLength, _digits = div };
                    else
                        return new ECScalar() { _sign = -1, _digitLength = resultLength, _digits = div };
                }
            }
        }
        public static ECScalar DivRem(ECScalar left, ECScalar right, out ECScalar remainder)
        {
            if (left._sign == 0)
            {
                remainder = ECScalar.Zero;
                return ECScalar.Zero;
            }
            if (right._sign == 0)
                throw new ArithmeticException("0'a bölme yapılamaz.");

            int c = ECNumInternalOp.Compare(left._digits, left._digitLength, right._digits, right._digitLength);
            if (c == -1)
            {
                remainder = left.Copy();
                return ECScalar.Zero;
            }
            else if (c == 0)
            {
                remainder = ECScalar.Zero;
                if (left._sign == right._sign)
                    return new ECScalar(1);
                else
                    return new ECScalar(-1);
            }
            else
            {
                if (right._digitLength == 1)
                {
                    int resultLength;
                    uint rem;
                    uint[] div = ECNumInternalOp.DivRemSingle(left._digits, left._digitLength, right._digits[0], out resultLength, out rem);
                    remainder = new ECScalar(rem);
                    if (rem != 0)
                        remainder._sign = left._sign;
                    if (left._sign == right._sign)
                        return new ECScalar() { _digits = div, _digitLength = resultLength, _sign = 1 };
                    else
                        return new ECScalar() { _digits = div, _digitLength = resultLength, _sign = -1 };
                }
                else
                {
                    uint[] num = left._digits.Clone() as uint[];
                    int resultLength, remainderLength;
                    uint[] div = ECNumInternalOp.DivRem(ref num, left._digitLength, right._digits, right._digitLength, out resultLength, out remainderLength);
                    remainder = new ECScalar() { _digitLength = remainderLength, _digits = num, _sign = left._sign };
                    if (left._sign == right._sign)
                        return new ECScalar() { _sign = 1, _digitLength = resultLength, _digits = div };
                    else
                        return new ECScalar() { _sign = -1, _digitLength = resultLength, _digits = div };
                }
            }
        }
        public static ECScalar LeftShift(ECScalar value, int shift)
        {
            if (value.IsZero)
                return ECScalar.Zero;
            if (shift < 0)
                return ECScalar.RightShift(value, -shift);

            uint[] digs = value._digits.Clone() as uint[];
            int len = value._digitLength;
            ECNumInternalOp.ShiftLeft(ref digs, ref len, shift);
            return new ECScalar() { _digitLength = len, _digits = digs, _sign = value._sign };
        }
        public static ECScalar ModInverse(ECScalar K, ECScalar modulus)
        {
            if (K.IsOne)
                return ECScalar.One;

            ECScalar x1 = ECScalar.Zero, x2 = modulus, y1 = ECScalar.One, y2 = K;

            ECScalar t1, t2, q = ECScalar.DivRem(x2, y2, out t2);
            q.Negate();
            t1 = q;

            while (!y2.IsOne)
            {
                if (t2._sign == 0)
                    return ECScalar.Zero;

                x1 = y1; x2 = y2;
                y1 = t1; y2 = t2;
                q = ECScalar.DivRem(x2, y2, out t2);

                t1 = ECScalar.Subtract(x1, ECScalar.Multiply(q, y1));
            }
            if (y1._sign == -1)
                return (ECScalar.Add(y1, modulus));
            else
                return y1;
        }
        public static ECScalar Multiply(ECScalar left, ECScalar right)
        {
            if (left._sign == 0 || right._sign == 0)
                return ECScalar.Zero;

            int resultLength;
            uint[] mul = ECNumInternalOp.Mul(left._digits, left._digitLength, right._digits, right._digitLength, out resultLength);
            if (left._sign == right._sign)
                return new ECScalar() { _digitLength = resultLength, _sign = 1, _digits = mul };
            else
                return new ECScalar() { _digitLength = resultLength, _sign = -1, _digits = mul };
        }
        public static ECScalar Negate(ECScalar value)
        {
            value = value.Copy();
            if (value._sign == 0)
                return value;

            value._sign = value._sign == 1 ? -1 : 1;
            return value;
        }
        public static ECScalar Remainder(ECScalar left, ECScalar right)
        {
            if (left._sign == 0)
                return ECScalar.Zero;
            if (right._sign == 0)
                throw new ArithmeticException("0'a bölme yapılamaz.");

            int c = ECNumInternalOp.Compare(left._digits, left._digitLength, right._digits, right._digitLength);
            if (c == -1)
            {
                return left.Copy();
            }
            else if (c == 0)
            {
                return ECScalar.Zero;
            }
            else
            {
                if (right._digitLength == 1)
                {
                    int resultLength;
                    uint rem;
                    ECNumInternalOp.DivRemSingle(left._digits, left._digitLength, right._digits[0], out resultLength, out rem);
                    if (left._sign == 1)
                        return new ECScalar() { _digits = new uint[1] { rem }, _digitLength = 1, _sign = 1 };
                    else
                        return new ECScalar() { _digits = new uint[1] { rem }, _digitLength = 1, _sign = -1 };
                }
                else
                {
                    uint[] num = left._digits.Clone() as uint[];
                    int remLength = left._digitLength;
                    ECNumInternalOp.Rem(ref num, ref remLength, right._digits, right._digitLength);
                    if (left._sign == 1)
                        return new ECScalar() { _sign = 1, _digitLength = remLength, _digits = num };
                    else
                        return new ECScalar() { _sign = -1, _digitLength = remLength, _digits = num };
                }
            }
        }
        public static ECScalar RightShift(ECScalar value, int shift)
        {
            if (value.IsZero)
                return ECScalar.Zero;
            if (shift < 0)
                return ECScalar.LeftShift(value, -shift);

            uint[] digs = value._digits.Clone() as uint[];
            int len = value._digitLength;
            ECNumInternalOp.ShiftRight(ref digs, ref len, shift);
            if (len == 1 && digs[0] == 0)
                return ECScalar.Zero;
            return new ECScalar() { _digitLength = len, _digits = digs, _sign = value._sign };
        }
        public static ECScalar Subtract(ECScalar left, ECScalar right)
        {
            if (left._sign == 0)
            {
                ECScalar val = right.Copy();
                if (val._sign == 0)
                    return val;
                val._sign = val._sign == 1 ? val._sign = -1 : val._sign = 1;
                return val;
            }
            if (right._sign == 0)
                return left.Copy();

            if (left._sign != right._sign)
            {
                int resultLength;
                uint[] dif = ECNumInternalOp.Add(left._digits, left._digitLength, right._digits, right._digitLength, out resultLength);
                if (left.Sign == 1)
                    return new ECScalar() { _digitLength = resultLength, _digits = dif, _sign = 1 };
                else
                    return new ECScalar() { _digitLength = resultLength, _digits = dif, _sign = -1 };
            }
            else
            {
                int c = ECNumInternalOp.Compare(left._digits, left._digitLength, right._digits, right._digitLength);
                if (c == 1)
                {
                    int resultLength;
                    uint[] dif = ECNumInternalOp.Sub(left._digits, left._digitLength, right._digits, right._digitLength, out resultLength);
                    return new ECScalar() { _digitLength = resultLength, _digits = dif, _sign = left._sign };
                }
                else if (c == -1)
                {
                    int resultLength;
                    uint[] dif = ECNumInternalOp.Sub(right._digits, right._digitLength, left._digits, left._digitLength, out resultLength);
                    return new ECScalar() { _digitLength = resultLength, _digits = dif, _sign = right._sign == 1 ? -1 : 1 };
                }
                else
                {
                    return ECScalar.Zero;
                }
            }
        }
        public static ECScalar Square(ECScalar value)
        {
            return ECScalar.Multiply(value, value);
        }
        public static ECScalar TwoPower(long exponent)
        {
            if (exponent == 0)
                return ECScalar.One;

            int digitLength = (int)(exponent / 32) + 1;
            uint[] digits = new uint[digitLength];
            digits[digitLength - 1] = ((uint)1 << (int)(exponent & 31));
            return new ECScalar() { _digitLength = digitLength, _digits = digits, _sign = 1 };
        }

        public static ECScalar Parse(string value)
        {
            try
            {
                int digitLength, sign;
                uint[] digits = ECNumInternalOp.SignedParse(value, out digitLength, out sign);
                return new ECScalar { _digitLength = digitLength, _digits = digits, _sign = sign };
            }
            catch (Exception)
            {
                throw new FormatException();
            }
        }
        public static ECScalar ParseFromHex(string hex)
        {
            bool isNeg = false;
            if (isNeg = hex.StartsWith("-"))
                hex = hex.Substring(1, hex.Length - 1);

            hex = hex.ToLower();

            if (hex.StartsWith("0x"))
                hex = hex.Substring(2, hex.Length - 2);

            int byteLength = (hex.Length + 1) / 2;
            byte[] bytes = new byte[byteLength];

            if ((hex.Length & 1) == 1)
                hex = "0" + hex;
            for (int i = 0; i < byteLength; i++)
            {
                char c1 = hex[2 * i];
                char c2 = hex[2 * i + 1];
                if (c1 > 96)
                    bytes[i] |= (byte)((c1 - 87) << 4);
                else
                    bytes[i] |= (byte)((c1 - 48) << 4);

                if (c2 > 96)
                    bytes[i] |= (byte)((c2 - 87));
                else
                    bytes[i] |= (byte)((c2 - 48));
            }
            int digitLength;
            uint[] digits = ECNumInternalOp.FromUnsignedBytes(bytes, true, out digitLength);
            if (digitLength == 1 && digits[0] == 0)
                return ECScalar.Zero;
            return new ECScalar(digits, digitLength, isNeg ? -1 : 1);
        }

        public int CompareTo(ECScalar other)
        {
            if (this._sign == other._sign)
            {
                if (this._sign == 0)
                    return 0;
                else
                {
                    int c = ECNumInternalOp.Compare(this._digits, this._digitLength, other._digits, other._digitLength);
                    if (c == 1)
                    {
                        if (this._sign == 1)
                            return 1;
                        else
                            return -1;
                    }
                    else if (c == -1)
                    {
                        if (this._sign == 1)
                            return -1;
                        else
                            return 1;
                    }
                    else
                        return 0;
                }
            }
            else
            {
                return this._sign.CompareTo(other._sign);
            }
        }
        public override bool Equals(object obj)
        {
            return this.Equals((ECScalar)obj);
        }
        public bool Equals(ECScalar other)
        {
            return this.CompareTo(other) == 0;
        }
        public ECScalar Copy()
        {
            uint[] val = this._digits.Clone() as uint[];
            return new ECScalar() { _digits = val, _sign = this._sign, _digitLength = this._digitLength, };
        }
        public int GetBit(long bitPosition)
        {
            if (this._sign == 0)
                return 0;
            if (bitPosition > this.BitsLength)
                return 0;
            int bit = ECNumInternalOp.GetBit(this._digits, this._digitLength, bitPosition);
            if (this._sign == 1)
                return bit;
            else
                return ~bit;
        }
        public byte[] GetBytes(bool bigEndian)
        {
            return ECNumInternalOp.GetSignedBytes(this._digits, this._digitLength, bigEndian, this._sign);
        }
        public byte[] GetUnsignedBytes(bool bigEndian)
        {
            return ECNumInternalOp.GetUnsignedBytes(this._digits, this._digitLength, bigEndian);
        }
        public override int GetHashCode()
        {
            if (this._sign == 0)
                return 0;

            uint sum = 0;
            for (int i = 0; i < this._digitLength; i++)
            {
                sum += this._digits[i];
            }
            if (this._sign == 1)
                return (int)sum;
            else
                return -(int)sum;
        }
        public void Negate()
        {
            if (this._sign == 0)
                return;

            this._sign = this._sign == 1 ? -1 : 1;
        }
        public void LeftShift(int shift)
        {
            if (this.IsZero)
                return;
            if (shift < 0)
            {
                ECNumInternalOp.ShiftRight(ref this._digits, ref this._digitLength, -shift);
            }
            else
            {
                ECNumInternalOp.ShiftLeft(ref this._digits, ref this._digitLength, shift);
            }
        }
        public void RightShift(int shift)
        {
            if (this.IsZero)
                return;

            if (shift < 0)
            {
                ECNumInternalOp.ShiftLeft(ref this._digits, ref this._digitLength, -shift);
            }
            else
            {
                ECNumInternalOp.ShiftRight(ref this._digits, ref this._digitLength, shift);
            }
        }
        public override string ToString()
        {
            if (this._sign == 0)
                return "0";

            string s = ECNumInternalOp.ToString(this._digits, this._digitLength, this._sign);
            //if (this._sign == -1)
            //    return "-" + s;
            return s;
        }
        public int[] NonAdjacentForm(int window)
        {
            ECScalar d = this.Copy();
            int modulus = 1 << window;

            int[] naf = new int[d.BitsLength + 1];
            int modMinOne = modulus - 1;
            int halfOfModulus = modulus >> 1;
            for (int i = 0; !d.IsZero; i++)
            {
                if (d.IsOdd)
                {
                    int mod = (int)d.FirstDigit & modMinOne; //d mod 2 ^ w

                    if (mod >= halfOfModulus)
                    {
                        int inc = modulus - mod;
                        naf[i] = -inc;
                        d += inc;
                    }
                    else
                    {
                        naf[i] = mod;
                        d -= (uint)mod;
                    }
                }
                d.RightShift(1);
            }
            return naf;
        }

        public static ECScalar operator +(ECScalar left, ECScalar right)
        {
            return ECScalar.Add(left, right);
        }
        public static ECScalar operator -(ECScalar left, ECScalar right)
        {
            return ECScalar.Subtract(left, right);
        }
        public static ECScalar operator *(ECScalar left, ECScalar right)
        {
            return ECScalar.Multiply(left, right);
        }
        public static ECScalar operator /(ECScalar left, ECScalar right)
        {
            return ECScalar.Divide(left, right);
        }
        public static ECScalar operator %(ECScalar left, ECScalar right)
        {
            return ECScalar.Remainder(left, right);
        }
        public static ECScalar operator <<(ECScalar value, int shift)
        {
            return ECScalar.LeftShift(value, shift);
        }
        public static ECScalar operator >>(ECScalar value, int shift)
        {
            return ECScalar.RightShift(value, shift);
        }

        public static ECScalar operator ++(ECScalar value)
        {
            return ECScalar.Add(value, 1);
        }
        public static ECScalar operator --(ECScalar value)
        {
            return ECScalar.Subtract(value, 1);
        }
        public static ECScalar operator -(ECScalar value)
        {
            return ECScalar.Negate(value);
        }

        public static implicit operator ECScalar(byte value)
        {
            return new ECScalar(value);
        }
        public static implicit operator ECScalar(ushort value)
        {
            return new ECScalar(value);
        }
        public static implicit operator ECScalar(uint value)
        {
            return new ECScalar(value);
        }
        public static implicit operator ECScalar(ulong value)
        {
            return new ECScalar(value);
        }
        public static implicit operator ECScalar(sbyte value)
        {
            return new ECScalar(value);
        }
        public static implicit operator ECScalar(short value)
        {
            return new ECScalar(value);
        }
        public static implicit operator ECScalar(int value)
        {
            return new ECScalar(value);
        }
        public static implicit operator ECScalar(long value)
        {
            return new ECScalar(value);
        }
        public static explicit operator int(ECScalar value)
        {
            return (int)value._digits[value._digitLength - 1];
        }

        public static bool operator ==(ECScalar left, sbyte right)
        {
            return left.CompareTo(right) == 0;
        }
        public static bool operator !=(ECScalar left, sbyte right)
        {
            return left.CompareTo(right) != 0;
        }
        public static bool operator <(ECScalar left, sbyte right)
        {
            return left.CompareTo(right) == -1;
        }
        public static bool operator >(ECScalar left, sbyte right)
        {
            return left.CompareTo(right) == 1;
        }
        public static bool operator <=(ECScalar left, sbyte right)
        {
            return left.CompareTo(right) < 1;
        }
        public static bool operator >=(ECScalar left, sbyte right)
        {
            return left.CompareTo(right) > -1;
        }
        public static bool operator ==(ECScalar left, byte right)
        {
            return left.CompareTo(right) == 0;
        }
        public static bool operator !=(ECScalar left, byte right)
        {
            return left.CompareTo(right) != 0;
        }
        public static bool operator <(ECScalar left, byte right)
        {
            return left.CompareTo(right) == -1;
        }
        public static bool operator >(ECScalar left, byte right)
        {
            return left.CompareTo(right) == 1;
        }
        public static bool operator <=(ECScalar left, byte right)
        {
            return left.CompareTo(right) < 1;
        }
        public static bool operator >=(ECScalar left, byte right)
        {
            return left.CompareTo(right) > -1;
        }
        public static bool operator ==(ECScalar left, short right)
        {
            return left.CompareTo(right) == 0;
        }
        public static bool operator !=(ECScalar left, short right)
        {
            return left.CompareTo(right) != 0;
        }
        public static bool operator <(ECScalar left, short right)
        {
            return left.CompareTo(right) == -1;
        }
        public static bool operator >(ECScalar left, short right)
        {
            return left.CompareTo(right) == 1;
        }
        public static bool operator <=(ECScalar left, short right)
        {
            return left.CompareTo(right) < 1;
        }
        public static bool operator >=(ECScalar left, short right)
        {
            return left.CompareTo(right) > -1;
        }
        public static bool operator ==(ECScalar left, ushort right)
        {
            return left.CompareTo(right) == 0;
        }
        public static bool operator !=(ECScalar left, ushort right)
        {
            return left.CompareTo(right) != 0;
        }
        public static bool operator <(ECScalar left, ushort right)
        {
            return left.CompareTo(right) == -1;
        }
        public static bool operator >(ECScalar left, ushort right)
        {
            return left.CompareTo(right) == 1;
        }
        public static bool operator <=(ECScalar left, ushort right)
        {
            return left.CompareTo(right) < 1;
        }
        public static bool operator >=(ECScalar left, ushort right)
        {
            return left.CompareTo(right) > -1;
        }
        public static bool operator ==(ECScalar left, int right)
        {
            return left.CompareTo(right) == 0;
        }
        public static bool operator !=(ECScalar left, int right)
        {
            return left.CompareTo(right) != 0;
        }
        public static bool operator <(ECScalar left, int right)
        {
            return left.CompareTo(right) == -1;
        }
        public static bool operator >(ECScalar left, int right)
        {
            return left.CompareTo(right) == 1;
        }
        public static bool operator <=(ECScalar left, int right)
        {
            return left.CompareTo(right) < 1;
        }
        public static bool operator >=(ECScalar left, int right)
        {
            return left.CompareTo(right) > -1;
        }
        public static bool operator ==(ECScalar left, uint right)
        {
            return left.CompareTo(right) == 0;
        }
        public static bool operator !=(ECScalar left, uint right)
        {
            return left.CompareTo(right) != 0;
        }
        public static bool operator <(ECScalar left, uint right)
        {
            return left.CompareTo(right) == -1;
        }
        public static bool operator >(ECScalar left, uint right)
        {
            return left.CompareTo(right) == 1;
        }
        public static bool operator <=(ECScalar left, uint right)
        {
            return left.CompareTo(right) < 1;
        }
        public static bool operator >=(ECScalar left, uint right)
        {
            return left.CompareTo(right) > -1;
        }
        public static bool operator ==(ECScalar left, long right)
        {
            return left.CompareTo(right) == 0;
        }
        public static bool operator !=(ECScalar left, long right)
        {
            return left.CompareTo(right) != 0;
        }
        public static bool operator <(ECScalar left, long right)
        {
            return left.CompareTo(right) == -1;
        }
        public static bool operator >(ECScalar left, long right)
        {
            return left.CompareTo(right) == 1;
        }
        public static bool operator <=(ECScalar left, long right)
        {
            return left.CompareTo(right) < 1;
        }
        public static bool operator >=(ECScalar left, long right)
        {
            return left.CompareTo(right) > -1;
        }
        public static bool operator ==(ECScalar left, ulong right)
        {
            return left.CompareTo(right) == 0;
        }
        public static bool operator !=(ECScalar left, ulong right)
        {
            return left.CompareTo(right) != 0;
        }
        public static bool operator <(ECScalar left, ulong right)
        {
            return left.CompareTo(right) == -1;
        }
        public static bool operator >(ECScalar left, ulong right)
        {
            return left.CompareTo(right) == 1;
        }
        public static bool operator <=(ECScalar left, ulong right)
        {
            return left.CompareTo(right) < 1;
        }
        public static bool operator >=(ECScalar left, ulong right)
        {
            return left.CompareTo(right) > -1;
        }
        public static bool operator ==(ECScalar left, ECScalar right)
        {
            return left.CompareTo(right) == 0;
        }
        public static bool operator !=(ECScalar left, ECScalar right)
        {
            return left.CompareTo(right) != 0;
        }
        public static bool operator <(ECScalar left, ECScalar right)
        {
            return left.CompareTo(right) == -1;
        }
        public static bool operator >(ECScalar left, ECScalar right)
        {
            return left.CompareTo(right) == 1;
        }
        public static bool operator <=(ECScalar left, ECScalar right)
        {
            return left.CompareTo(right) < 1;
        }
        public static bool operator >=(ECScalar left, ECScalar right)
        {
            return left.CompareTo(right) > -1;
        }

        internal static class ECNumInternalOp
        {
            internal static void Add(ref uint[] left, ref int leftLength, uint[] right, int rightLength) //Tested OK.
            {
                uint[] result;
                int max, min;
                uint[] maxOperand, minOperand;
                if (leftLength > rightLength)
                {
                    max = leftLength;
                    min = rightLength;
                    maxOperand = left;
                    minOperand = right;
                }
                else
                {
                    min = leftLength;
                    max = rightLength;
                    maxOperand = right;
                    minOperand = left;
                }
                if (left.Length < max)
                    Array.Resize(ref left, max + 1);
                result = left;
                ulong carry = 0;
                for (int i = 0; i < min; i++)
                {
                    ulong sum = (ulong)minOperand[i] + (ulong)maxOperand[i] + carry;
                    carry = sum >> 32;
                    result[i] = (uint)(sum);
                }

                if (carry > 0)
                {
                    for (int i = min; i < max; i++)
                    {
                        ulong sum = (ulong)maxOperand[i] + carry;
                        carry = sum >> 32;
                        result[i] = (uint)(sum);
                    }
                }
                else
                {
                    for (int i = min; i < max; i++)
                        result[i] = maxOperand[i];
                }
                result[max] = (uint)(carry);
                leftLength = max + 1;
                ECNumInternalOp.trim(result, ref leftLength);
            }
            internal static uint[] Add(uint[] left, int leftLength, uint[] right, int rightLength, out int resultLength) //Tested OK.
            {
                uint[] result;
                int max, min;
                uint[] maxOperand, minOperand;
                if (leftLength > rightLength)
                {
                    max = leftLength;
                    min = rightLength;
                    maxOperand = left;
                    minOperand = right;
                }
                else
                {
                    min = leftLength;
                    max = rightLength;
                    maxOperand = right;
                    minOperand = left;
                }
                result = new uint[max + 1];
                ulong carry = 0;
                for (int i = 0; i < min; i++)
                {
                    ulong sum = (ulong)minOperand[i] + (ulong)maxOperand[i] + carry;
                    carry = sum >> 32;
                    result[i] = (uint)(sum);
                }

                if (carry > 0)
                {
                    for (int i = min; i < max; i++)
                    {
                        ulong sum = (ulong)maxOperand[i] + carry;
                        carry = sum >> 32;
                        result[i] = (uint)(sum);
                    }
                }
                else
                {
                    for (int i = min; i < max; i++)
                        result[i] = maxOperand[i];
                }
                result[max] = (uint)(carry);
                resultLength = max + 1;
                ECNumInternalOp.trim(result, ref resultLength);
                return result;
            }
            internal static void AddSingle(ref uint[] left, ref int leftLength, uint right) //Tested OK.
            {
                int max = leftLength;
                ulong carry = 0;

                ulong sum = (ulong)left[0] + (ulong)right + carry;
                carry = sum >> 32;
                left[0] = (uint)(sum);

                for (int i = 1; i < max && carry > 0; i++)
                {
                    sum = (ulong)left[i] + carry;
                    carry = sum >> 32;
                    left[i] = (uint)(sum);
                }

                if (carry > 0)
                {
                    if (!(left.Length > max))
                        Array.Resize(ref left, max + 1);

                    left[max] = (uint)(carry);
                    leftLength = max + 1;
                }
                else
                    leftLength = max;
                ECNumInternalOp.trim(left, ref leftLength);
            }
            internal static uint[] Div(uint[] numerator, int numeratorLength, uint[] denominator, int denominatorLength, out int quotientLength) //Tested OK.
            {
                int denLastU = denominatorLength - 1;
                int numLastU = numeratorLength - 1;

                int opLDiff = numLastU - denLastU;

                quotientLength = opLDiff;
                for (int iu = numLastU; ; iu--)
                {
                    if (iu < opLDiff)
                    {
                        quotientLength++;
                        break;
                    }
                    if (denominator[iu - opLDiff] != numerator[iu])
                    {
                        if (denominator[iu - opLDiff] < numerator[iu])
                            quotientLength++;
                        break;
                    }
                }

                uint[] quotient = new uint[quotientLength];

                uint denFirst = denominator[denominatorLength - 1];
                uint denSecond = denominator[denominatorLength - 2];
                int leftShiftBit = ECNumInternalOp.countOfZeroBitStart(denFirst);
                int rightShiftBit = 32 - leftShiftBit;
                if (leftShiftBit > 0)
                {
                    denFirst = (denFirst << leftShiftBit) | (denSecond >> rightShiftBit);
                    denSecond <<= leftShiftBit;
                    if (denominatorLength > 2)
                        denSecond |= denominator[denominatorLength - 3] >> rightShiftBit;
                }

                for (int uInd = quotientLength; --uInd >= 0; )
                {
                    uint hiNumDig = (uInd + denominatorLength <= numLastU) ? numerator[uInd + denominatorLength] : 0;

                    ulong currNum = ((ulong)hiNumDig << 32) | numerator[uInd + denominatorLength - 1];
                    uint nextNum = numerator[uInd + denominatorLength - 2];
                    if (leftShiftBit > 0)
                    {
                        currNum = (currNum << leftShiftBit) | (nextNum >> rightShiftBit);
                        nextNum <<= leftShiftBit;
                        if (uInd + denominatorLength >= 3)
                            nextNum |= numerator[uInd + denominatorLength - 3] >> rightShiftBit;
                    }

                    ulong rQuot = currNum / denFirst;
                    ulong rRem = (uint)(currNum % denFirst);
                    if (rQuot > uint.MaxValue)
                    {
                        rRem += denFirst * (rQuot - uint.MaxValue);
                        rQuot = uint.MaxValue;
                    }
                    while (rRem <= uint.MaxValue && rQuot * denSecond > (((ulong)((uint)rRem) << 32) | nextNum))
                    {
                        rQuot--;
                        rRem += denFirst;
                    }

                    if (rQuot > 0)
                    {
                        ulong borrow = 0;
                        for (int u = 0; u < denominatorLength; u++)
                        {
                            borrow += denominator[u] * rQuot;
                            uint uSub = (uint)borrow;
                            borrow >>= 32;
                            if (numerator[uInd + u] < uSub)
                                borrow++;
                            numerator[uInd + u] -= uSub;
                        }

                        if (hiNumDig < borrow)
                        {
                            uint uCarry = 0;
                            for (int iu2 = 0; iu2 < denominatorLength; iu2++)
                            {
                                uCarry = addCarry(ref numerator[uInd + iu2], denominator[iu2], uCarry);
                            }
                            rQuot--;
                        }
                        numLastU = uInd + denominatorLength - 1;
                    }
                    quotient[uInd] = (uint)rQuot;
                }
                ECNumInternalOp.trim(quotient, ref quotientLength);
                return quotient;
            }
            internal static uint[] DivRem(ref uint[] numerator, int numeratorLength, uint[] denominator, int denominatorLength, out int quotientLength, out int remainderLength) //Tested OK.
            {
                int numLastU = numeratorLength - 1;
                int opLDiff = numLastU - (denominatorLength - 1);

                quotientLength = opLDiff;
                for (int iu = numLastU; ; iu--)
                {
                    if (iu < opLDiff)
                    {
                        quotientLength++;
                        break;
                    }
                    if (denominator[iu - opLDiff] != numerator[iu])
                    {
                        if (denominator[iu - opLDiff] < numerator[iu])
                            quotientLength++;
                        break;
                    }
                }

                uint[] quotient = new uint[quotientLength];

                uint denFirst = denominator[denominatorLength - 1];
                uint denSecond = denominator[denominatorLength - 2];
                int leftShiftBit = ECNumInternalOp.countOfZeroBitStart(denFirst);
                int rightShiftBit = 32 - leftShiftBit;
                if (leftShiftBit > 0)
                {
                    denFirst = (denFirst << leftShiftBit) | (denSecond >> rightShiftBit);
                    denSecond <<= leftShiftBit;
                    if (denominatorLength > 2)
                        denSecond |= denominator[denominatorLength - 3] >> rightShiftBit;
                }

                for (int uInd = quotientLength; --uInd >= 0; )
                {
                    uint hiNumDig = (uInd + denominatorLength <= numLastU) ? numerator[uInd + denominatorLength] : 0;

                    ulong currNum = ((ulong)hiNumDig << 32) | numerator[uInd + denominatorLength - 1];
                    uint nextNum = numerator[uInd + denominatorLength - 2];
                    if (leftShiftBit > 0)
                    {
                        currNum = (currNum << leftShiftBit) | (nextNum >> rightShiftBit);
                        nextNum <<= leftShiftBit;
                        if (uInd + denominatorLength >= 3)
                            nextNum |= numerator[uInd + denominatorLength - 3] >> rightShiftBit;
                    }

                    ulong rQuot = currNum / denFirst;
                    ulong rRem = (uint)(currNum % denFirst);
                    if (rQuot > uint.MaxValue)
                    {
                        rRem += denFirst * (rQuot - uint.MaxValue);
                        rQuot = uint.MaxValue;
                    }
                    while (rRem <= uint.MaxValue && rQuot * denSecond > (((ulong)((uint)rRem) << 32) | nextNum))
                    {
                        rQuot--;
                        rRem += denFirst;
                    }

                    if (rQuot > 0)
                    {
                        ulong borrow = 0;
                        for (int u = 0; u < denominatorLength; u++)
                        {
                            borrow += denominator[u] * rQuot;
                            uint uSub = (uint)borrow;
                            borrow >>= 32;
                            if (numerator[uInd + u] < uSub)
                                borrow++;
                            numerator[uInd + u] -= uSub;
                        }

                        if (hiNumDig < borrow)
                        {
                            uint uCarry = 0;
                            for (int iu2 = 0; iu2 < denominatorLength; iu2++)
                            {
                                uCarry = addCarry(ref numerator[uInd + iu2], denominator[iu2], uCarry);
                            }
                            rQuot--;
                        }
                        numLastU = uInd + denominatorLength - 1;
                    }
                    quotient[uInd] = (uint)rQuot;
                }

                remainderLength = denominatorLength;
                for (int i = remainderLength; i < numerator.Length; i++)
                    numerator[i] = 0;
                ECNumInternalOp.trim(numerator, ref remainderLength);
                ECNumInternalOp.trim(quotient, ref quotientLength);
                return quotient;
            }
            internal static uint[] DivRemSingle(uint[] left, int leftLength, uint divisor, out int resultLength, out uint remainder) //Tested OK.
            {
                uint[] r = left.Clone() as uint[];
                uint[] q = new uint[leftLength];

                ulong dividend = r[leftLength - 1];
                int qPos = leftLength - 1;
                int rPos = qPos;
                if (dividend >= divisor)
                {
                    ulong quot = dividend / divisor;
                    q[qPos--] = (uint)quot;
                    r[rPos] = (uint)(dividend % divisor);
                }
                else
                    qPos--;
                rPos--;
                while (rPos > -1)
                {
                    int rPosPlusOne = rPos + 1;
                    dividend = ((ulong)r[rPosPlusOne] << 32) | r[rPos];
                    ulong quot = dividend / divisor;
                    q[qPos--] = (uint)quot;
                    r[rPosPlusOne] = 0;
                    r[rPos--] = (uint)(dividend % divisor);
                }
                if (q[q.Length - 1] == 0)
                    resultLength = leftLength - 1;
                else
                    resultLength = leftLength;

                remainder = r[0];
                ECNumInternalOp.trim(q, ref resultLength);
                return q;
            }
            internal static uint[] Mul(uint[] left, int leftLength, uint[] right, int rightLength, out int resultLength) //Tested OK.
            {
                resultLength = leftLength + rightLength;
                uint[] result = new uint[resultLength];

                if (leftLength > rightLength)
                {
                    int tmp = leftLength;
                    leftLength = rightLength;
                    rightLength = tmp;
                    uint[] tmpb = left;
                    left = right;
                    right = tmpb;
                }

                for (int i = 0; i < leftLength; i++)
                {
                    if (left[i] == 0) continue;

                    ulong carry = 0;
                    for (int j = 0, k = i; j < rightLength; j++, k++)
                    {
                        ulong val = ((ulong)left[i] * right[j]) + result[k] + carry;
                        result[k] = (uint)val;
                        carry = (val >> 32);
                    }
                    if (carry != 0)
                        result[i + rightLength] = (uint)carry;
                }

                ECNumInternalOp.trim(result, ref resultLength);
                return result;
            }
            internal static uint[] MulSingle(uint[] left, int leftLength, uint right, out int resultLength) //Tested OK.
            {
                resultLength = leftLength + 1;
                uint[] result = new uint[resultLength];

                for (int i = 0; i < leftLength; i++)
                {
                    if (left[i] == 0) continue;

                    ulong carry = 0;

                    ulong val = ((ulong)left[i] * (ulong)right) + (ulong)result[i] + carry;
                    result[i] = (uint)(val & 0xFFFFFFFF);
                    carry = (val >> 32);

                    if (carry != 0)
                        result[i + 1] = (uint)carry;
                }

                ECNumInternalOp.trim(result, ref resultLength);
                return result;
            }
            internal static void Rem(ref uint[] numerator, ref int numeratorLength, uint[] denominator, int denominatorLength) //Tested OK.
            {
                int denLastU = denominatorLength - 1;
                int numLastU = numeratorLength - 1;

                int opLDiff = numLastU - denLastU;

                int quotientLength = opLDiff;
                for (int iu = numLastU; ; iu--)
                {
                    if (iu < opLDiff)
                    {
                        quotientLength++;
                        break;
                    }
                    if (denominator[iu - opLDiff] != numerator[iu])
                    {
                        if (denominator[iu - opLDiff] < numerator[iu])
                            quotientLength++;
                        break;
                    }
                }

                uint denFirst = denominator[denominatorLength - 1];
                uint denSecond = denominator[denominatorLength - 2];
                int leftShiftBit = ECNumInternalOp.countOfZeroBitStart(denFirst);
                int rightShiftBit = 32 - leftShiftBit;
                if (leftShiftBit > 0)
                {
                    denFirst = (denFirst << leftShiftBit) | (denSecond >> rightShiftBit);
                    denSecond <<= leftShiftBit;
                    if (denominatorLength > 2)
                        denSecond |= denominator[denominatorLength - 3] >> rightShiftBit;
                }

                for (int iu = quotientLength; --iu >= 0; )
                {
                    uint uNumHi = (iu + denominatorLength <= numLastU) ? numerator[iu + denominatorLength] : 0;

                    ulong uuNum = ((ulong)uNumHi << 32) | numerator[iu + denominatorLength - 1];
                    uint uNumNext = numerator[iu + denominatorLength - 2];
                    if (leftShiftBit > 0)
                    {
                        uuNum = (uuNum << leftShiftBit) | (uNumNext >> rightShiftBit);
                        uNumNext <<= leftShiftBit;
                        if (iu + denominatorLength >= 3)
                            uNumNext |= numerator[iu + denominatorLength - 3] >> rightShiftBit;
                    }

                    ulong uuQuo = uuNum / denFirst;
                    ulong uuRem = (uint)(uuNum % denFirst);
                    if (uuQuo > uint.MaxValue)
                    {
                        uuRem += denFirst * (uuQuo - uint.MaxValue);
                        uuQuo = uint.MaxValue;
                    }
                    while (uuRem <= uint.MaxValue && uuQuo * denSecond > (((ulong)((uint)uuRem) << 32) | uNumNext))
                    {
                        uuQuo--;
                        uuRem += denFirst;
                    }

                    if (uuQuo > 0)
                    {
                        ulong uuBorrow = 0;
                        for (int iu2 = 0; iu2 < denominatorLength; iu2++)
                        {
                            uuBorrow += denominator[iu2] * uuQuo;
                            uint uSub = (uint)uuBorrow;
                            uuBorrow >>= 32;
                            if (numerator[iu + iu2] < uSub)
                                uuBorrow++;
                            numerator[iu + iu2] -= uSub;
                        }

                        if (uNumHi < uuBorrow)
                        {
                            uint uCarry = 0;
                            for (int iu2 = 0; iu2 < denominatorLength; iu2++)
                            {
                                uCarry = addCarry(ref numerator[iu + iu2], denominator[iu2], uCarry);
                            }
                            uuQuo--;
                        }
                        numLastU = iu + denominatorLength - 1;
                    }
                }
                numeratorLength = denominatorLength;
                for (int i = numeratorLength; i < numerator.Length; i++)
                    numerator[i] = 0;
                ECNumInternalOp.trim(numerator, ref numeratorLength);
            }
            internal static void Sub(ref uint[] left, ref int leftLength, uint[] right, int rightLength) //Tested OK.
            {
                int max, min;
                uint[] maxOperand;
                if (leftLength > rightLength)
                {
                    max = leftLength;
                    min = rightLength;
                    maxOperand = left;
                }
                else
                {
                    min = leftLength;
                    max = rightLength;
                    maxOperand = right;
                }
                if (left.Length < max)
                    Array.Resize(ref left, max);
                uint[] result = left;

                long carry = 0;
                for (int i = 0; i < min; i++)
                {
                    long diff = (long)left[i] - (long)right[i] - carry;
                    result[i] = (uint)(diff);

                    if (diff < 0)
                        carry = 1;
                    else
                        carry = 0;
                }
                if (carry > 0)
                {
                    for (int i = min; i < max; i++)
                    {
                        long diff = (long)maxOperand[i] - carry;
                        result[i] = (uint)(diff);

                        if (diff < 0)
                            carry = 1;
                        else
                            carry = 0;
                    }
                }
                else
                {
                    for (int i = min; i < max; i++)
                        result[i] = maxOperand[i];
                }

                leftLength = max;
                ECNumInternalOp.trim(result, ref leftLength);
            }
            internal static uint[] Sub(uint[] left, int leftLength, uint[] right, int rightLength, out int resultLength) //Tested OK.
            {
                int max, min;
                uint[] maxOperand;
                if (leftLength > rightLength)
                {
                    max = leftLength;
                    min = rightLength;
                    maxOperand = left;
                }
                else
                {
                    min = leftLength;
                    max = rightLength;
                    maxOperand = right;
                }

                uint[] result = new uint[max];

                long carry = 0;
                for (int i = 0; i < min; i++)
                {
                    long diff = (long)left[i] - (long)right[i] - carry;
                    result[i] = (uint)(diff);

                    if (diff < 0)
                        carry = 1;
                    else
                        carry = 0;
                }
                if (carry > 0)
                {
                    for (int i = min; i < max; i++)
                    {
                        long diff = (long)maxOperand[i] - carry;
                        result[i] = (uint)(diff);

                        if (diff < 0)
                            carry = 1;
                        else
                            carry = 0;
                    }
                }
                else
                {
                    for (int i = min; i < max; i++)
                        result[i] = maxOperand[i];
                }

                resultLength = max;
                ECNumInternalOp.trim(result, ref resultLength);
                return result;
            }
            internal static void SubSingle(ref uint[] left, ref int leftLength, uint right) //Tested OK.
            {
                int max = leftLength;

                long carry = 0;

                long diff = (long)left[0] - (long)right - carry;
                left[0] = (uint)(diff);

                if (diff < 0)
                    carry = 1;
                else
                    carry = 0;

                for (int i = 1; i < max && carry > 0; i++)
                {
                    diff = (long)left[i] - carry;
                    left[i] = (uint)(diff);

                    if (diff < 0)
                        carry = 1;
                    else
                        carry = 0;
                }
                leftLength = max;
                ECNumInternalOp.trim(left, ref leftLength);
            }

            internal static void ShiftLeft(ref uint[] digits, ref int digitLength, int shift) //Tested OK. 
            {
                if (shift == 0) return;

                int digitShift = shift / 32;
                int smallShift = shift - (digitShift * 32);

                int xl = digitLength;

                int zl = xl + digitShift + 1;
                uint[] zd = new uint[zl];

                if (smallShift == 0)
                    for (int i = 0; i < xl; i++)
                        zd[i + digitShift] = digits[i];
                else
                {
                    int carryShift = 32 - smallShift;
                    uint carry = 0;
                    int i;
                    for (i = 0; i < xl; i++)
                    {
                        uint rot = digits[i];
                        zd[i + digitShift] = rot << smallShift | carry;
                        carry = rot >> carryShift;
                    }
                    zd[i + digitShift] = carry;
                }
                digits = zd;
                if (zd[zl - 1] == 0)
                    digitLength = zl - 1;
                else
                    digitLength = zl;
                ECNumInternalOp.trim(digits, ref digitLength);
            }
            internal static uint[] ShiftLeft(uint[] digits, ref int digitLength, int shift) //Tested OK. 
            {
                if (shift == 0) return digits.Clone() as uint[];

                int digitShift = shift / 32;
                int smallShift = shift - (digitShift * 32);

                int xl = digitLength;

                int zl = xl + digitShift + 1;
                uint[] zd = new uint[zl];

                if (smallShift == 0)
                    for (int i = 0; i < xl; i++)
                        zd[i + digitShift] = digits[i];
                else
                {
                    int carryShift = 32 - smallShift;
                    uint carry = 0;
                    int i;
                    for (i = 0; i < xl; i++)
                    {
                        uint rot = digits[i];
                        zd[i + digitShift] = rot << smallShift | carry;
                        carry = rot >> carryShift;
                    }
                    zd[i + digitShift] = carry;
                }
                if (zd[zl - 1] == 0)
                    digitLength = zl - 1;
                else
                    digitLength = zl;
                ECNumInternalOp.trim(zd, ref digitLength);
                return zd;
            }
            internal static void ShiftRight(ref uint[] digits, ref int digitLength, int shift) //Tested OK. 
            {
                int shiftAmount = 32;
                int invShift = 0;
                int bufLen = digits.Length;

                while (bufLen > 1 && digits[bufLen - 1] == 0)
                    bufLen--;

                for (int count = shift; count > 0; )
                {
                    if (count < shiftAmount)
                    {
                        shiftAmount = count;
                        invShift = 32 - shiftAmount;
                    }

                    ulong carry = 0;
                    for (int i = bufLen - 1; i >= 0; i--)
                    {
                        ulong val = ((ulong)digits[i]) >> shiftAmount;
                        val |= carry;

                        carry = ((ulong)digits[i]) << invShift;
                        digits[i] = (uint)(val);
                    }

                    count -= shiftAmount;
                }
                digitLength = bufLen;
                ECNumInternalOp.trim(digits, ref digitLength);
            }

            internal static uint[] And(uint[] left, int leftLength, uint[] right, int rightLength, out int resultLength) //Tested OK.
            {
                int max, min;
                if (leftLength > rightLength)
                {
                    max = leftLength;
                    min = rightLength;
                }
                else
                {
                    max = rightLength;
                    min = leftLength;
                }

                uint[] result = new uint[min];
                int i;
                for (i = 0; i < min; i++)
                    result[i] = left[i] & right[i];

                resultLength = min;
                ECNumInternalOp.trim(result, ref resultLength);
                return result;
            }
            internal static void And(ref uint[] left, ref int leftLength, uint[] right, int rightLength) //Tested OK.
            {
                if (leftLength < rightLength)
                    throw new InvalidOperationException("sol operandın uzunluğu sağdakinden büyük veya eşit olmalı.");
                for (int i = 0; i < rightLength; i++)
                    left[i] = left[i] & right[i];
                for (int i = rightLength; i < leftLength; i++)
                    left[i] = 0;
                leftLength = leftLength - rightLength;
            }
            internal static int Compare(uint[] left, int leftLength, uint[] right, int rightLength) //Tested OK.
            {
                if (leftLength > rightLength)
                    return 1;
                else if (leftLength < rightLength)
                    return -1;
                else
                {
                    for (int i = leftLength - 1; i >= 0; i--)
                    {
                        int c = left[i].CompareTo(right[i]);
                        if (c != 0)
                            return c;
                    }
                    return 0;
                }
            }
            internal static void Not(ref uint[] digits, ref int digitLength) //Tested OK.
            {
                for (int i = 0; i < digitLength; i++)
                    digits[i] = ~digits[i];
            }
            internal static uint[] Or(uint[] left, int leftLength, uint[] right, int rightLength) //Tested OK.
            {
                int max, min; uint[] maxOperand;
                if (leftLength > rightLength)
                {
                    max = leftLength;
                    min = rightLength;
                    maxOperand = left;
                }
                else
                {
                    max = rightLength;
                    min = leftLength;
                    maxOperand = right;
                }

                uint[] result = new uint[max];
                int i;
                for (i = 0; i < min; i++)
                    result[i] = left[i] | right[i];
                for (; i < max; i++)
                    result[i] = maxOperand[i];
                return result;
            }
            internal static void Or(ref uint[] left, int leftLength, uint[] right, int rightLength) //Tested OK.
            {
                if (leftLength < rightLength)
                    throw new InvalidOperationException("sol operandın uzunluğu sağdakinden büyük veya eşit olmalı.");
                int min = Math.Min(leftLength, rightLength);
                for (int i = 0; i < min; i++)
                    left[i] = left[i] | right[i];
            }
            internal static uint[] Xor(uint[] left, int leftLength, uint[] right, int rightLength) //Tested OK.
            {
                int max, min; uint[] maxOperand;
                if (leftLength > rightLength)
                {
                    max = leftLength;
                    min = rightLength;
                    maxOperand = left;
                }
                else
                {
                    max = rightLength;
                    min = leftLength;
                    maxOperand = right;
                }

                uint[] result = new uint[max];
                int i;
                for (i = 0; i < min; i++)
                    result[i] = left[i] ^ right[i];
                for (; i < max; i++)
                    result[i] = maxOperand[i];
                return result;
            }
            internal static void Xor(ref uint[] left, int leftLength, uint[] right, int rightLength) //Tested OK.
            {
                if (leftLength < rightLength)
                    throw new InvalidOperationException("sol operandın uzunluğu sağdakinden büyük veya eşit olmalı.");
                int min = Math.Min(leftLength, rightLength);
                for (int i = 0; i < min; i++)
                    left[i] = left[i] ^ right[i];
            }

            internal static long UnsignedBitsLength(uint[] digits, int digitLength) //Tested OK.
            {
                if (digitLength == 0)
                    return 0;

                uint uiLast = digits[digitLength - 1];
                return 32 * (long)digitLength - ECNumInternalOp.countOfZeroBitStart(uiLast);
            }
            internal static long SignedBitsLength(uint[] digits, int digitLength, int sign) //Tested OK.
            {
                if (sign == 0)
                    return 1;
                if (digitLength == 1 && digits[0] == 0)
                    return 1;

                uint lastDigit = digits[digitLength - 1];
                byte lastByte = 0;
                int bitsLength = digitLength * 32;

                if ((lastByte = (byte)(lastDigit >> 24)) != 0) { }
                else if ((lastByte = (byte)(lastDigit >> 16)) != 0) { bitsLength -= 8; }
                else if ((lastByte = (byte)(lastDigit >> 8)) != 0) { bitsLength -= 16; }
                else if ((lastByte = (byte)(lastDigit)) != 0) { bitsLength -= 24; }

                if ((lastByte >> 7) == 1 && sign == -1)
                    bitsLength += 8;
                return bitsLength;
            }
            internal static int UnsignedBytesLength(uint[] digits, int digitLength) //Tested OK.
            {
                if (digitLength == 1 && digits[0] == 0)
                    return 1;

                uint uiLast = digits[digitLength - 1];
                int bytesLength = 4 * digitLength;
                if (uiLast >> 8 == 0)
                    bytesLength -= 3;
                else if (uiLast >> 16 == 0)
                    bytesLength -= 2;
                else if (uiLast >> 24 == 0)
                    bytesLength -= 1;
                return bytesLength;
            }
            internal static int SignedBytesLength(uint[] digits, int digitLength, int sign) //Tested OK.
            {
                if (sign == 0)
                    return 1;
                if (digitLength == 1 && digits[0] == 0)
                    return 1;

                uint lastDigit = digits[digitLength - 1];
                byte lastByte = 0;
                int bytesLength = digitLength * 4;

                if ((lastByte = (byte)(lastDigit >> 24)) != 0) { }
                else if ((lastByte = (byte)(lastDigit >> 16)) != 0) { bytesLength -= 1; }
                else if ((lastByte = (byte)(lastDigit >> 8)) != 0) { bytesLength -= 2; }
                else if ((lastByte = (byte)(lastDigit)) != 0) { bytesLength -= 3; }

                if ((lastByte >> 7) == 1)
                    bytesLength++;
                return bytesLength;
            }
            internal static string ToString(uint[] digits, int digitLength, int sign) //Tested OK.
            {
                if (sign == 0)
                    return "0";
                else if (digitLength == 0)
                    return "0";
                else if (digitLength == 1 && sign == 1)
                    return digits[0].ToString();

                const uint kuBase = 1000000000; // 10^9

                int cuMax = digitLength * 10 / 9 + 2;

                uint[] rguDst = new uint[cuMax];
                int cuDst = 0;

                for (int iuSrc = digitLength; --iuSrc >= 0; )
                {
                    uint uCarry = digits[iuSrc];
                    for (int iuDst = 0; iuDst < cuDst; iuDst++)
                    {
                        ulong uuRes = ((ulong)rguDst[iuDst] << 32) | uCarry;
                        rguDst[iuDst] = (uint)(uuRes % kuBase);
                        uCarry = (uint)(uuRes / kuBase);
                    }
                    if (uCarry != 0)
                    {
                        rguDst[cuDst++] = uCarry % kuBase;
                        uCarry /= kuBase;
                        if (uCarry != 0)
                            rguDst[cuDst++] = uCarry;
                    }
                }

                int cchMax = cuDst * 9;

                int rgchBufSize = cchMax + 1;
                char[] rgch;

                if (sign == -1)
                {
                    rgchBufSize++;
                    rgch = new char[rgchBufSize];
                }
                else
                    rgch = new char[rgchBufSize];


                int ichDst = cchMax;

                for (int iuDst = 0; iuDst < cuDst - 1; iuDst++)
                {
                    uint uDig = rguDst[iuDst];
                    for (int cch = 9; --cch >= 0; )
                    {
                        rgch[--ichDst] = (char)('0' + uDig % 10);
                        uDig /= 10;
                    }
                }
                for (uint uDig = rguDst[cuDst - 1]; uDig != 0; )
                {
                    rgch[--ichDst] = (char)('0' + uDig % 10);
                    uDig /= 10;
                }
                if (sign == -1)
                {
                    rgch[--ichDst] = '-';
                    return new String(rgch, ichDst, cchMax - ichDst);
                }
                else
                    return new String(rgch, ichDst, cchMax - ichDst);
            }
            internal static uint[] UnsignedParse(string value, out int digitLength) //Tested OK.
            {
                int offset = 0;
                const uint cBase = 100000000;
                uint[] digitsBase10Pow8 = new uint[value.Length / 8 + Math.Sign(offset = value.Length % 8)];
                if (offset == 0)
                    digitsBase10Pow8[digitsBase10Pow8.Length - 1] = uint.Parse(value.Substring(0, offset += 8));
                else
                    digitsBase10Pow8[digitsBase10Pow8.Length - 1] = uint.Parse(value.Substring(0, offset));

                char[] chars = new char[8];
                for (int i = digitsBase10Pow8.Length - 2; i >= 0; i--)
                {
                    value.CopyTo(offset, chars, 0, 8);
                    offset += 8;
                    digitsBase10Pow8[i] = uint.Parse(new string(chars));
                }

                digitLength = digitsBase10Pow8.Length;
                uint[] data = new uint[digitLength];

                ECNumInternalOp.AddSingle(ref data, ref digitLength, digitsBase10Pow8[digitsBase10Pow8.Length - 1]);
                for (int i = digitsBase10Pow8.Length - 2; i >= 0; i--)
                {
                    data = ECNumInternalOp.MulSingle(data, digitLength, cBase, out digitLength);
                    ECNumInternalOp.AddSingle(ref data, ref digitLength, digitsBase10Pow8[i]);
                }
                return data;
            }
            internal static uint[] SignedParse(string value, out int digitLength, out int sign) //Tested OK.
            {
                if (value[0] == '-')
                {
                    sign = -1;
                    uint[] digits = ECNumInternalOp.UnsignedParse(value.Substring(1, value.Length - 1), out digitLength);
                    if (digitLength == 1 && digits[0] == 0)
                        sign = 0;
                    return digits;
                }
                else if (value == "0")
                {
                    sign = 0;
                    digitLength = 1;
                    return new uint[1];
                }
                else
                {
                    sign = 1;
                    return ECNumInternalOp.UnsignedParse(value, out digitLength);
                }
            }
            internal static byte[] GetUnsignedBytes(uint[] digits, int digitLength, bool bigEndian) //Tested OK.
            {
                if (digitLength == 1 && digits[0] == 0)
                    return new byte[1];
                int bytesLength = ECNumInternalOp.UnsignedBytesLength(digits, digitLength);
                byte[] bytes = new byte[bytesLength];
                if (bigEndian)
                {
                    int bytesPos = 0;
                    int dataPos = digitLength - 1;
                    uint first = digits[dataPos--];

                    int nullBytesLength = ECNumInternalOp.countOfZeroBitStart(first) / 8;

                    while (nullBytesLength == 4)
                    {
                        first = digits[dataPos--];
                        nullBytesLength = ECNumInternalOp.countOfZeroBitStart(first) / 8;
                    }

                    if (nullBytesLength == 3)
                    {
                        bytes[bytesPos++] = (byte)first;
                    }
                    else if (nullBytesLength == 2)
                    {
                        bytes[bytesPos++] = (byte)(first >> 8);
                        bytes[bytesPos++] = (byte)first;
                    }
                    else if (nullBytesLength == 1)
                    {
                        bytes[bytesPos++] = (byte)(first >> 16);
                        bytes[bytesPos++] = (byte)(first >> 8);
                        bytes[bytesPos++] = (byte)first;
                    }
                    else if (nullBytesLength == 0)
                    {
                        bytes[bytesPos++] = (byte)(first >> 24);
                        bytes[bytesPos++] = (byte)(first >> 16);
                        bytes[bytesPos++] = (byte)(first >> 8);
                        bytes[bytesPos++] = (byte)first;
                    }

                    while (dataPos > -1)
                    {
                        uint current = digits[dataPos--];
                        bytes[bytesPos++] = (byte)(current >> 24);
                        bytes[bytesPos++] = (byte)(current >> 16);
                        bytes[bytesPos++] = (byte)(current >> 8);
                        bytes[bytesPos++] = (byte)(current);
                    }
                }
                else
                {
                    int bytesPos = 0;
                    int dataPos = 0;
                    int lastDigit = digitLength - 1;
                    while (dataPos < lastDigit)
                    {
                        uint current = digits[dataPos++];
                        bytes[bytesPos++] = (byte)(current);
                        bytes[bytesPos++] = (byte)(current >> 8);
                        bytes[bytesPos++] = (byte)(current >> 16);
                        bytes[bytesPos++] = (byte)(current >> 24);
                    }
                    uint uiLast = digits[lastDigit];
                    int nullDataLength = ECNumInternalOp.countOfZeroBitStart(uiLast) / 8;

                    if (nullDataLength == 0)
                    {
                        bytes[bytesPos++] = (byte)(uiLast);
                        bytes[bytesPos++] = (byte)(uiLast >> 8);
                        bytes[bytesPos++] = (byte)(uiLast >> 16);
                        bytes[bytesPos++] = (byte)(uiLast >> 24);
                    }
                    else if (nullDataLength == 1)
                    {
                        bytes[bytesPos++] = (byte)(uiLast);
                        bytes[bytesPos++] = (byte)(uiLast >> 8);
                        bytes[bytesPos++] = (byte)(uiLast >> 16);
                    }
                    else if (nullDataLength == 2)
                    {
                        bytes[bytesPos++] = (byte)(uiLast);
                        bytes[bytesPos++] = (byte)(uiLast >> 8);
                    }
                    else if (nullDataLength == 3)
                    {
                        bytes[bytesPos++] = (byte)(uiLast);
                    }
                }
                return bytes;
            }
            internal static uint[] FromUnsignedBytes(byte[] data, bool bigEndian, out int digitLength) //Tested OK.
            {
                digitLength = data.Length / 4;
                if ((data.Length & 3) > 0)
                    digitLength++;

                uint[] digits = new uint[digitLength];

                if (bigEndian)
                {
                    int digitPos = digitLength - 1;
                    int dataPos = 0;

                    int nullDataLength = data.Length & 3;
                    if (nullDataLength == 1)
                    {
                        digits[digitPos--] = data[dataPos++];
                    }
                    else if (nullDataLength == 2)
                    {
                        uint digit = 0;
                        digit |= (uint)(data[dataPos++] << 8);
                        digit |= (uint)(data[dataPos++]);
                        digits[digitPos--] = digit;
                    }
                    else if (nullDataLength == 3)
                    {
                        uint digit = 0;
                        digit |= (uint)(data[dataPos++] << 16);
                        digit |= (uint)(data[dataPos++] << 8);
                        digit |= (uint)(data[dataPos++]);
                        digits[digitPos--] = digit;
                    }

                    while (digitPos > -1)
                    {
                        uint current = 0;
                        current |= (uint)(data[dataPos++] << 24);
                        current |= (uint)(data[dataPos++] << 16);
                        current |= (uint)(data[dataPos++] << 8);
                        current |= (uint)(data[dataPos++]);
                        digits[digitPos--] = current;
                    }
                }
                else
                {
                    int digitPos = 0;
                    int dataPos = 0;
                    int lastDigitPos = digitLength - 1;
                    while (digitPos < lastDigitPos)
                    {
                        uint current = 0;
                        current |= (uint)(data[dataPos++]);
                        current |= (uint)(data[dataPos++] << 8);
                        current |= (uint)(data[dataPos++] << 16);
                        current |= (uint)(data[dataPos++] << 24);
                        digits[digitPos++] = current;
                    }

                    int nullDataLength = data.Length & 3;

                    if (nullDataLength == 1)
                    {
                        digits[lastDigitPos] = data[dataPos++];
                    }
                    else if (nullDataLength == 2)
                    {
                        uint digit = 0;
                        digit |= (uint)(data[dataPos++]);
                        digit |= (uint)(data[dataPos++] << 8);
                        digits[lastDigitPos] = digit;
                    }
                    else if (nullDataLength == 3)
                    {
                        uint digit = 0;
                        digit |= (uint)(data[dataPos++]);
                        digit |= (uint)(data[dataPos++] << 8);
                        digit |= (uint)(data[dataPos++] << 16);
                        digits[lastDigitPos] = digit;
                    }
                    else if (nullDataLength == 0)
                    {
                        uint digit = 0;
                        digit |= (uint)(data[dataPos++]);
                        digit |= (uint)(data[dataPos++] << 8);
                        digit |= (uint)(data[dataPos++] << 16);
                        digit |= (uint)(data[dataPos++] << 24);
                        digits[lastDigitPos] = digit;
                    }
                }
                ECNumInternalOp.trim(digits, ref digitLength);
                return digits;
            }
            internal static int GetBit(uint[] digits, int digitLength, long bitPosition) //Tested OK.
            {
                int digitPos = (int)(bitPosition / 32);
                if (digitLength <= digitPos)
                    return 0;

                int smallBitPos = (int)(bitPosition & 31);
                return (int)((digits[digitPos] >> smallBitPos) & 1);
            }
            internal static void SetBit(ref uint[] digits, ref int digitLength, long bitPosition, int bit)
            {
                int setDigPos = (int)(bitPosition / 32);
                int smallPos = (int)(bitPosition & 31);

                if (bit == 1)
                {
                    if (setDigPos > digitLength - 1)
                    {
                        digitLength = setDigPos + 1;
                        Array.Resize(ref digits, digitLength);
                    }
                    digits[setDigPos] |= ((uint)1 << smallPos);
                }
                else
                {
                    if (setDigPos < digitLength)
                        digits[setDigPos] &= ~((uint)1 << smallPos);

                    ECNumInternalOp.trim(digits, ref digitLength);
                }
            }
            internal static byte[] GetSignedBytes(uint[] digits, int digitLength, bool bigEndian, int sign) //Tested OK.
            {
                if (sign == 0)
                    return new byte[1];

                if (sign == -1)
                {
                    uint[] cDig = digits.Clone() as uint[];
                    ECNumInternalOp.SubSingle(ref cDig, ref digitLength, 1);
                    digits = cDig;
                }

                int bytesLength = ECNumInternalOp.UnsignedBytesLength(digits, digitLength);

                uint lastDigit = digits[digitLength - 1];
                byte lastByte = 0;

                if ((lastByte = (byte)(lastDigit >> 24)) != 0) { }
                else if ((lastByte = (byte)(lastDigit >> 16)) != 0) { }
                else if ((lastByte = (byte)(lastDigit >> 8)) != 0) { }
                else if ((lastByte = (byte)(lastDigit)) != 0) { }

                bool isLastBitOne = (lastByte >> 7) == 1;
                byte[] bytes;
                int nullBytesLength = ECNumInternalOp.countOfZeroBitStart(lastDigit) / 8;

                if (bigEndian)
                {
                    int digitPos = digitLength - 2;
                    int bytesPos = 0;
                    if (isLastBitOne)
                    {
                        bytesLength++;
                        bytes = new byte[bytesLength];
                        bytesPos++;
                        //if (sign == -1)
                        //{
                        //    bytes[bytesPos++] = 128;
                        //}
                        //else
                        //    bytesPos++;
                    }
                    else
                    {
                        bytes = new byte[bytesLength];
                        //if (sign == -1)
                        //    lastByte |= 128;
                    }
                    if (nullBytesLength == 0)
                    {
                        bytes[bytesPos++] = lastByte;
                        bytes[bytesPos++] = (byte)(lastDigit >> 16);
                        bytes[bytesPos++] = (byte)(lastDigit >> 8);
                        bytes[bytesPos++] = (byte)lastDigit;
                    }
                    else if (nullBytesLength == 1)
                    {
                        bytes[bytesPos++] = lastByte;
                        bytes[bytesPos++] = (byte)(lastDigit >> 8);
                        bytes[bytesPos++] = (byte)lastDigit;
                    }
                    else if (nullBytesLength == 2)
                    {
                        bytes[bytesPos++] = lastByte;
                        bytes[bytesPos++] = (byte)lastDigit;
                    }
                    else if (nullBytesLength == 3)
                        bytes[bytesPos++] = lastByte;

                    while (digitPos > -1)
                    {
                        uint digit = digits[digitPos--];
                        bytes[bytesPos++] = (byte)(digit >> 24);
                        bytes[bytesPos++] = (byte)(digit >> 16);
                        bytes[bytesPos++] = (byte)(digit >> 8);
                        bytes[bytesPos++] = (byte)digit;
                    }
                    if (sign == -1)
                    {
                        for (int i = 0; i < bytes.Length; i++)
                        {
                            bytes[i] = (byte)(~bytes[i]);
                        }

                    }
                }
                else
                {
                    int digitPos = 0;
                    int bytesPos = 0;

                    if (isLastBitOne)
                    {
                        bytesLength++;
                        bytes = new byte[bytesLength];
                        //if (sign == -1)
                        //    bytes[bytesLength - 1] = 128;
                    }
                    else
                    {
                        bytes = new byte[bytesLength];
                        //if (sign == -1)
                        //    lastByte |= 128;
                    }

                    while (digitPos < digitLength - 1)
                    {
                        uint digit = digits[digitPos++];
                        bytes[bytesPos++] = (byte)digit;
                        bytes[bytesPos++] = (byte)(digit >> 8);
                        bytes[bytesPos++] = (byte)(digit >> 16);
                        bytes[bytesPos++] = (byte)(digit >> 24);
                    }

                    if (nullBytesLength == 0)
                    {
                        bytes[bytesPos++] = (byte)lastDigit;
                        bytes[bytesPos++] = (byte)(lastDigit >> 8);
                        bytes[bytesPos++] = (byte)(lastDigit >> 16);
                        bytes[bytesPos++] = lastByte;
                    }
                    if (nullBytesLength == 1)
                    {
                        bytes[bytesPos++] = (byte)lastDigit;
                        bytes[bytesPos++] = (byte)(lastDigit >> 8);
                        bytes[bytesPos++] = lastByte;
                    }
                    else if (nullBytesLength == 2)
                    {
                        bytes[bytesPos++] = (byte)lastDigit;
                        bytes[bytesPos++] = lastByte;
                    }
                    else if (nullBytesLength == 3)
                        bytes[bytesPos++] = lastByte;

                    if (sign == -1)
                    {
                        for (int i = 0; i < bytes.Length; i++)
                            bytes[i] = (byte)(~bytes[i]);
                    }
                }
                return bytes;
            }
            internal static uint[] FromSignedBytes(byte[] data, bool bigEndian, out int digitLength, out int sign) //Tested OK.
            {
                if (data.Length == 1)
                {
                    digitLength = 1;
                    if (data[0] == 0)
                    {
                        sign = 0;
                        return new uint[1];
                    }
                    else if (data[0] > 127)
                    {
                        sign = -1;
                        return new uint[1] { (uint)(~data[0] + 1) };
                    }
                    else
                    {
                        sign = 1;
                        return new uint[1] { data[0] };
                    }
                }

                if (bigEndian)
                {
                    byte lastBytes = data[0];
                    byte notLastBytes = (byte)(~lastBytes);
                    int readableLength = data.Length;
                    bool isNeg = notLastBytes < 128;
                    if (notLastBytes == 0)
                        readableLength--;
                    if (!isNeg && lastBytes == 0)
                        readableLength--;

                    digitLength = readableLength / 4;
                    int nullBytesCount = 4 - (readableLength & 3);
                    if (nullBytesCount != 4)
                        digitLength++;

                    int dataPos = data.Length - 1;

                    uint[] digits = new uint[digitLength];
                    int digitPos = 0;
                    int uiLast = digitLength - 1;

                    if (isNeg)
                    {
                        while (digitPos < uiLast)
                        {
                            uint digit = ((byte)(~data[dataPos--]));
                            digit |= (uint)((byte)(~data[dataPos--]) << 8);
                            digit |= (uint)((byte)(~data[dataPos--]) << 16);
                            digit |= (uint)((byte)(~data[dataPos--]) << 24);
                            digits[digitPos++] = digit;
                        }

                        if (nullBytesCount == 4)
                        {
                            uint digit = ((byte)(~data[dataPos--]));
                            digit |= (uint)((byte)(~data[dataPos--]) << 8);
                            digit |= (uint)((byte)(~data[dataPos--]) << 16);
                            digit |= (uint)((byte)(~data[dataPos--]) << 24);
                            digits[uiLast] = digit;
                        }
                        else if (nullBytesCount == 1)
                        {
                            uint digit = ((byte)(~data[dataPos--]));
                            digit |= (uint)((byte)(~data[dataPos--]) << 8);
                            digit |= (uint)((byte)(~data[dataPos--]) << 16);
                            digits[uiLast] = digit;
                        }
                        else if (nullBytesCount == 2)
                        {
                            uint digit = ((byte)(~data[dataPos--]));
                            digit |= (uint)((byte)(~data[dataPos--]) << 8);
                            digits[uiLast] = digit;
                        }
                        else if (nullBytesCount == 3)
                        {
                            digits[uiLast] = ((byte)(~data[dataPos--]));
                        }
                        sign = -1;
                        ECNumInternalOp.AddSingle(ref digits, ref digitLength, 1);
                    }
                    else
                    {
                        while (digitPos < uiLast)
                        {
                            uint digit = data[dataPos--];
                            digit |= (uint)(data[dataPos--] << 8);
                            digit |= (uint)(data[dataPos--] << 16);
                            digit |= (uint)(data[dataPos--] << 24);
                            digits[digitPos++] = digit;
                        }

                        if (nullBytesCount == 4)
                        {
                            uint digit = data[dataPos--];
                            digit |= (uint)(data[dataPos--] << 8);
                            digit |= (uint)(data[dataPos--] << 16);
                            digit |= (uint)(data[dataPos--] << 24);
                            digits[digitPos++] = digit;
                        }
                        else if (nullBytesCount == 1)
                        {
                            uint digit = data[dataPos--];
                            digit |= (uint)(data[dataPos--] << 8);
                            digit |= (uint)(data[dataPos--] << 16);
                            digits[uiLast] = digit;
                        }
                        else if (nullBytesCount == 2)
                        {
                            uint digit = data[dataPos--];
                            digit |= (uint)(data[dataPos--] << 8);
                            digits[uiLast] = digit;
                        }
                        else if (nullBytesCount == 3)
                        {
                            digits[uiLast] = data[dataPos--];
                        }
                        sign = 1;
                    }
                    return digits;
                }
                else
                {
                    byte lastBytes = data[data.Length - 1];
                    byte notLastBytes = (byte)(~lastBytes);
                    int readableLength = data.Length;
                    bool isNeg = notLastBytes < 128;
                    if (notLastBytes == 0)
                        readableLength--;
                    if (!isNeg && lastBytes == 0)
                        readableLength--;

                    digitLength = readableLength / 4;
                    int nullBytesCount = 4 - (readableLength & 3);
                    if (nullBytesCount != 4)
                        digitLength++;

                    uint[] digits = new uint[digitLength];
                    int digitPos = digitLength - 1;
                    int dataPos = readableLength - 1;

                    if (isNeg)
                    {
                        if (nullBytesCount == 1)
                        {
                            uint digit = (uint)((byte)(~data[dataPos--]) << 16);
                            digit |= (uint)((byte)(~data[dataPos--]) << 8);
                            digit |= ((byte)(~data[dataPos--]));
                            digits[digitPos--] = digit;
                        }
                        else if (nullBytesCount == 2)
                        {
                            uint digit = (uint)((byte)(~data[dataPos--]) << 8);
                            digit |= ((byte)(~data[dataPos--]));
                            digits[digitPos--] = digit;
                        }
                        else if (nullBytesCount == 3)
                        {
                            digits[digitPos--] = ((byte)(~data[dataPos--]));
                        }

                        while (digitPos > -1)
                        {
                            uint digit = (uint)((byte)(~data[dataPos--]) << 24);
                            digit |= (uint)((byte)(~data[dataPos--]) << 16);
                            digit |= (uint)((byte)(~data[dataPos--]) << 8);
                            digit |= ((byte)(~data[dataPos--]));
                            digits[digitPos--] = digit;
                        }

                        sign = -1;
                        ECNumInternalOp.AddSingle(ref digits, ref digitLength, 1);
                    }
                    else
                    {
                        if (nullBytesCount == 1)
                        {
                            uint digit = (uint)(data[dataPos--] << 16);
                            digit |= (uint)(data[dataPos--] << 8);
                            digit |= (data[dataPos--]);
                            digits[digitPos--] = digit;
                        }
                        else if (nullBytesCount == 2)
                        {
                            uint digit = (uint)(data[dataPos--] << 8);
                            digit |= (data[dataPos--]);
                            digits[digitPos--] = digit;
                        }
                        else if (nullBytesCount == 3)
                        {
                            digits[digitPos--] = (data[dataPos--]);
                        }

                        while (digitPos > -1)
                        {
                            uint digit = (uint)(data[dataPos--] << 24);
                            digit |= (uint)(data[dataPos--] << 16);
                            digit |= (uint)(data[dataPos--] << 8);
                            digit |= (data[dataPos--]);
                            digits[digitPos--] = digit;
                        }
                        sign = 1;
                    }
                    return digits;
                }
            }

            private static uint addCarry(ref uint u1, uint u2, uint uCarry)
            {
                ulong uu = (ulong)u1 + u2 + uCarry;
                u1 = (uint)uu;
                return (uint)(uu >> 32);
            }
            private static int countOfZeroBitStart(uint u)
            {
                if (u == 0)
                    return 32;

                int cbit = 0;
                if ((u & 0xFFFF0000) == 0)
                {
                    cbit += 16;
                    u <<= 16;
                }
                if ((u & 0xFF000000) == 0)
                {
                    cbit += 8;
                    u <<= 8;
                }
                if ((u & 0xF0000000) == 0)
                {
                    cbit += 4;
                    u <<= 4;
                }
                if ((u & 0xC0000000) == 0)
                {
                    cbit += 2;
                    u <<= 2;
                }
                if ((u & 0x80000000) == 0)
                    cbit += 1;
                return cbit;
            }
            private static void trim(uint[] digits, ref int digitLength)
            {
                while (digits[digitLength - 1] == 0 && digitLength > 1)
                    digitLength--;
            }
        }
    }
}
