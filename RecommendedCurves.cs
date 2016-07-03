namespace System.Security.Cryptography
{
    internal class SECP112R1 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.3.132.0.6";
        public override string URN { get { return SECP112R1._urn; } }

        public SECP112R1()
        {
            this.A = -3;
            this.B = ECScalar.ParseFromHex("659EF8BA043916EEDE8911702B22");
            this.P = ECScalar.ParseFromHex("DB7C2ABF62E35E668076BEAD208B");
            this.N = ECScalar.ParseFromHex("DB7C2ABF62E35E7628DFAC6561C5");
            this.G = new ECPoint(ECScalar.ParseFromHex("09487239995A5EE76B55F9C2F098"), ECScalar.ParseFromHex("A89CE5AF8724C0A23E0E0FF77500"));
            this.H = ECScalar.One;
            this.BitLength = 112;
            this.CurveName = CurveName.SECP112R1;
        }

    }
    internal class SECP112R2 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.3.132.0.7";
        public override string URN { get { return SECP112R2._urn; } }

        public SECP112R2()
        {
            this.A = ECScalar.ParseFromHex("6127C24C05F38A0AAAF65C0EF02C");
            this.B = ECScalar.ParseFromHex("51DEF1815DB5ED74FCC34C85D709");
            this.P = ECScalar.ParseFromHex("DB7C2ABF62E35E668076BEAD208B");
            this.N = ECScalar.ParseFromHex("36DF0AAFD8B8D7597CA10520D04B");
            this.G = new ECPoint(ECScalar.ParseFromHex("4BA30AB5E892B4E1649DD0928643"), ECScalar.ParseFromHex("ADCD46F5882E3747DEF36E956E97"));
            this.H = 4;
            this.BitLength = 112;
            this.CurveName = CurveName.SECP112R2;
        }

    }
    internal class SECP128R1 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.3.132.0.28";
        public override string URN { get { return SECP128R1._urn; } }

        public SECP128R1()
        {
            this.A = -3;
            this.B = ECScalar.ParseFromHex("E87579C11079F43DD824993C2CEE5ED3");
            this.P = ECScalar.ParseFromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
            this.N = ECScalar.ParseFromHex("FFFFFFFE0000000075A30D1B9038A115");
            this.G = new ECPoint(ECScalar.ParseFromHex("161FF7528B899B2D0C28607CA52C5B86"), ECScalar.ParseFromHex("CF5AC8395BAFEB13C02DA292DDED7A83"));
            this.H = ECScalar.One;
            this.BitLength = 128;
            this.CurveName = CurveName.SECP128R1;
        }

    }
    internal class SECP128R2 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.3.132.0.29";
        public override string URN { get { return SECP128R2._urn; } }

        public SECP128R2()
        {
            this.A = ECScalar.ParseFromHex("D6031998D1B3BBFEBF59CC9BBFF9AEE1");
            this.B = ECScalar.ParseFromHex("5EEEFCA380D02919DC2C6558BB6D8A5D");
            this.P = ECScalar.ParseFromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
            this.N = ECScalar.ParseFromHex("3FFFFFFF7FFFFFFFBE0024720613B5A3");
            this.G = new ECPoint(ECScalar.ParseFromHex("7B6AA5D85E572983E6FB32A7CDEBC140"), ECScalar.ParseFromHex("27B6916A894D3AEE7106FE805FC34B44"));
            this.H = 4;
            this.BitLength = 128;
            this.CurveName = CurveName.SECP128R2;
        }

    }
    internal class SECP160K1 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.3.132.0.9";
        public override string URN { get { return SECP160K1._urn; } }

        public SECP160K1()
        {
            this.A = ECScalar.Zero;
            this.B = 7;
            this.P = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
            this.N = ECScalar.ParseFromHex("100000000000000000001B8FA16DFAB9ACA16B6B3");
            this.G = new ECPoint(ECScalar.ParseFromHex("3B4C382CE37AA192A4019E763036F4F5DD4D7EBB"), ECScalar.ParseFromHex("938CF935318FDCED6BC28286531733C3F03C4FEE"));
            this.H = ECScalar.One;
            this.BitLength = 160;
            this.CurveName = CurveName.SECP160K1;
        }

    }
    internal class SECP160R1 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.3.132.0.8";
        public override string URN { get { return SECP160R1._urn; } }

        public SECP160R1()
        {
            this.A = -3;
            this.B = ECScalar.ParseFromHex("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45");
            this.P = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF");
            this.N = ECScalar.ParseFromHex("100000000000000000001F4C8F927AED3CA752257");
            this.G = new ECPoint(ECScalar.ParseFromHex("4A96B5688EF573284664698968C38BB913CBFC82"), ECScalar.ParseFromHex("23A628553168947D59DCC912042351377AC5FB32"));
            this.H = ECScalar.One;
            this.BitLength = 160;
            this.CurveName = CurveName.SECP160R1;
        }

    }
    internal class SECP160R2 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.3.132.0.30";
        public override string URN { get { return SECP160R2._urn; } }

        public SECP160R2()
        {
            this.A = -3;
            this.B = ECScalar.ParseFromHex("B4E134D3FB59EB8BAB57274904664D5AF50388BA");
            this.P = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
            this.N = ECScalar.ParseFromHex("100000000000000000000351EE786A818F3A1A16B");
            this.G = new ECPoint(ECScalar.ParseFromHex("52DCB034293A117E1F4FF11B30F7199D3144CE6D"), ECScalar.ParseFromHex("FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E"));
            this.H = ECScalar.One;
            this.BitLength = 160;
            this.CurveName = CurveName.SECP160R2;
        }

    }
    internal class SECP192K1 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.3.132.0.31";
        public override string URN { get { return SECP192K1._urn; } }

        public SECP192K1()
        {
            this.A = ECScalar.Zero;
            this.B = 3;
            this.P = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37");
            this.N = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D");
            this.G = new ECPoint(ECScalar.ParseFromHex("DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"), ECScalar.ParseFromHex("9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D"));
            this.H = ECScalar.One;
            this.BitLength = 192;
            this.CurveName = CurveName.SECP192K1;
        }

    }
    internal class SECP192R1 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.2.840.10045.3.1.1";
        public override string URN { get { return SECP192R1._urn; } }

        public SECP192R1()
        {
            this.A = -3;
            this.B = ECScalar.ParseFromHex("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1");
            this.P = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
            this.N = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
            this.G = new ECPoint(ECScalar.ParseFromHex("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"), ECScalar.ParseFromHex("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"));
            this.H = ECScalar.One;
            this.BitLength = 192;
            this.CurveName = CurveName.SECP192R1;
        }

    }
    internal class SECP224K1 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.3.132.0.32";
        public override string URN { get { return SECP224K1._urn; } }

        public SECP224K1()
        {
            this.A = ECScalar.Zero;
            this.B = 5;
            this.P = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D");
            this.N = ECScalar.ParseFromHex("10000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7");
            this.G = new ECPoint(ECScalar.ParseFromHex("A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C"), ECScalar.ParseFromHex("7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5"));
            this.H = ECScalar.One;
            this.BitLength = 224;
            this.CurveName = CurveName.SECP224K1;
        }

    }
    internal class SECP224R1 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.3.132.0.33";
        public override string URN { get { return SECP224R1._urn; } }

        public SECP224R1()
        {
            this.A = -3;
            this.B = ECScalar.ParseFromHex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
            this.P = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
            this.N = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
            this.G = new ECPoint(ECScalar.ParseFromHex("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"), ECScalar.ParseFromHex("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"));
            this.H = ECScalar.One;
            this.BitLength = 224;
            this.CurveName = CurveName.SECP224R1;
        }

    }
    internal class SECP256K1 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.3.132.0.10";
        public override string URN { get { return SECP256K1._urn; } }

        public SECP256K1()
        {
            this.A = ECScalar.Zero;
            this.B = 7;
            this.P = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
            this.N = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
            this.G = new ECPoint(ECScalar.ParseFromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"), ECScalar.ParseFromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"));
            this.H = ECScalar.One;
            this.BitLength = 256;
            this.CurveName = CurveName.SECP256K1;
        }

    }
    internal class SECP256R1 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.2.840.10045.3.1.7";
        public override string URN { get { return SECP256R1._urn; } }

        public SECP256R1()
        {
            this.A = -3;
            this.B = ECScalar.ParseFromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
            this.P = ECScalar.ParseFromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
            this.N = ECScalar.ParseFromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
            this.G = new ECPoint(ECScalar.ParseFromHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"), ECScalar.ParseFromHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));
            this.H = ECScalar.One;
            this.BitLength = 256;
            this.CurveName = CurveName.SECP256R1;
        }

    }
    internal class SECP384R1 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.3.132.0.34";
        public override string URN { get { return SECP384R1._urn; } }

        public SECP384R1()
        {
            this.A = -3;
            this.B = ECScalar.ParseFromHex("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF");
            this.P = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF");
            this.N = ECScalar.ParseFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973");
            this.G = new ECPoint(ECScalar.ParseFromHex("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"), ECScalar.ParseFromHex("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"));
            this.H = ECScalar.One;
            this.BitLength = 384;
            this.CurveName = CurveName.SECP384R1;
        }

    }
    internal class SECP521R1 : GFpGroupCurves
    {
        private const string _urn = "urn:oid:1.3.132.0.35";
        public override string URN { get { return SECP521R1._urn; } }

        public SECP521R1()
        {
            this.A = -3;
            this.B = ECScalar.ParseFromHex("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00");
            this.P = ECScalar.ParseFromHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
            this.N = ECScalar.ParseFromHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409");
            this.G = new ECPoint(ECScalar.ParseFromHex("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"), ECScalar.ParseFromHex("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"));
            this.H = ECScalar.One;
            this.BitLength = 521;
            this.CurveName = CurveName.SECP521R1;
        }

    }
}