using System;
using NUnit.Framework;

namespace OtpNet.Test
{
    [TestFixture()]
    public class OtpUriTest
    {
        private const string _baseSecret = "JBSWY3DPEHPK3PXP";
        private const string _baseUser = "alice@google.com";
        private const string _baseIssuer = "ACME Co";

        [TestCase(_baseSecret, OtpType.Totp, _baseUser, _baseIssuer, OtpHashMode.Sha1, 6, 30, 0,
            "otpauth://totp/ACME%20Co:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20&algorithm=SHA1&digits=6&period=30")]
        public void GenerateOtpUriTest(string secret, OtpType otpType, string user, string issuer,
            OtpHashMode hash, int digits, int period, int counter, string expectedUri)
        {
            var sec = Base32Encoding.ToBytes(secret);
            var uriString = new OtpUri(otpType, sec, user, issuer, hash, digits, period, counter).ToString();
            Assert.That(uriString, Is.EqualTo(expectedUri));
        }
    }
}
