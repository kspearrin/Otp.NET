using NUnit.Framework;

namespace OtpNet.Test;

[TestFixture]
public class OtpUriTest
{
    private const string BaseSecret = "JBSWY3DPEHPK3PXP";
    private const string BaseUser = "alice@google.com";
    private const string BaseIssuer = "ACME Co";

    [TestCase(BaseSecret, OtpType.Totp, BaseUser, BaseIssuer, OtpHashMode.Sha1, 6, 30, 0,
        "otpauth://totp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")]
    [TestCase(BaseSecret, OtpType.Totp, BaseUser, BaseIssuer, OtpHashMode.Sha256, 6, 30, 0,
        "otpauth://totp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=6&period=30")]
    [TestCase(BaseSecret, OtpType.Totp, BaseUser, BaseIssuer, OtpHashMode.Sha512, 6, 30, 0,
        "otpauth://totp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA512&digits=6&period=30")]
    [TestCase(BaseSecret, OtpType.Hotp, BaseUser, BaseIssuer, OtpHashMode.Sha512, 6, 30, 0,
        "otpauth://hotp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA512&digits=6&counter=0")]
    public void GenerateOtpUriTest(string secret, OtpType otpType, string user, string issuer,
        OtpHashMode hash, int digits, int period, int counter, string expectedUri)
    {
        var uriString = new OtpUri(otpType, secret, user, issuer, hash, digits, period, counter).ToString();
        Assert.That(uriString, Is.EqualTo(expectedUri));
    }
}
