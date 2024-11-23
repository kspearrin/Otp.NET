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

        var parsedOtpUri = new OtpUri(expectedUri);
        Assert.That(parsedOtpUri.Secret, Is.EqualTo(secret));
        Assert.That(parsedOtpUri.Type, Is.EqualTo(otpType));
        Assert.That(parsedOtpUri.User, Is.EqualTo(user));
        Assert.That(parsedOtpUri.Issuer, Is.EqualTo(issuer));
        Assert.That(parsedOtpUri.Algorithm, Is.EqualTo(hash));
        Assert.That(parsedOtpUri.Digits, Is.EqualTo(digits));
        Assert.That(parsedOtpUri.Period, Is.EqualTo(period));
        Assert.That(parsedOtpUri.Counter, Is.EqualTo(counter));
    }

    [TestCase(BaseSecret, OtpType.Totp, BaseUser, BaseIssuer, OtpHashMode.Sha1, 6, 30, 0,
        "otpauth://totp/ACME%20Co:%20alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")]
    [TestCase(BaseSecret, OtpType.Totp, BaseUser, BaseIssuer, OtpHashMode.Sha1, 6, 30, 0,
        "otpauth://totp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP")]
    [TestCase(BaseSecret, OtpType.Totp, BaseUser, BaseIssuer, OtpHashMode.Sha1, 6, 30, 0,
        "otpauth://totp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30")]
    [TestCase(BaseSecret, OtpType.Totp, BaseUser, BaseIssuer, OtpHashMode.Sha1, 6, 30, 0,
        "otpauth://totp/alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")]
    [TestCase(BaseSecret, OtpType.Totp, BaseUser, BaseIssuer, OtpHashMode.Sha1, 6, 30, 0,
        "otpauth://totp/ACME%20Co%3Aalice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")]
    public void ParseOtpUriTest(string expectedSecret, OtpType expectedOtpType, string expectedUser, string expectedIssuer,
        OtpHashMode expectedHash, int expectedDigits, int expectedPeriod, int expectedCounter, string uri)
    {
        var parsedOtpUri = new OtpUri(uri);
        Assert.That(parsedOtpUri.Secret, Is.EqualTo(expectedSecret));
        Assert.That(parsedOtpUri.Type, Is.EqualTo(expectedOtpType));
        Assert.That(parsedOtpUri.User, Is.EqualTo(expectedUser));
        Assert.That(parsedOtpUri.Issuer, Is.EqualTo(expectedIssuer));
        Assert.That(parsedOtpUri.Algorithm, Is.EqualTo(expectedHash));
        Assert.That(parsedOtpUri.Digits, Is.EqualTo(expectedDigits));
        Assert.That(parsedOtpUri.Period, Is.EqualTo(expectedPeriod));
        Assert.That(parsedOtpUri.Counter, Is.EqualTo(expectedCounter));
    }

    [TestCase("http://totp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")]  // invalid scheme
    [TestCase("otpauth://invalid/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")] // invalid type
    [TestCase("otpauth://totp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Different&algorithm=SHA1&digits=6&period=30")] // different issuers
    [TestCase("otpauth://totp/ACME%20Co:alice%40google.com?issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")] // missing secret
    [TestCase("otpauth://totp/ACME%20Co:alice%40google.com?secret=1IsInvalid&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")] // invalid secret
    [TestCase("otpauth://totp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=Invalid&digits=6&period=30")] // invalid algorithm
    [TestCase("otpauth://totp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=invalid&period=30")] // invalid digits
    [TestCase("otpauth://totp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=-1&period=30")] // negative digits
    [TestCase("otpauth://totp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=invalid")] // invalid period
    [TestCase("otpauth://totp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=-1")] // negative period
    [TestCase("otpauth://totp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30&counter=0")] // counter with totp
    [TestCase("otpauth://hotp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")] // period with htop
    [TestCase("otpauth://hotp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&counter=invalid")] // invalid counter
    [TestCase("otpauth://hotp/ACME%20Co:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&counter=-1")] // negative counter
    public void ParseInvalidOtpUriTest(string uri)
    {
        void Constructor()
        {
            var _ = new OtpUri(uri);
        }

        Assert.Throws<System.ArgumentException>(Constructor);
    }
}
