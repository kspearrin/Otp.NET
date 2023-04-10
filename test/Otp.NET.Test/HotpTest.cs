using Moq;
using NUnit.Framework;

namespace OtpNet.Test;

[TestFixture]
public class HotpTest
{
    private static readonly byte[] rfc4226Secret = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x30
        };

    [TestCase(OtpHashMode.Sha1, 0, "755224")]
    [TestCase(OtpHashMode.Sha1, 1, "287082")]
    [TestCase(OtpHashMode.Sha1, 2, "359152")]
    [TestCase(OtpHashMode.Sha1, 3, "969429")]
    [TestCase(OtpHashMode.Sha1, 4, "338314")]
    [TestCase(OtpHashMode.Sha1, 5, "254676")]
    [TestCase(OtpHashMode.Sha1, 6, "287922")]
    [TestCase(OtpHashMode.Sha1, 7, "162583")]
    [TestCase(OtpHashMode.Sha1, 8, "399871")]
    [TestCase(OtpHashMode.Sha1, 9, "520489")]
    public void ComputeHOTPRfc4226Test(OtpHashMode hash, long counter, string expectedOtp)
    {
        Hotp otpCalc = new Hotp(rfc4226Secret, hash, expectedOtp.Length);
        string otp = otpCalc.ComputeHOTP(counter);
        Assert.That(otp, Is.EqualTo(expectedOtp));
    }

    [Test]
    public void ContructorWithKeyProviderTest()
    {
        //Mock a key provider which always returns an all-zero HMAC (causing an all-zero OTP)
        Mock<IKeyProvider> keyMock = new Mock<IKeyProvider>();
        keyMock.Setup(key => key.ComputeHmac(It.Is<OtpHashMode>(m => m == OtpHashMode.Sha1), It.IsAny<byte[]>())).Returns(new byte[20]);

        var otp = new Hotp(keyMock.Object, OtpHashMode.Sha1, 6);
        Assert.That(otp.ComputeHOTP(0), Is.EqualTo("000000"));
        Assert.That(otp.ComputeHOTP(1), Is.EqualTo("000000"));
    }
}
