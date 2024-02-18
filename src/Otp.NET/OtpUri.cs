using System;
using System.Collections.Generic;
using System.Text;

namespace OtpNet;

// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
public class OtpUri
{
    /// <summary>
    /// Create a new OTP Auth Uri
    /// </summary>
    public OtpUri(
        OtpType schema,
        string secret,
        string user,
        string issuer = null,
        OtpHashMode algorithm = OtpHashMode.Sha1,
        int digits = 6,
        int period = 30,
        int counter = 0)
    {
        _ = secret ?? throw new ArgumentNullException(nameof(secret));
        _ = user ?? throw new ArgumentNullException(nameof(user));
        if (digits < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(digits));
        }

        Type = schema;
        Secret = secret;
        User = user;
        Issuer = issuer;
        Algorithm = algorithm;
        Digits = digits;

        switch (Type)
        {
            case OtpType.Totp:
                Period = period;
                break;
            case OtpType.Hotp:
                Counter = counter;
                break;
        }
    }

    /// <summary>
    /// Create a new OTP Auth Uri
    /// </summary>
    public OtpUri(
        OtpType schema,
        byte[] secret,
        string user,
        string issuer = null,
        OtpHashMode algorithm = OtpHashMode.Sha1,
        int digits = 6,
        int period = 30,
        int counter = 0)
        : this(schema, Base32Encoding.ToString(secret), user, issuer,
              algorithm, digits, period, counter)
    { }

    /// <summary>
    /// What type of OTP is this uri for
    /// <seealso cref="OtpType"/>
    /// </summary>
    public OtpType Type { get; private set; }

    /// <summary>
    /// The secret parameter is an arbitrary key value encoded in Base32 according to RFC 3548.
    /// The padding specified in RFC 3548 section 2.2 is not required and should be omitted.
    /// </summary>
    public string Secret { get; private set; }

    /// <summary>
    /// Which account a key is associated with
    /// </summary>
    public string User { get; private set; }

    /// <summary>
    /// The issuer parameter is a string value indicating the provider or service this account is
    /// associated with, URL-encoded according to RFC 3986.
    /// </summary>
    public string Issuer { get; private set; }

    /// <summary>
    /// The algorithm used by the generator
    /// </summary>
    public OtpHashMode Algorithm { get; private set; }

    /// <summary>
    /// The amount of digits in the final code
    /// </summary>
    public int Digits { get; private set; }

    /// <summary>
    /// The number of seconds that a code is valid. Only applies to TOTP, not HOTP
    /// </summary>
    public int Period { get; private set; }

    /// <summary>
    /// Initial counter value for HOTP. This is ignored when using TOTP.
    /// </summary>
    public int Counter { get; private set; }

    /// <summary>
    /// Generates a Uri according to the parameters
    /// </summary>
    /// <returns>a Uri according to the parameters</returns>
    public Uri ToUri()
    {
        return new Uri(ToString());
    }

    /// <summary>
    /// Generates a Uri String according to the parameters
    /// </summary>
    /// <returns>a Uri String according to the parameters</returns>
    public override string ToString()
    {
        var parameters = new Dictionary<string, string>
        {
            { "secret", Secret.TrimEnd('=') }
        };

        if (!string.IsNullOrWhiteSpace(Issuer))
        {
            parameters.Add("issuer", Uri.EscapeDataString(Issuer));
        }
        parameters.Add("algorithm", Algorithm.ToString().ToUpper());
        parameters.Add("digits", Digits.ToString());

        switch (Type)
        {
            case OtpType.Totp:
                parameters.Add("period", Period.ToString());
                break;
            case OtpType.Hotp:
                parameters.Add("counter", Counter.ToString());
                break;
        }

        var uriBuilder = new StringBuilder("otpauth://");
        uriBuilder.Append(Type.ToString().ToLowerInvariant());
        uriBuilder.Append("/");

        // The label
        if (!string.IsNullOrWhiteSpace(Issuer))
        {
            uriBuilder.Append(Uri.EscapeDataString(Issuer));
            uriBuilder.Append(":");
        }
        uriBuilder.Append(Uri.EscapeDataString(User));

        // Start of the parameters
        uriBuilder.Append("?");
        foreach (var pair in parameters)
        {
            uriBuilder.Append(pair.Key);
            uriBuilder.Append("=");
            uriBuilder.Append(pair.Value);
            uriBuilder.Append("&");
        }
        // Remove last "&"
        uriBuilder.Remove(uriBuilder.Length - 1, 1);

        return uriBuilder.ToString();
    }
}
