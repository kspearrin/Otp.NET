using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace OtpNet;

// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
public class OtpUri
{
    private const OtpHashMode DEFAULT_HASH_MODE = OtpHashMode.Sha1;
    private const int DEFAULT_DIGITS = 6;
    private const int DEFAULT_PERIOD = 30;
    private const int DEFAULT_COUNTER = 0;
    private const string SCHEME = "otpauth";
    private static readonly Regex queryParameterRegex = new(@"[?&](\w[\w.]*)=([^?&]+)");
    private static readonly Regex accountAndIssuerRegex = new("^/(?:([^:]+):)? *([^:]+)$");

    private delegate bool ParseNumber<T>(string s, System.Globalization.NumberStyles style, IFormatProvider provider, out T result);

    /// <summary>
    /// Create a new OTP Auth Uri
    /// </summary>
    public OtpUri(
        OtpType schema,
        string secret,
        string user,
        string issuer = null,
        OtpHashMode algorithm = DEFAULT_HASH_MODE,
        int digits = DEFAULT_DIGITS,
        int period = DEFAULT_PERIOD,
        long counter = DEFAULT_COUNTER)
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
        OtpHashMode algorithm = DEFAULT_HASH_MODE,
        int digits = DEFAULT_DIGITS,
        int period = DEFAULT_PERIOD,
        long counter = DEFAULT_COUNTER)
        : this(schema, Base32Encoding.ToString(secret), user, issuer,
              algorithm, digits, period, counter)
    { }

    public OtpUri(string uri)
        : this(new Uri(uri))
    { }

    public OtpUri(Uri uri)
    {
        _ = uri ?? throw new ArgumentNullException(nameof(uri));

        if (uri.Scheme != SCHEME)
        {
            throw new ArgumentException($"Uri must use scheme {SCHEME}", nameof(uri));
        }

        T? DetermineEnum<T>(string str) where T : struct, Enum
        {
            foreach (T type in Enum.GetValues(typeof(T)))
            {
                string typeString = type.ToString();
                if (typeString.Equals(str, StringComparison.InvariantCultureIgnoreCase))
                {
                    return type;
                }
            }
            return null;
        }

        void Parse<T>(string key, string value, ref T? result, ParseNumber<T> parse) where T : struct
        {
            if (result.HasValue) throw new ArgumentException($"Uri supplies '{key}' parameter multiple times", nameof(uri));
            if (!parse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var parsedResult))
            {
                throw new ArgumentException($"Uri '{key}' parameter '{value}' is not a valid integer", nameof(uri));
            }
            result = parsedResult;
        }

        OtpType? determinedType = DetermineEnum<OtpType>(uri.Authority);
        if (!determinedType.HasValue) throw new ArgumentException("Uri uses no known type", nameof(uri));
        Type = determinedType.Value;

        // Contains the leading path delimiter
        var accountAndIssuerMatch = accountAndIssuerRegex.Match(uri.LocalPath);
        if (accountAndIssuerMatch.Success)
        {
            Group issuerGroup = accountAndIssuerMatch.Groups[1];
            Issuer = issuerGroup.Success ? issuerGroup.Value : null;
            User = accountAndIssuerMatch.Groups[2].Value;
        }

        // Parse query parameters
        OtpHashMode? algorithm = null;
        int? digits = null;
        long? counter = null;
        int? period = null;

        var queryParameterMatch = queryParameterRegex.Match(uri.Query);
        while (queryParameterMatch.Success)
        {
            string key = queryParameterMatch.Groups[1].Value.ToLower();
            string value = Uri.UnescapeDataString(queryParameterMatch.Groups[2].Value);

            switch (key)
            {
                case "secret":
                    Secret = value;
                    break;
                case "issuer":
                    if (Issuer != null && Issuer != value) throw new ArgumentException($"Uri supplies different issuers in label ({Issuer}) and parameter ({value})", nameof(uri));
                    Issuer = value;
                    break;
                case "algorithm":
                    if (algorithm.HasValue) throw new ArgumentException("Uri supplies 'algorithm' parameter multiple times", nameof(uri));
                    algorithm = DetermineEnum<OtpHashMode>(value);
                    if (!algorithm.HasValue) throw new ArgumentException($"Uri 'algorithm' parameter '{value}' uses no known algorithm", nameof(uri));
                    break;
                case "digits":
                    Parse(key, value, ref digits, int.TryParse);
                    break;
                case "counter":
                    if (Type != OtpType.Hotp) throw new ArgumentException($"Uri 'counter' parameter is not valid for type '{Type}'", nameof(uri));
                    Parse(key, value, ref counter, long.TryParse);
                    break;
                case "period":
                    if (Type != OtpType.Totp) throw new ArgumentException($"Uri 'period' parameter is not valid for type '{Type}'", nameof(uri));
                    Parse(key, value, ref period, int.TryParse);
                    break;
                default:
                    throw new ArgumentException($"Unknown parameter '{key}' in query string of uri", nameof(uri));
            }

            queryParameterMatch = queryParameterMatch.NextMatch();
        }

        if (Secret == null) throw new ArgumentException($"Uri didn't provide the mandatory parameter 'secret'");
        // throws when Secret does contain invalid characters
        _ = Base32Encoding.ToBytes(Secret);

        Algorithm = algorithm ?? DEFAULT_HASH_MODE;
        Digits = digits ?? DEFAULT_DIGITS;
        Period = period ?? DEFAULT_PERIOD;
        Counter = counter ?? DEFAULT_COUNTER;
    }

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
    public long Counter { get; private set; }

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

        var uriBuilder = new StringBuilder(SCHEME);
        uriBuilder.Append("://");
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
