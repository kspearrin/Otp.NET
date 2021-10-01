using System;
using System.Collections.Generic;
using System.Text;

namespace OtpNet {
    public class OTPUri
    {
        /// <summary>
        /// What type of OTP is this uri for
        /// <seealso cref="OTPType"/>
        /// </summary>
        public readonly OTPType Type;

        /// <summary>
        /// The secret parameter is an arbitrary key value encoded in Base32 according to RFC 3548.
        /// The padding specified in RFC 3548 section 2.2 is not required and should be omitted.
        /// </summary>
        public readonly byte[] Secret;

        /// <summary>
        /// Which account a key is associated with
        /// </summary>
        public readonly string User;

        /// <summary>
        /// The issuer parameter is a string value indicating the provider or service this account is
        /// associated with, URL-encoded according to RFC 3986.
        /// </summary>
        public readonly string Issuer;

        /// <summary>
        /// The algorithm used by the generator
        /// </summary>
        public readonly OtpHashMode Algorithm;

        /// <summary>
        /// The amount of digits in the final code
        /// </summary>
        public readonly int Digits;

        /// <summary>
        /// The number of seconds that a code is valid. Only applies to TOTP, not HOTP
        /// </summary>
        public readonly int Period;

        /// <summary>
        /// Initial counter value for HOTP. This is ignored when using TOTP.
        /// </summary>
        public readonly int Counter;


        /// <summary>
        /// Create a new OTPAuthUri
        /// </summary>
        public OTPUri(
            OTPType schema,
            byte[] secret,
            string user,
            string issuer = null,
            OtpHashMode algorithm = OtpHashMode.Sha1,
            int digits = 6,
            int period = 30,
            int counter = 0
        )
        {
            _ = secret ?? throw new ArgumentNullException(nameof(secret));
            _ = user ?? throw new ArgumentNullException(nameof(user));
            Type = schema;
            Secret = secret;
            User = user;
            Issuer = issuer;
            Algorithm = algorithm;
            if (digits < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(digits));
            }
            Digits = digits;
            switch (Type)
            {

                case OTPType.TOTP:
                    Period = period;
                    break;
                case OTPType.HOTP:
                    Counter = counter;
                    break;
            }
        }

        /// <summary>
        /// Generates a Uri String according to the parameters
        /// </summary>
        /// <returns>a Uri String according to the parameters</returns>
        public override string ToString()
        {
            Dictionary<string, string> parameters = new Dictionary<string, string>();

            parameters.Add("secret", Base32Encoding.ToString(Secret));
            if (Issuer != null)
            {
                parameters.Add("issuer", Issuer);
            }
            parameters.Add("algorithm", Algorithm.ToString().ToUpper());
            parameters.Add("digits", Digits.ToString());

            switch (Type)
            {
                case OTPType.TOTP:
                    parameters.Add("period", Period.ToString());
                    break;
                case OTPType.HOTP:
                    parameters.Add("counter", Counter.ToString());
                    break;
            }

            StringBuilder uriBuilder = new StringBuilder("otpauth://");
            uriBuilder.Append(Type.ToString().ToLower());
            uriBuilder.Append("/");
            // The label
            if (Issuer != null)
            {
                uriBuilder.Append(Issuer);
                uriBuilder.Append(":");
            }
            uriBuilder.Append(User);
            // Start of the parameters
            uriBuilder.Append("?");

            foreach (KeyValuePair<string, string> pair in parameters)
            {
                uriBuilder.Append(pair.Key);
                uriBuilder.Append("=");
                uriBuilder.Append(pair.Value);
                uriBuilder.Append("&");
            }
            uriBuilder.Remove(uriBuilder.Length - 1, 1); // Remove last "&"

            return Uri.EscapeUriString(uriBuilder.ToString());
        }
    }
}
