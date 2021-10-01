namespace OtpNet {
    /// <summary>
    /// Schema types for OTPs
    /// </summary>
    public enum OTPType
    {
        /// <summary>
        /// Time-based OTP
        /// see https://datatracker.ietf.org/doc/html/rfc6238
        /// </summary>
        TOTP,
        /// <summary>
        /// HMAC-based (counter) OTP
        /// see https://datatracker.ietf.org/doc/html/rfc4226
        /// </summary>
        HOTP,
    }
}