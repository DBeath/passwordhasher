namespace PasswordHasher
{
    /// <summary>
    /// The Version of Hashing/Encryption algorithm used for the Password.
    /// WARNING: DO NOT change the integer values, or users passwords will break.
    /// </summary>
    public enum HashVersionEnum
    {
        /// <summary>
        /// Unknown Hash version.
        /// </summary>
        Unknown = 0,

        /// <summary>
        /// Old SHA256 Hash without Salt.
        /// </summary>
        SHA256 = 1,

        /// <summary>
        /// Intermediate Hash for migration. The old SHA256 hash used as input into Bcrypt.
        /// </summary>
        Intermediate_SHA256_Bcrypt = 2,

        /// <summary>
        /// Bcrypt algorithm hash.
        /// </summary>
        Bcrypt = 3,
    }
}
