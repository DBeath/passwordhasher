# Password Hash Upgrade
An example project of password hashing functions implemented in C# for handling the safe rehashing of improperly hashed passwords.

Occasionally we will come across projects that are storing user's passwords in plaintext or with weak hashing algorithms, presenting an unacceptable security risk. In the case of stored plaintext passwords, we can simply hash the passwords using a secure hashing algorithm.

However, if the passwords have already been hashed with a weak algorithm such as an SHA variant, then the problem becomes a little more difficult. To avoid having to reset all user's passwords, we can pass the weak hashes into the stronger algorithm and save the result as the new hash. When a user logs in, to verify their password, we first hash it with the original weak hash, then use that as the input into the verification method of the strong algorithm. If the password is verified, as we now know we have the correct plaintext password, we can rehash it with the strong algorithm only. The next time the user logs in, we can then skip the intermediate step and use only the verification method for the strong hash algorithm.

There may be thousands or millions of improperly stored passwords, so it will take time to hash the weak hashes with the stronger hashes. As users may still be logging in during this time, we will need to handle the original hashes until all weak hashes have been upgraded, as well as the intermediate hashes and the final strong hash.

For example, if passwords were originally hashed with SHA, and we now need to upgrade the algorithm to Bcrypt, we can Psuedocode the following:

``` Psuedocode
// Safely rehash user password
Function Create_Intermediate_Hash(SHA_Hashed_Password)
    Intermediate_Hash = Bcrypt.CreateHash(SHA_Hashed_Password)
    Save_To_Database(Intermediate_Hash)

// Verify user password
Function Verify_User_Password(PlainText_Password):
    Hashed_Password = Get_User_Password_Hash_From_Database()

    // Get the hash algorithm, could be stored in a separate column, or as part of the password hash
    Hashed_Password_Algorithm = Get_Hash_Algorithm(Hashed_Password)
    
    If Hashed_Password_Algorithm is SHA_To_Bcrypt:
        SHA_Hash = SHA.Hash(PlainText_Password)
        Verified = Bcrypt.Verify(SHA_Hash)
        If Verified is Valid:
            return Valid_Requires_ReHash

    Else If Hashed_Password_Algorithm is Bcrypt:
        Verified = Bcrypt.Verify(PlainText_Password)
        If Verified is Valid:
            return Valid

    Else If Hashed_Password_Algorithm is SHA:
        SHA_Hash = SHA.Hash(PlainText_Password)
        If SHA_Hash == Hashed_Password:
            return Valid_Requires_ReHash

    return Invalid

// Rehash the plaintext password with Bcrypt and save the result
Function Rehash_Password(PlainText_Password)
    Bcrypt_Hash = Bcrypt.CreateHash(PlainText_Password)
    Save_To_Database(Bcrypt_Hash)

// Main program
Function Main()
    // Get the unsafe password hash and rehash it with the intermediate step
    Current_Password_Hash = Get_User_Password_Hash_From_Database()
    Create_Intermediate_Hash(Current_Password_Hash)

    // User logs in and provides password in plaintext
    Verified = Verify_User_Password(PlainText_Password)
    If Verified == Valid_Requires_ReHash:
        Rehash_Password(PlainText_Password)
        Login_User()
    Else if Verified == Valid:
        Login_User()
    Else:
        Reject_Login()
```

## Example Project
This example project is written in C# using .NET Core 3. *PasswordHasher.cs* implements the *IPasswordHasher* interface, returning a *PasswordVerificationResult*. In this case, passwords were originally hashed with SHA_256, and will be upgraded to use Bcrypt. Because we didn't want to create another column to store the hash type, the hash type has been appended to the password hash.

*Program.cs* is a Console Application that implements the hashing methods in *HashHelpers.cs*, to fetch all SHA_256 passwords from the database and hash them with Bcrypt to create the intermediate hash.