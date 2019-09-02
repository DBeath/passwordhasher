using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PasswordHasher
{
    public static class Program
    {
        private static readonly string connectionString = "Data Source=(localdb)\\MSSQLLocalDB; Initial Catalog=Password_DB; Integrated Security=SSPI; MultipleActiveResultSets=true;";

        static void Main(string[] args)
        {
                int userBatch = 30;
            if (args.Length > 0)
            {
                userBatch = int.Parse(args[0]);
            }

            var countToBeHashed = CountPasswordsToBeHashed().GetAwaiter().GetResult();

            Console.WriteLine($"{countToBeHashed} Passwords require Rehashing.");
            Console.WriteLine($"Rehashing passwords for {userBatch} Users at a time.");
            Console.Write("Are you sure you want to continue [y/n]? default n: ");
            if (Console.ReadKey().Key != ConsoleKey.Y)
            {
                return;
            }
            Console.WriteLine();
            Console.WriteLine("OK. Now fetching and hashing passwords.");

            var totalHashed = 0;
            using (IDbConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();
                var users = GetUsers(connection, userBatch);

                while (users.Any())
                {
                    Console.WriteLine($"Fetched {users.Count()} Users. Hashing Passwords...");

                    var hashedUsers = HashPasswords(users).GetAwaiter().GetResult();
                    UpdateUsers(hashedUsers, connection);
                    totalHashed += hashedUsers.Count();

                    users = GetUsers(connection, userBatch);
                }
            }

            Console.WriteLine($"Finished hashing. Hashed {totalHashed} Passwords.");
            Console.ReadKey();
        }

        /// <summary>
        /// Fetch Users and their current Passwords from the Database.
        /// </summary>
        /// <param name="maxNum">Maximum number of users to fetch</param>
        /// <returns></returns>
        private static IEnumerable<UserPasswordDto> GetUsers(IDbConnection connection, int maxNum = 100)
        {
            List<UserPasswordDto> userPasswords = new List<UserPasswordDto>();

            string selectQueryString = "SELECT TOP (@maxNum) [Id], [Password] FROM Users WHERE [Password] IS NOT NULL AND [Password] NOT LIKE '%$_' AND LEN([Password]) = 64";

            using (SqlCommand command = new SqlCommand(selectQueryString, (SqlConnection)connection))
            {
                command.Parameters.AddWithValue("@maxNum", maxNum);
                SqlDataReader reader = command.ExecuteReader();

                try
                {
                    while (reader.Read())
                    {
                        userPasswords.Add(new UserPasswordDto
                        {
                            Id = (long)reader["Id"],
                            CurrentPassword = (string)reader["Password"]
                        });
                    }
                }
                finally
                {
                    reader.Close();
                }
            }

            return userPasswords;
        }

        /// <summary>
        /// Updates a single user in the database.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="connection"></param>
        private static void UpdateUser(UserPasswordDto user, IDbConnection connection)
        {
            string updateQueryString = "UPDATE Users SET Password = @password WHERE Id = @id AND Password = @currentPassword";

            using (SqlCommand updateCommand = new SqlCommand(updateQueryString, (SqlConnection)connection))
            {
                updateCommand.Parameters.AddWithValue("@id", user.Id);
                updateCommand.Parameters.AddWithValue("@password", user.Password);
                updateCommand.Parameters.AddWithValue("@currentPassword", user.CurrentPassword);
                try
                {
                    updateCommand.ExecuteNonQuery();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Exception while updating User {user.Id}, Ex: {ex}");
                }
            }
        }

        /// <summary>
        /// Update Users
        /// </summary>
        /// <param name="users"></param>
        private static void UpdateUsers(IEnumerable<UserPasswordDto> users, IDbConnection connection)
        {
            foreach (var user in users)
            {
                UpdateUser(user, connection);
            }
        }

        /// <summary>
        /// Rehash User's current Password hashes with our intermediate Hash.
        /// </summary>
        /// <param name="userPasswords"></param>
        /// <returns></returns>
        private static async Task<IEnumerable<UserPasswordDto>> HashPasswords(IEnumerable<UserPasswordDto> userPasswords)
        {
            var results = await Task.WhenAll(userPasswords.Select(x => HashUserPassword(x)));
            return results;
        }

        /// <summary>
        /// Rehash a single User's current Password with our intermediate Hash.
        /// </summary>
        /// <param name="userPassword"></param>
        /// <returns></returns>
        private static async Task<UserPasswordDto> HashUserPassword(UserPasswordDto userPassword)
        {
            return await Task.Run(() =>
            {
                var timer = Stopwatch.StartNew();
                // Current User Password is UpperCase SHA256 hash. Make sure that ToUpper() is called.
                userPassword.Password = HashHelpers.CreateHashWithVersion(userPassword.CurrentPassword.ToUpper(), version: HashVersionEnum.Intermediate_SHA256_Bcrypt);
                timer.Stop();
                Console.WriteLine($"Created Hash for Id {userPassword.Id}, Hash: {userPassword.Password}. Thread {Thread.CurrentThread.ManagedThreadId}. Time: {timer.ElapsedMilliseconds}ms");
                return userPassword;
            });
        }

        private static async Task<int> CountPasswordsToBeHashed()
        {
            int count = 0;
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();
                string queryString = "SELECT Count(*) as PwCount FROM Users WHERE [Password] IS NOT NULL AND [Password] NOT LIKE '%$_' AND LEN([Password]) = 64";
                using (SqlCommand command = new SqlCommand(queryString, connection))
                {
                    count = (int)await command.ExecuteScalarAsync();
                }
            }
            return count;
        }
    }
}
