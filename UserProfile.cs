using System.Text.Json.Serialization;
using System.Security.Cryptography;

namespace StrawberrySecret;

public class UserProfile
{
    public string Username { get; set; } = string.Empty;
    public int Iterations { get; set; }
    public int SaltSizeBytes { get; set; }
    public int NonceSizeBytes { get; set; }
    public int TagSizeBytes { get; set; }
    public string Kdf { get; set; } = "PBKDF2";
    public string Algorithm { get; set; } = "AES-256-GCM";
    public string UserSaltBase64 { get; set; } = string.Empty; // random per user

    [JsonIgnore]
    public byte[] UserSalt => Convert.FromBase64String(UserSaltBase64);

    public static UserProfile CreateDefault(string username, int iterations, int saltSize, int nonceSize, int tagSize)
    {
        return new UserProfile
        {
            Username = username,
            Iterations = iterations,
            SaltSizeBytes = saltSize,
            NonceSizeBytes = nonceSize,
            TagSizeBytes = tagSize,
            UserSaltBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
        };
    }
}