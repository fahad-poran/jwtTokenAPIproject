# JWT Authentication Implementation

This document explains the JWT authentication implementation in our Repository Pattern API project.

---

## 🔐 Core Security Implementation

### Password Hashing
We use **HMAC-SHA512 with unique salts** for secure password storage:

```csharp
private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
{
    using (var hmac = new System.Security.Cryptography.HMACSHA512())
    {
        passwordSalt = hmac.Key;
        passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
    }
}
```

### Password Verification
```csharp
private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
{
    using (var hmac = new System.Security.Cryptography.HMACSHA512(passwordSalt))
    {
        var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        return computedHash.SequenceEqual(passwordHash);
    }
}
```

---

## 🚀 Authentication Methods

### User Registration
```csharp
public async Task<ServiceResponse<int>> Register(User user, string password)
{
    var response = new ServiceResponse<int>();
    
    if (await UserExists(user.Username))
    {
        response.Success = false;
        response.Message = "User already exists.";
        return response;
    }

    CreatePasswordHash(password, out byte[] passwordHash, out byte[] passwordSalt);
    user.PasswordHash = passwordHash;
    user.PasswordSalt = passwordSalt;

    _context.Users.Add(user);
    await _context.SaveChangesAsync();
    
    response.Data = user.Id;
    response.Message = "User Created Successfully";
    return response;
}
```

### User Login
```csharp
public async Task<ServiceResponse<string>> Login(string username, string password)
{
    var response = new ServiceResponse<string>();
    var user = await _context.Users
        .FirstOrDefaultAsync(u => u.Username.ToLower().Equals(username.ToLower()));

    if (user is null)
    {
        response.Success = false;
        response.Message = "User not found.";
    }
    else if (!VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
    {
        response.Success = false;
        response.Message = "Wrong password.";
    }
    else
    {
        response.Data = CreateToken(user);
    }
    
    return response;
}
```

---

## 🎫 JWT Token Generation

### Token Creation
```csharp
private string CreateToken(User user)
{
    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Username)
    };

    var appSettingsToken = _configuration.GetSection("AppSettings:Token").Value;
    
    if (appSettingsToken is null)
        throw new Exception("AppSettings Token is null!");

    SymmetricSecurityKey key = new SymmetricSecurityKey(
        System.Text.Encoding.UTF8.GetBytes(appSettingsToken));
        
    SigningCredentials creds = new SigningCredentials(key, 
        SecurityAlgorithms.HmacSha512Signature);

    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.Now.AddDays(1),
        SigningCredentials = creds
    };

    JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
    SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
    
    return tokenHandler.WriteToken(token);
}
```

---

## ⚠️ Important Security Notes

- **JWT Secret Key:** Ensure your `AppSettings:Token` in configuration is at least **512 bits (64 characters) long**  
- **Password Security:** Never store passwords in plain text  
- **Token Expiration:** Tokens expire after **1 day** for security  
- **Unique Salts:** Each user gets a unique salt for password hashing  

---

## 📋 Configuration

Add to your **appsettings.json**:

```json
{
  "AppSettings": {
    "Token": "YourSuperSecureLongSecretKeyWithAtLeast64CharactersLength1234567890ABCDEF"
  }
}
```

---

✅ This implementation provides secure authentication using **industry-standard practices** with **JWT tokens** and **password hashing**.
