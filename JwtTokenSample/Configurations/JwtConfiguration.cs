namespace JwtTokenSample.Configurations
{
    public sealed class JwtConfiguration
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public int ExpiryDays { get; set; }
        public string Password { get; set; }
    }
}
