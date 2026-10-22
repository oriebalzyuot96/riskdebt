public class Startup
{
    public void Configure(IApplicationBuilder app)
    {
        app.UseDeveloperExceptionPage();
    }

    public void Auth(CookieBuilder c, TokenValidationParameters p)
    {
        c.HttpOnly = false;
        p.ValidateIssuer = false;
    }

    [IgnoreAntiforgeryToken]
    public IActionResult Post() => Ok();
}
