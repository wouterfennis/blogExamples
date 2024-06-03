
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.HttpOverrides;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace WebApi
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();


            // 2
            builder.Services.Configure<ForwardedHeadersOptions>(options =>
            {
                // This will forward the X-Forwarded-For and X-Forwarded-Proto headers
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                
                // This will forward the X-Forwarded-Host header
                options.KnownNetworks.Clear();

                // This will forward the X-Forwarded-Host header
                options.KnownProxies.Clear();
            }).AddCertificateForwarding(options =>
            {
                options.CertificateHeader = "X-ARR-ClientCert"; // This is standard with App Services
                options.HeaderConverter = (headerValue) =>
                {
                    if (string.IsNullOrEmpty(headerValue))
                    {
                        return null;
                    }

                    var bytes = Convert.FromBase64String(headerValue);
                    return new X509Certificate2(bytes);
                };
            }).AddAuthentication("Certificate")
            .AddCertificate(options =>
            {
                options.AllowedCertificateTypes = CertificateTypes.All;
                options.RevocationMode = X509RevocationMode.Online;
                options.ValidateCertificateUse = true;
                options.ValidateValidityPeriod = true;
                options.Events = new CertificateAuthenticationEvents
                {
                    OnCertificateValidated = context =>
                    {
                        var isValid = "YOUR_CERTIFICATE_THUMBPRINT".Equals(context.ClientCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase);

                        if (isValid)
                        {
                            context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Certificate"));
                            context.Success();
                        }
                        else
                        {
                            context.Fail("Invalid certificate");
                        }

                        return Task.CompletedTask;
                    }
                };
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            // 1
            // Forwarded headers and certificate forwarding are required for running behind a reverse proxy
            // This will make the client certificate available to the application
            app.UseForwardedHeaders();
            app.UseCertificateForwarding();

            app.UseHttpsRedirection();

            app.MapControllers();

            app.Run();
        }
    }
}
