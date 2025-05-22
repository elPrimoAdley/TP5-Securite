using Duende.IdentityModel.OidcClient.Browser;

namespace DesktopClient;

using System;
using System.Diagnostics;
using System.Net;
using System.Threading.Tasks;

public class SystemBrowser : IBrowser
{
    private readonly int _port;

    public SystemBrowser(int port)
    {
        _port = port;
    }

    public async Task<BrowserResult> InvokeAsync(BrowserOptions options, System.Threading.CancellationToken cancellationToken = default)
    {
        var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
        listener.Start();

        Process.Start(new ProcessStartInfo
        {
            FileName = options.StartUrl,
            UseShellExecute = true
        });

        var context = await listener.GetContextAsync();

        var response = context.Response;
        string responseString = "<html><head><meta http-equiv='refresh' content='10;url=https://localhost'></head><body>Connexion réussie, vous pouvez fermer cette fenêtre.</body></html>";
        var buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
        response.ContentLength64 = buffer.Length;
        var responseOutput = response.OutputStream;
        await responseOutput.WriteAsync(buffer, 0, buffer.Length);
        responseOutput.Close();

        return new BrowserResult
        {
            Response = context.Request.Url.ToString(),
            ResultType = BrowserResultType.Success
        };
    }
}