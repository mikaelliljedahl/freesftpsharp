using System.Globalization;
using System.Text;
using QRCoder;

namespace SshServer.TwoFactor;

/// <summary>Makes the QR code of an <c>otpauth://</c> URI as an SVG image on the server, without an external service.</summary>
public static class TotpQrCode
{
    /// <summary>An SVG with one path of dark modules and a quiet zone of four modules, scaled by the page.</summary>
    public static string ToSvg(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(text, QRCodeGenerator.ECCLevel.M);
        // The matrix of QRCoder already has the quiet zone of four modules.
        var matrix = data.ModuleMatrix;
        var size = matrix.Count;

        var path = new StringBuilder();
        for (var y = 0; y < size; y++)
        {
            var row = matrix[y];
            for (var x = 0; x < size; x++)
            {
                if (!row[x])
                    continue;
                var start = x;
                while (x + 1 < size && row[x + 1])
                    x++;
                path.Append(CultureInfo.InvariantCulture, $"M{start} {y}h{x - start + 1}v1h-{x - start + 1}z");
            }
        }

        return $"<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" shape-rendering=\"crispEdges\" " +
               $"role=\"img\" aria-label=\"QR code for the authenticator app\"><rect width=\"{size}\" height=\"{size}\" fill=\"#fff\"/>" +
               $"<path fill=\"#000\" d=\"{path}\"/></svg>";
    }
}
