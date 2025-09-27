using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using AwesomeAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GLib.Tests;

[TestClass]
[TestCategory("IntegrationTest")]
public class SourceFuncCrashTests : Test
{
    private static readonly string RepoRoot = GetRepoRoot();
    private static readonly string ReproProject = Path.Combine(RepoRoot, "src", "Tests", "Repros", "SourceFuncCrashRepro", "SourceFuncCrashRepro.csproj");

    [TestMethod]
    public void SourceFuncDestroyNotifyWrapperIsKeptAlive()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            Assert.Inconclusive("Repro only validated on Linux");
            return;
        }

        File.Exists(ReproProject).Should().BeTrue();

        var startInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            ArgumentList = { "run", "--project", ReproProject },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var process = Process.Start(startInfo)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();

        var output = stdout.GetAwaiter().GetResult();
        var error = stderr.GetAwaiter().GetResult();

        Console.WriteLine(output);
        Console.Error.WriteLine(error);

        process.ExitCode.Should().Be(0, "the destroy-notify wrapper is now rooted");
        error.Should().NotContain("garbage collected delegate");
    }

    private static string GetRepoRoot()
    {
        var path = AppContext.BaseDirectory;

        while (!string.IsNullOrEmpty(path))
        {
            if (File.Exists(Path.Combine(path, "shell.nix")))
            {
                return path;
            }

            path = Path.GetDirectoryName(path)!;
        }

        throw new InvalidOperationException("Unable to locate repository root");
    }
}
