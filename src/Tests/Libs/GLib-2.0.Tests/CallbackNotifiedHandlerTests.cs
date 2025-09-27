using System;
using AwesomeAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GLib.Tests;

[TestClass, TestCategory("UnitTest")]
public class CallbackNotifiedHandlerTests : Test
{
    [TestMethod]
    public void DestroyNotifyCanBeInvokedMultipleTimes()
    {
        var handler = new GLib.Internal.SourceFuncNotifiedHandler(() => true);
        var destroyNotify = handler.DestroyNotify;

        destroyNotify.Should().NotBeNull();

        Action destroyTwice = () =>
        {
            destroyNotify!(IntPtr.Zero);
            destroyNotify!(IntPtr.Zero);
        };

        destroyTwice.Should().NotThrow();
    }
}
