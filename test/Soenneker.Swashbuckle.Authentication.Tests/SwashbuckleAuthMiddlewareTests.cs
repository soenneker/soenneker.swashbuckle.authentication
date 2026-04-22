using Soenneker.Tests.HostedUnit;

namespace Soenneker.Swashbuckle.Authentication.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public class SwashbuckleAuthMiddlewareTests : HostedUnitTest
{
    public SwashbuckleAuthMiddlewareTests(Host host) : base(host)
    {
    }

    [Test]
    public void Default()
    {

    }
}
