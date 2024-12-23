using Soenneker.Tests.FixturedUnit;
using Xunit;

namespace Soenneker.Swashbuckle.Authentication.Tests;

[Collection("Collection")]
public class SwashbuckleAuthMiddlewareTests : FixturedUnitTest
{
    public SwashbuckleAuthMiddlewareTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
    }

    [Fact]
    public void Default()
    {

    }
}
