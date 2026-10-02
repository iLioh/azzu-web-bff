FROM mcr.microsoft.com/dotnet/aspnet:8.0-azurelinux3.0-distroless-extra@sha256:1e65650d5745b73fa5a819fc858dd0b03e899dd8efc107fd895dd1fff493c661 AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
USER 1654

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["Directory.Build.props", "./"]
COPY ["src/Azzu.WebBff.Api/Azzu.WebBff.Api.csproj", "src/Azzu.WebBff.Api/"]
COPY ["src/Azzu.WebBff.Application/Azzu.WebBff.Application.csproj", "src/Azzu.WebBff.Application/"]
COPY ["src/Azzu.WebBff.Contracts/Azzu.WebBff.Contracts.csproj", "src/Azzu.WebBff.Contracts/"]
COPY ["src/Azzu.WebBff.Domain/Azzu.WebBff.Domain.csproj", "src/Azzu.WebBff.Domain/"]
COPY ["src/Azzu.WebBff.Infrastructure/Azzu.WebBff.Infrastructure.csproj", "src/Azzu.WebBff.Infrastructure/"]
RUN dotnet restore "src/Azzu.WebBff.Api/Azzu.WebBff.Api.csproj"
COPY . .
RUN dotnet publish "src/Azzu.WebBff.Api/Azzu.WebBff.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "Azzu.WebBff.Api.dll"]
