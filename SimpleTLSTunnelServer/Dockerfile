FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY SimpleTLSTunnelServer/SimpleTLSTunnelServer.csproj SimpleTLSTunnelServer/
COPY SimpleTLSTunnelClient/SimpleTLSTunnelClient.csproj SimpleTLSTunnelClient/
RUN dotnet restore SimpleTLSTunnelServer/SimpleTLSTunnelServer.csproj
COPY . .
RUN dotnet publish SimpleTLSTunnelServer/SimpleTLSTunnelServer.csproj -c Release --no-restore -o /app/publish

FROM mcr.microsoft.com/dotnet/runtime:6.0
WORKDIR /app
COPY --from=build /app/publish .
EXPOSE 443
ENTRYPOINT ["dotnet", "SimpleTLSTunnelServer.dll"]
