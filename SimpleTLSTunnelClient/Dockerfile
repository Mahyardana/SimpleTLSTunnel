FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY SimpleTLSTunnelClient/SimpleTLSTunnelClient.csproj SimpleTLSTunnelClient/
COPY SimpleTLSTunnelServer/SimpleTLSTunnelServer.csproj SimpleTLSTunnelServer/
RUN dotnet restore SimpleTLSTunnelClient/SimpleTLSTunnelClient.csproj
COPY . .
RUN dotnet publish SimpleTLSTunnelClient/SimpleTLSTunnelClient.csproj -c Release --no-restore -o /app/publish

FROM mcr.microsoft.com/dotnet/runtime:6.0
WORKDIR /app
COPY --from=build /app/publish .
EXPOSE 1080
ENTRYPOINT ["dotnet", "SimpleTLSTunnelClient.dll"]
