using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Lidgren.Network;
using Robust.Shared.ContentPack;
using Robust.Shared.Utility;

namespace Robust.Shared.Network;

public sealed partial class NetManager
{
    private static readonly JsonSerializerOptions ConnectionFilterBanJsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly Dictionary<IPAddress, int> _ipActiveConnectionCount = new();
    private readonly Dictionary<IPAddress, IpRateState> _ipRateStates = new();
    private readonly Dictionary<IPAddress, TimeSpan> _ipBlockedUntil = new();
    private readonly Dictionary<IPAddress, int> _ipViolationStrikes = new();
    private readonly HashSet<IPAddress> _ipPermanentlyBlocked = new();
    private readonly HashSet<NetConnection> _connectionsWithReservedSlot = new();
    private readonly Dictionary<NetConnection, string> _rejectOnConnected = new();
    private TimeSpan _lastConnectionFilterCleanup;
    private bool _connectionFilterBansLoaded;

    private void RejectHandshakeConnection(NetConnection connection, string reason)
    {
        _rejectOnConnected[connection] = reason;
        connection.Approve();
    }

    private bool TryConsumeRejectOnConnected(NetConnection connection, out string reason)
    {
        reason = string.Empty;
        if (!_rejectOnConnected.TryGetValue(connection, out var pendingReason))
            return false;

        reason = pendingReason;
        _rejectOnConnected.Remove(connection);
        return true;
    }

    private struct IpRateState
    {
        public int Count;
        public TimeSpan WindowStart;
    }

    private bool TryAcquireConnectionSlot(NetConnection connection, out string denyReason)
    {
        denyReason = "Blocked";
        EnsureConnectionFilterBansLoaded();

        var ip = NormalizeConnectionIp(connection.RemoteEndPoint.Address);
        var now = _timing.RealTime;

        CleanupConnectionFilter(now);

        if (_ipPermanentlyBlocked.Contains(ip))
            return false;

        if (_ipBlockedUntil.TryGetValue(ip, out var blockedUntil) && now < blockedUntil)
            return false;

        var maxConcurrent = _config.GetCVar(CVars.NetIpMaxConcurrent);
        if (maxConcurrent > 0 && _ipActiveConnectionCount.GetValueOrDefault(ip) >= maxConcurrent)
        {
            RecordConnectionFilterViolation(ip, now);
            return false;
        }

        var rateLimit = _config.GetCVar(CVars.NetIpConnectRateLimit);
        var ratePeriod = TimeSpan.FromSeconds(_config.GetCVar(CVars.NetIpConnectRatePeriod));
        if (rateLimit > 0)
        {
            ref var state = ref CollectionsMarshal.GetValueRefOrAddDefault(_ipRateStates, ip, out _);
            if (now - state.WindowStart > ratePeriod)
            {
                state.WindowStart = now;
                state.Count = 0;
            }

            state.Count++;
            if (state.Count > rateLimit)
            {
                RecordConnectionFilterViolation(ip, now);
                return false;
            }
        }

        _ipActiveConnectionCount.TryGetValue(ip, out var count);
        _ipActiveConnectionCount[ip] = count + 1;
        _connectionsWithReservedSlot.Add(connection);
        return true;
    }

    private void ReleaseConnectionSlot(NetConnection connection)
    {
        if (!_connectionsWithReservedSlot.Remove(connection))
            return;

        var ip = NormalizeConnectionIp(connection.RemoteEndPoint.Address);
        if (!_ipActiveConnectionCount.TryGetValue(ip, out var count))
            return;

        if (count <= 1)
            _ipActiveConnectionCount.Remove(ip);
        else
            _ipActiveConnectionCount[ip] = count - 1;
    }

    private void RecordConnectionFilterViolation(IPAddress ip, TimeSpan now)
    {
        var baseDuration = _config.GetCVar(CVars.NetIpViolationBlockDuration);
        if (baseDuration <= 0)
            return;

        if (_ipPermanentlyBlocked.Contains(ip))
            return;

        _ipViolationStrikes.TryGetValue(ip, out var strikes);
        strikes++;
        _ipViolationStrikes[ip] = strikes;

        var maxDuration = _config.GetCVar(CVars.NetIpViolationBlockMaxDuration);
        var duration = baseDuration;
        for (var i = 1; i < strikes; i++)
            duration *= 2;

        if (duration > maxDuration)
        {
            _ipPermanentlyBlocked.Add(ip);
            _ipBlockedUntil.Remove(ip);
            _logger.Warning(
                "Permanently blocked {ConnectionIp} after {ViolationStrikes} connection filter violations",
                ip,
                strikes);
            SaveConnectionFilterBans();
            return;
        }

        _ipBlockedUntil[ip] = now + TimeSpan.FromSeconds(duration);
        _logger.Info(
            "Temporarily blocked {ConnectionIp} for {BlockSeconds}s after {ViolationStrikes} connection filter violation(s)",
            ip,
            (int) duration,
            strikes);
        SaveConnectionFilterBans();
    }

    private ResPath GetConnectionFilterBanFilePath()
    {
        return new ResPath(_config.GetCVar(CVars.NetIpFilterBanFile));
    }

    private void EnsureConnectionFilterBansLoaded()
    {
        if (_connectionFilterBansLoaded || !CanUseConnectionFilterBanStorage())
            return;

        _connectionFilterBansLoaded = true;
        LoadConnectionFilterBans();
    }

    private bool CanUseConnectionFilterBanStorage()
    {
        return _resource.UserData.RootDir != null;
    }

    private void LoadConnectionFilterBans()
    {
        var path = GetConnectionFilterBanFilePath();
        if (!_resource.UserData.TryReadAllText(path, out var text))
            return;

        ConnectionFilterBanFile? data;
        try
        {
            data = JsonSerializer.Deserialize<ConnectionFilterBanFile>(text, ConnectionFilterBanJsonOptions);
        }
        catch (Exception e)
        {
            _logger.Error("Failed to deserialize connection filter ban file {BanFile}: {Error}", path, e);
            return;
        }

        if (data?.Entries == null)
            return;

        var loadedPermanent = 0;
        foreach (var entry in data.Entries)
        {
            if (!IPAddress.TryParse(entry.Ip, out var address))
            {
                _logger.Warning("Skipping invalid IP in connection filter ban file: {ConnectionIp}", entry.Ip);
                continue;
            }

            var ip = NormalizeConnectionIp(address);
            if (entry.Strikes > 0)
                _ipViolationStrikes[ip] = entry.Strikes;

            if (!entry.Permanent)
                continue;

            _ipPermanentlyBlocked.Add(ip);
            loadedPermanent++;
        }

        if (loadedPermanent > 0)
        {
            _logger.Info(
                "Loaded {PermanentBanCount} permanent connection filter ban(s) from {BanFile}",
                loadedPermanent,
                path);
        }
    }

    private void SaveConnectionFilterBans()
    {
        if (!CanUseConnectionFilterBanStorage())
            return;

        var path = GetConnectionFilterBanFilePath();
        var ips = new HashSet<IPAddress>(_ipPermanentlyBlocked);
        foreach (var ip in _ipViolationStrikes.Keys)
            ips.Add(ip);

        var entries = new List<ConnectionFilterBanEntry>(ips.Count);
        foreach (var ip in ips)
        {
            _ipViolationStrikes.TryGetValue(ip, out var strikes);
            entries.Add(new ConnectionFilterBanEntry
            {
                Ip = ip.ToString(),
                Strikes = strikes,
                Permanent = _ipPermanentlyBlocked.Contains(ip),
            });
        }

        entries.Sort(static (a, b) => string.Compare(a.Ip, b.Ip, StringComparison.Ordinal));

        try
        {
            var json = JsonSerializer.Serialize(
                new ConnectionFilterBanFile { Entries = entries },
                ConnectionFilterBanJsonOptions);
            _resource.UserData.WriteAllText(path, json);
            _logger.Debug(
                "Saved {BanEntryCount} connection filter ban entries to {BanFile}",
                entries.Count,
                path);
        }
        catch (Exception e)
        {
            _logger.Error("Failed to save connection filter ban file {BanFile}: {Error}", path, e);
        }
    }

    private sealed class ConnectionFilterBanFile
    {
        public List<ConnectionFilterBanEntry> Entries { get; set; } = new();
    }

    private sealed class ConnectionFilterBanEntry
    {
        public string Ip { get; set; } = string.Empty;
        public int Strikes { get; set; }
        public bool Permanent { get; set; }
    }

    private bool ShouldLogConnectionStatus(NetConnection connection)
    {
        if (_channels.ContainsKey(connection))
            return true;

        return !IsConnectionFilterSuppressed(connection.RemoteEndPoint.Address);
    }

    private bool IsConnectionFilterSuppressed(IPAddress address)
    {
        var ip = NormalizeConnectionIp(address);
        if (_ipPermanentlyBlocked.Contains(ip))
            return true;

        return _ipBlockedUntil.TryGetValue(ip, out var blockedUntil) && _timing.RealTime < blockedUntil;
    }

    private void CleanupConnectionFilter(TimeSpan now)
    {
        var cleanupInterval = TimeSpan.FromSeconds(_config.GetCVar(CVars.NetIpFilterCleanupPeriod));
        if (now - _lastConnectionFilterCleanup < cleanupInterval)
            return;

        _lastConnectionFilterCleanup = now;

        List<IPAddress>? expiredBlocks = null;
        foreach (var (ip, blockedUntil) in _ipBlockedUntil)
        {
            if (now < blockedUntil)
                continue;

            expiredBlocks ??= new List<IPAddress>();
            expiredBlocks.Add(ip);
        }

        if (expiredBlocks != null)
        {
            foreach (var ip in expiredBlocks)
                _ipBlockedUntil.Remove(ip);
        }

        var ratePeriod = TimeSpan.FromSeconds(_config.GetCVar(CVars.NetIpConnectRatePeriod));
        List<IPAddress>? expiredRates = null;
        foreach (var (ip, state) in _ipRateStates)
        {
            if (now - state.WindowStart <= ratePeriod)
                continue;

            expiredRates ??= new List<IPAddress>();
            expiredRates.Add(ip);
        }

        if (expiredRates != null)
        {
            foreach (var ip in expiredRates)
                _ipRateStates.Remove(ip);
        }
    }

    private static IPAddress NormalizeConnectionIp(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetworkV6)
            return address;

        var bytes = address.GetAddressBytes();
        for (var i = 8; i < 16; i++)
            bytes[i] = 0;

        return new IPAddress(bytes);
    }
}
