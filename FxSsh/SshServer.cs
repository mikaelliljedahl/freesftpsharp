﻿using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace FxSsh
{
    public class SshServer : IDisposable
    {
        private readonly object _lock = new object();
        private readonly List<Session> sessions = new List<Session>();
        private readonly Dictionary<string, string> hostKeys = new Dictionary<string, string>();
        private bool _isDisposed;
        private bool _started;
        private TcpListener _listenser = null;

        public SshServer()
            : this(new StartingInfo())
        { }

        public SshServer(StartingInfo info)
        {
            Contract.Requires(info != null);

            StartingInfo = info;
        }

        public StartingInfo StartingInfo { get; private set; }

        public event EventHandler<Session> ConnectionAccepted;
        public event EventHandler<Exception> ExceptionRasied;

        public void Start()
        {
            lock (_lock)
            {
                CheckDisposed();
                if (_started)
                    throw new InvalidOperationException("The server is already started.");

                _listenser = StartingInfo.LocalAddress == IPAddress.IPv6Any
                    ? TcpListener.Create(StartingInfo.Port) // dual stack
                    : new TcpListener(StartingInfo.LocalAddress, StartingInfo.Port);
                _listenser.ExclusiveAddressUse = false;
                _listenser.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                _listenser.Start();
                BeginAcceptSocket();

                _started = true;
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                CheckDisposed();
                if (!_started)
                    throw new InvalidOperationException("The server is not started.");

                _listenser.Stop();

                _isDisposed = true;
                _started = false;

                foreach (var session in sessions)
                {
                    try
                    {
                        session.Disconnect();
                    }
                    catch
                    {
                    }
                }
            }
        }

        public void AddHostKey(string type, string xml)
        {
            Contract.Requires(type != null);
            Contract.Requires(xml != null);

            if (!hostKeys.ContainsKey(type))
                hostKeys.Add(type, xml);
        }

        private void BeginAcceptSocket()
        {
            try
            {
                _listenser.BeginAcceptSocket(AcceptSocket, null);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch
            {
                if (_started)
                    BeginAcceptSocket();
            }
        }

        private void AcceptSocket(IAsyncResult ar)
        {
            try
            {
                var socket = _listenser.EndAcceptSocket(ar);
                Task.Run(() =>
                {
                    var session = new Session(socket, hostKeys);
                    session.Disconnected += (ss, ee) => { lock (_lock) sessions.Remove(session); };
                    lock (_lock)
                        sessions.Add(session);
                    try
                    {
                        ConnectionAccepted?.Invoke(this, session);
                        session.EstablishConnection();
                    }
                    catch (SshConnectionException ex)
                    {
                        session.Disconnect(ex.DisconnectReason, ex.Message);
                        ExceptionRasied?.Invoke(this, ex);
                    }
                    catch (Exception ex)
                    {
                        session.Disconnect();
                        ExceptionRasied?.Invoke(this, ex);
                    }
                });
            }
            catch
            {
            }
            finally
            {
                BeginAcceptSocket();
            }
        }

        private void CheckDisposed()
        {
            if (_isDisposed)
                throw new ObjectDisposedException(GetType().FullName);
        }

        #region IDisposable
        public void Dispose()
        {
            lock (_lock)
            {
                if (_isDisposed)
                    return;
                Stop();
            }
        }
        #endregion
    }
}
