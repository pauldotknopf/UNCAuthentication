using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using BOOL = System.Boolean;
using DWORD = System.UInt32;
using LPWSTR = System.String;
using NET_API_STATUS = System.UInt32;

namespace UNCAuthentication
{
    public class UNCAccessWithCredentials : IDisposable
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct USE_INFO_2
        {
            internal LPWSTR ui2_local;
            internal LPWSTR ui2_remote;
            internal LPWSTR ui2_password;
            internal DWORD ui2_status;
            internal DWORD ui2_asg_type;
            internal DWORD ui2_refcount;
            internal DWORD ui2_usecount;
            internal LPWSTR ui2_username;
            internal LPWSTR ui2_domainname;
        }

        [DllImport("NetApi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern NET_API_STATUS NetUseAdd(
            LPWSTR UncServerName,
            DWORD Level,
            ref USE_INFO_2 Buf,
            out DWORD ParmError);

        [DllImport("NetApi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern NET_API_STATUS NetUseDel(
            LPWSTR UncServerName,
            LPWSTR UseName,
            DWORD ForceCond);

        private bool disposed = false;

        private string _uncPath;
        private string _user;
        private string _password;
        private string _domain;
        private int _lastError;

        /// <summary>
        /// The last system error code returned from NetUseAdd or NetUseDel.  Success = 0
        /// </summary>
        public int LastError
        {
            get { return _lastError; }
        }

        public void Dispose()
        {
            if (!this.disposed)
            {
                NetUseDelete();
            }
            disposed = true;
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Connects to a UNC path using the credentials supplied.
        /// </summary>
        /// <param name="uncPath">Fully qualified domain name UNC path</param>
        /// <param name="user">A user with sufficient rights to access the path.</param>
        /// <param name="domain">Domain of User.</param>
        /// <param name="password">Password of User</param>
        /// <returns>True if mapping succeeds.  Use LastError to get the system error code.</returns>
        public bool NetUseWithCredentials(string uncPath, string user, string domain, string password)
        {
            _uncPath = uncPath;
            _user = user;
            _password = password;
            _domain = domain;
            return NetUseWithCredentials();
        }

        private bool NetUseWithCredentials()
        {
            try
            {
                var useinfo = new USE_INFO_2
                {
                    ui2_remote = _uncPath,
                    ui2_username = _user,
                    ui2_domainname = _domain,
                    ui2_password = _password,
                    ui2_asg_type = 0,
                    ui2_usecount = 1
                };

                uint paramErrorIndex;
                uint returncode = NetUseAdd(null, 2, ref useinfo, out paramErrorIndex);
                _lastError = (int)returncode;
                return returncode == 0;
            }
            catch
            {
                _lastError = Marshal.GetLastWin32Error();
                return false;
            }
        }

        /// <summary>
        /// Ends the connection to the remote resource 
        /// </summary>
        /// <returns>True if it succeeds.  Use LastError to get the system error code</returns>
        public bool NetUseDelete()
        {
            try
            {
                uint returncode = NetUseDel(null, _uncPath, 2);
                _lastError = (int)returncode;
                return (returncode == 0);
            }
            catch
            {
                _lastError = Marshal.GetLastWin32Error();
                return false;
            }
        }

        ~UNCAccessWithCredentials()
        {
            Dispose();
        }

    }
}
