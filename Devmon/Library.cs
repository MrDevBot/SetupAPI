using System.ComponentModel;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
// ReSharper disable SuggestVarOrType_BuiltInTypes
// ReSharper disable SuggestVarOrType_SimpleTypes
// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Local
// ReSharper disable IdentifierTypo
// ReSharper disable SuggestVarOrType_Elsewhere

//AE: Only god and I know what I was thinking when I wrote this, now only god knows.

namespace Devmon;

public static class HardwareManager
{
    public static class SetupApi
    {
        private const string SETUPAPI = "setupapi.dll";
        private const int ERROR_INVALID_DATA = 13;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        private class SafeDeviceInformationSetHandle : SafeHandleMinusOneIsInvalid
        {
            private SafeDeviceInformationSetHandle() : base(true) { }
            private SafeDeviceInformationSetHandle(IntPtr preexistingHandle, bool ownsHandle) : base(ownsHandle)
            {
                SetHandle(preexistingHandle);
            }

            [SecurityCritical]
            protected override bool ReleaseHandle()
            {
                return SetupDiDestroyDeviceInfoList(handle);
            }
        }

        #region Enumerations

        [Flags]
        private enum DIGCF : uint
        {
            DEFAULT = 0x00000001,
            PRESENT = 0x00000002,
            ALLCLASSES = 0x00000004,
            PROFILE = 0x00000008,
            DEVICEINTERFACE = 0x00000010
        }

        public enum SPDRP : uint
        {
            /// <summary>
            /// DeviceDesc (R/W)
            /// </summary>
            DEVICEDESC = 0x00000000,

            /// <summary>
            /// HardwareID (R/W)
            /// </summary>
            HARDWAREID = 0x00000001,

            /// <summary>
            /// CompatibleIDs (R/W)
            /// </summary>
            COMPATIBLEIDS = 0x00000002,

            /// <summary>
            /// unused
            /// </summary>
            UNUSED0 = 0x00000003,

            /// <summary>
            /// Service (R/W)
            /// </summary>
            SERVICE = 0x00000004,

            /// <summary>
            /// unused
            /// </summary>
            UNUSED1 = 0x00000005,

            /// <summary>
            /// unused
            /// </summary>
            UNUSED2 = 0x00000006,

            /// <summary>
            /// Class (R--tied to ClassGUID)
            /// </summary>
            CLASS = 0x00000007,

            /// <summary>
            /// ClassGUID (R/W)
            /// </summary>
            CLASSGUID = 0x00000008,

            /// <summary>
            /// Driver (R/W)
            /// </summary>
            DRIVER = 0x00000009,

            /// <summary>
            /// ConfigFlags (R/W)
            /// </summary>
            CONFIGFLAGS = 0x0000000A,

            /// <summary>
            /// Mfg (R/W)
            /// </summary>
            MFG = 0x0000000B,

            /// <summary>
            /// FriendlyName (R/W)
            /// </summary>
            FRIENDLYNAME = 0x0000000C,

            /// <summary>
            /// LocationInformation (R/W)
            /// </summary>
            LOCATION_INFORMATION = 0x0000000D,

            /// <summary>
            /// PhysicalDeviceObjectName (R)
            /// </summary>
            PHYSICAL_DEVICE_OBJECT_NAME = 0x0000000E,

            /// <summary>
            /// Capabilities (R)
            /// </summary>
            CAPABILITIES = 0x0000000F,

            /// <summary>
            /// UiNumber (R)
            /// </summary>
            UI_NUMBER = 0x00000010,

            /// <summary>
            /// UpperFilters (R/W)
            /// </summary>
            UPPERFILTERS = 0x00000011,

            /// <summary>
            /// LowerFilters (R/W)
            /// </summary>
            LOWERFILTERS = 0x00000012,

            /// <summary>
            /// BusTypeGUID (R)
            /// </summary>
            BUSTYPEGUID = 0x00000013,

            /// <summary>
            /// LegacyBusType (R)
            /// </summary>
            LEGACYBUSTYPE = 0x00000014,

            /// <summary>
            /// BusNumber (R)
            /// </summary>
            BUSNUMBER = 0x00000015,

            /// <summary>
            /// Enumerator Name (R)
            /// </summary>
            ENUMERATOR_NAME = 0x00000016,

            /// <summary>
            /// Security (R/W, binary form)
            /// </summary>
            SECURITY = 0x00000017,

            /// <summary>
            /// Security (W, SDS form)
            /// </summary>
            SECURITY_SDS = 0x00000018,

            /// <summary>
            /// Device Type (R/W)
            /// </summary>
            DEVTYPE = 0x00000019,

            /// <summary>
            /// Device is exclusive-access (R/W)
            /// </summary>
            EXCLUSIVE = 0x0000001A,

            /// <summary>
            /// Device Characteristics (R/W)
            /// </summary>
            CHARACTERISTICS = 0x0000001B,

            /// <summary>
            /// Device Address (R)
            /// </summary>
            ADDRESS = 0x0000001C,

            /// <summary>
            /// UiNumberDescFormat (R/W)
            /// </summary>
            UI_NUMBER_DESC_FORMAT = 0X0000001D,

            /// <summary>
            /// Device Power Data (R)
            /// </summary>
            DEVICE_POWER_DATA = 0x0000001E,

            /// <summary>
            /// Removal Policy (R)
            /// </summary>
            REMOVAL_POLICY = 0x0000001F,

            /// <summary>
            /// Hardware Removal Policy (R)
            /// </summary>
            REMOVAL_POLICY_HW_DEFAULT = 0x00000020,

            /// <summary>
            /// Removal Policy Override (RW)
            /// </summary>
            REMOVAL_POLICY_OVERRIDE = 0x00000021,

            /// <summary>
            /// Device Install State (R)
            /// </summary>
            INSTALL_STATE = 0x00000022,

            /// <summary>
            /// Device Location Paths (R)
            /// </summary>
            LOCATION_PATHS = 0x00000023,
        }

        private enum DIF : uint
        {
            SELECTDEVICE = 0x00000001,
            INSTALLDEVICE = 0x00000002,
            ASSIGNRESOURCES = 0x00000003,
            PROPERTIES = 0x00000004,
            REMOVE = 0x00000005,
            FIRSTTIMESETUP = 0x00000006,
            FOUNDDEVICE = 0x00000007,
            SELECTCLASSDRIVERS = 0x00000008,
            VALIDATECLASSDRIVERS = 0x00000009,
            INSTALLCLASSDRIVERS = 0x0000000A,
            CALCDISKSPACE = 0x0000000B,
            DESTROYPRIVATEDATA = 0x0000000C,
            VALIDATEDRIVER = 0x0000000D,
            DETECT = 0x0000000F,
            INSTALLWIZARD = 0x00000010,
            DESTROYWIZARDDATA = 0x00000011,
            PROPERTYCHANGE = 0x00000012,
            ENABLECLASS = 0x00000013,
            DETECTVERIFY = 0x00000014,
            INSTALLDEVICEFILES = 0x00000015,
            UNREMOVE = 0x00000016,
            SELECTBESTCOMPATDRV = 0x00000017,
            ALLOW_INSTALL = 0x00000018,
            REGISTERDEVICE = 0x00000019,
            NEWDEVICEWIZARD_PRESELECT = 0x0000001A,
            NEWDEVICEWIZARD_SELECT = 0x0000001B,
            NEWDEVICEWIZARD_PREANALYZE = 0x0000001C,
            NEWDEVICEWIZARD_POSTANALYZE = 0x0000001D,
            NEWDEVICEWIZARD_FINISHINSTALL = 0x0000001E,
            UNUSED1 = 0x0000001F,
            INSTALLINTERFACES = 0x00000020,
            DETECTCANCEL = 0x00000021,
            REGISTER_COINSTALLERS = 0x00000022,
            ADDPROPERTYPAGE_ADVANCED = 0x00000023,
            ADDPROPERTYPAGE_BASIC = 0x00000024,
            RESERVED1 = 0x00000025,
            TROUBLESHOOTER = 0x00000026,
            POWERMESSAGEWAKE = 0x00000027,
            ADDREMOTEPROPERTYPAGE_ADVANCED = 0x00000028,
            UPDATEDRIVER_UI = 0x00000029,
            FINISHINSTALL_ACTION = 0x0000002A,
            RESERVED2 = 0x00000030,
        }

        private enum DICS : uint
        {
            ENABLE = 0x00000001,
            DISABLE = 0x00000002,
            PROPCHANGE = 0x00000003,
            START = 0x00000004,
            STOP = 0x00000005,
        }

        [Flags]
        private enum DICS_FLAG : uint
        {
            GLOBAL = 0x00000001,
            CONFIGSPECIFIC = 0x00000002,
            CONFIGGENERAL = 0x00000004,
        }

        #endregion

        #region Structures

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA
        {
            public uint cbSize;
            private readonly Guid ClassGuid;
            private readonly uint DevInst;
            private readonly IntPtr Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_CLASSINSTALL_HEADER
        {
            public uint cbSize;
            public DIF InstallFunction;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_PROPCHANGE_PARAMS
        {
            public SP_CLASSINSTALL_HEADER ClassInstallHeader;
            public DICS StateChange;
            public DICS_FLAG Scope;
            public uint HwProfile;
        }

        #endregion

        #region P/Invoke Functions

        [DllImport(SETUPAPI, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeDeviceInformationSetHandle SetupDiGetClassDevs(
            [In] ref Guid ClassGuid,
            [In] string? Enumerator,
            IntPtr hwndParent,
            DIGCF Flags
        );

        #pragma warning disable CS0618
        [DllImport(SETUPAPI, SetLastError = true), ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        #pragma warning restore CS0618
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        [DllImport(SETUPAPI, SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInfo(
            SafeDeviceInformationSetHandle DeviceInfoSet,
            uint MemberIndex,
            ref SP_DEVINFO_DATA DeviceInfoData
        );

        [DllImport(SETUPAPI, SetLastError = true)]
        private static extern bool SetupDiSetClassInstallParams(
            SafeDeviceInformationSetHandle DeviceInfoSet,
            [In] ref SP_DEVINFO_DATA deviceInfoData,
            [In] ref SP_PROPCHANGE_PARAMS classInstallParams,
            uint ClassInstallParamsSize
        );

        [DllImport(SETUPAPI, SetLastError = true)]
        private static extern bool SetupDiChangeState(
            SafeDeviceInformationSetHandle DeviceInfoSet,
            [In, Out] ref SP_DEVINFO_DATA DeviceInfoData
        );

        [DllImport(SETUPAPI, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool SetupDiGetDeviceRegistryProperty(
            SafeDeviceInformationSetHandle DeviceInfoSet,
            [In] ref SP_DEVINFO_DATA DeviceInfoData,
            SPDRP Property,
            out RegistryValueKind PropertyRegDataType,
            [Out] byte[]? PropertyBuffer,
            uint PropertyBufferSize,
            out uint RequiredSize
        );

        #endregion

        private static void CheckWin32CallSuccess(bool success)
        {
            if (!success)
            {
                throw new Win32Exception();
            }
        }

        private static string GetStringPropertyForDevice(SafeDeviceInformationSetHandle infoSet,
            ref SP_DEVINFO_DATA devInfo, SPDRP property)
        {
            if (!SetupDiGetDeviceRegistryProperty(infoSet, ref devInfo, property, out _, null, 0,
                    out var requiredSize))
            {
                switch (Marshal.GetLastWin32Error())
                {
                    case ERROR_INSUFFICIENT_BUFFER:
                        break;
                    case ERROR_INVALID_DATA:
                        return string.Empty;
                    default:
                        throw new Win32Exception();
                }
            }

            // ReSharper disable once HeapView.ObjectAllocation.Evident
            byte[] propertyBuffer = new byte[requiredSize];
            CheckWin32CallSuccess(SetupDiGetDeviceRegistryProperty(infoSet, ref devInfo, property, out _,
                propertyBuffer, (uint) propertyBuffer.Length, out requiredSize));

            return Encoding.Unicode.GetString(propertyBuffer);
        }
        
        public static class Devices
        {
            public struct Property
            {
                public string Key;
                public string Value;

                public Property(string Key, string Value)
                {
                    this.Key = Key;
                    this.Value = Value;
                }
            }

            public struct Device
            {
                public string Name;
                public List<Property> Properties;
            }

            public static readonly List<Device> deviceInfoList = GetDeviceEnumerator();
        }
        private static List<Devices.Device> GetDeviceEnumerator()
        {
            List<Devices.Device> retVal = new List<Devices.Device>();
            var nullGuid = Guid.Empty;
            using SafeDeviceInformationSetHandle infoSet =
                SetupDiGetClassDevs(ref nullGuid, null, IntPtr.Zero, DIGCF.ALLCLASSES);
            CheckWin32CallSuccess(!infoSet.IsInvalid);

            SP_DEVINFO_DATA devInfo = new SP_DEVINFO_DATA();
            devInfo.cbSize = (uint) Marshal.SizeOf(devInfo);

            for (uint index = 0;; ++index)
            {
                try
                {
                    Devices.Device currentDevice = new Devices.Device();
                    CheckWin32CallSuccess(SetupDiEnumDeviceInfo(infoSet, index, ref devInfo));
                    Console.WriteLine(GetStringPropertyForDevice(infoSet, ref devInfo, SPDRP.CLASS));

                    currentDevice.Name = GetStringPropertyForDevice(infoSet, ref devInfo, SPDRP.FRIENDLYNAME);
                    currentDevice.Properties = new List<Devices.Property>();
                    currentDevice.Properties.Add(new Devices.Property("", ""));
                    
                    //add currentDevice to return list
                    retVal.Add(currentDevice);
                }
                catch (Exception exception) // Type: System.ComponentModel.Win32Exception, cant use explicit, cant ref 
                {
                    if (exception.Message == "No more data is available.")
                    {
                        return retVal;
                    }
                    throw;
                }
            }
        }

        public static bool SetDeviceState(Func<string, bool> hardwareIdFilter, bool enable)
        {
            var nullGuid = Guid.Empty;
            using SafeDeviceInformationSetHandle infoSet =
                SetupDiGetClassDevs(ref nullGuid, null, IntPtr.Zero, DIGCF.ALLCLASSES);
            CheckWin32CallSuccess(!infoSet.IsInvalid);

            SP_DEVINFO_DATA devInfo = new SP_DEVINFO_DATA();
            devInfo.cbSize = (uint) Marshal.SizeOf(devInfo);

            for (uint index = 0;; ++index)
            {
                CheckWin32CallSuccess(SetupDiEnumDeviceInfo(infoSet, index, ref devInfo));

                string hardwareId = GetStringPropertyForDevice(infoSet, ref devInfo, SPDRP.HARDWAREID);

                try
                {
                    if ((!string.IsNullOrEmpty(hardwareId)) && (hardwareIdFilter(hardwareId)))
                    {
                        break;
                    }
                }
                catch (Exception)
                {
                    return false;
                }
            }

            SP_CLASSINSTALL_HEADER classinstallHeader = new SP_CLASSINSTALL_HEADER();
            classinstallHeader.cbSize = (uint) Marshal.SizeOf(classinstallHeader);
            classinstallHeader.InstallFunction = DIF.PROPERTYCHANGE;

            SP_PROPCHANGE_PARAMS propchangeParams = new SP_PROPCHANGE_PARAMS
            {
                ClassInstallHeader = classinstallHeader,
                StateChange = enable ? DICS.ENABLE : DICS.DISABLE,
                Scope = DICS_FLAG.GLOBAL,
                HwProfile = 0,
            };

            CheckWin32CallSuccess(SetupDiSetClassInstallParams(infoSet, ref devInfo, ref propchangeParams,
                (uint) Marshal.SizeOf(propchangeParams)));
            CheckWin32CallSuccess(SetupDiChangeState(infoSet, ref devInfo));

            return true;
        }
    }
}

public class DisplayManager
{
    //todo https://docs.microsoft.com/en-us/previous-versions/ms812499(v=msdn.10)?redirectedfrom=MSDN
}