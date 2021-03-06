using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Devmon;

// Example Usage Code
foreach (HardwareManager.SetupApi.Devices.Device device in HardwareManager.SetupApi.Devices.deviceInfoList)
{
    Console.Write(device.Name != string.Empty? $"{device.Name}\n" : "Unknown Device \n");

    foreach (var variableProperty in device.Properties)
    {
        Console.Write($"[{variableProperty.Key}] {variableProperty.Value}\n");
    }
    Console.Write("\n");
}
//Console.WriteLine(CompareHardware(HardwareManager.SetupApi.GetDeviceEnumerator(), HardwareManager.SetupApi.GetDeviceEnumerator()));

//foreach (HardwareManager.SetupApi.Device device in currentHardware)
//{
//    //HardwareManager.SetupApi.SetDeviceState(n => n.ToUpperInvariant().Contains(device.HardwareID), false);
//}

if (IsUserAnAdmin())
{
    Console.WriteLine(HardwareManager.SetupApi.SetDeviceState(
        n => n.ToUpperInvariant().Contains("PCI\\VEN_10DE&DEV_1F15&SUBSYS_20111A58&REV_A1"), false)
        ? $"[PCIe] Disabled Device @ PCI\\VEN_10DE&DEV_1F15&SUBSYS_20111A58&REV_A1"
        : $"[PCIe] Test Failure for Device @ PCI\\VEN_10DE&DEV_1F15&SUBSYS_20111A58&REV_A1");
}
else
{
    Console.WriteLine("[PCIe] cannot access device state, current process has insufficient privileges");
}   

// I'm lazy
static string PrintNotEmpty(string Input)
{
    return Input == "" ? "Null" : Input;
}

[DllImport("shell32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
static extern bool IsUserAnAdmin();