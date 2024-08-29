#include <iostream>
#include <Windows.h>
#include "../protections/pch.h"
#include "../Loading/Common.h"
#include "../Loading/VersionHelpers.h"
#include "../Loading/log.h"
#include "../Loading/Utils.h"
#include "../Loading/WinStructs.h"
#include "../Loading/ApiTypeDefs.h"
#include "../Loading/APIs.h"
#include "../Loading/winapifamily.h"
#include <thread>

BOOL ENABLE_TLS_CHECKS = FALSE;
BOOL ENABLE_DEBUG_CHECKS = TRUE;
BOOL ENABLE_INJECTION_CHECKS = TRUE; // unstable
BOOL ENABLE_GEN_SANDBOX_CHECKS = FALSE;
BOOL ENABLE_VBOX_CHECKS = FALSE;
BOOL ENABLE_VMWARE_CHECKS = FALSE;
BOOL ENABLE_VPC_CHECKS = TRUE;
BOOL ENABLE_KVM_CHECKS = TRUE;
BOOL ENABLE_XEN_CHECKS = TRUE;
BOOL ENABLE_WINE_CHECKS = TRUE;
BOOL ENABLE_PARALLELS_CHECKS = TRUE;
BOOL ENABLE_CODE_INJECTIONS = TRUE;
BOOL ENABLE_DUMPING_CHECK = TRUE;
BOOL ENABLE_ANALYSIS_TOOLS_CHECK = TRUE;

void EnableChecks(std::string checkType) {
	if (checkType == "TLS")						ENABLE_TLS_CHECKS = TRUE;
	else if (checkType == "DEBUG")				ENABLE_DEBUG_CHECKS = TRUE;
	else if (checkType == "INJECTION")			ENABLE_INJECTION_CHECKS = TRUE;
	else if (checkType == "GEN_SANDBOX")		ENABLE_GEN_SANDBOX_CHECKS = TRUE;
	else if (checkType == "VBOX")				ENABLE_VBOX_CHECKS = TRUE;
	else if (checkType == "VMWARE")				ENABLE_VMWARE_CHECKS = TRUE;
	else if (checkType == "VPC")				ENABLE_VPC_CHECKS = TRUE;
	else if (checkType == "KVM")				ENABLE_KVM_CHECKS = TRUE;
	else if (checkType == "XEN")				ENABLE_XEN_CHECKS = TRUE;
	else if (checkType == "WINE")				ENABLE_WINE_CHECKS = TRUE;
	else if (checkType == "PARALLELS")			ENABLE_PARALLELS_CHECKS = TRUE;
	else if (checkType == "CODE_INJECTIONS")	ENABLE_CODE_INJECTIONS = TRUE;
	else if (checkType == "DUMPING_CHECK")		ENABLE_DUMPING_CHECK = TRUE;
	else if (checkType == "ANALYSIS_TOOLS")		ENABLE_ANALYSIS_TOOLS_CHECK = TRUE;
}

void DisableChecks(std::string checkType) {
	if (checkType == "TLS")						ENABLE_TLS_CHECKS = FALSE;
	else if (checkType == "DEBUG")				ENABLE_DEBUG_CHECKS = FALSE;
	else if (checkType == "INJECTION")			ENABLE_INJECTION_CHECKS = FALSE;
	else if (checkType == "GEN_SANDBOX")		ENABLE_GEN_SANDBOX_CHECKS = FALSE;
	else if (checkType == "VBOX")				ENABLE_VBOX_CHECKS = FALSE;
	else if (checkType == "VMWARE")				ENABLE_VMWARE_CHECKS = FALSE;
	else if (checkType == "VPC")				ENABLE_VPC_CHECKS = FALSE;
	else if (checkType == "KVM")				ENABLE_KVM_CHECKS = FALSE;
	else if (checkType == "XEN")				ENABLE_XEN_CHECKS = FALSE;
	else if (checkType == "WINE")				ENABLE_WINE_CHECKS = FALSE;
	else if (checkType == "PARALLELS")			ENABLE_PARALLELS_CHECKS = FALSE;
	else if (checkType == "CODE_INJECTIONS")	ENABLE_CODE_INJECTIONS = FALSE;
	else if (checkType == "DUMPING_CHECK")		ENABLE_DUMPING_CHECK = FALSE;
	else if (checkType == "ANALYSIS_TOOLS")		ENABLE_ANALYSIS_TOOLS_CHECK = FALSE;
}

void ProtectionThread()
{
	while (true)
	{
		if (ENABLE_TLS_CHECKS) {
			print_category(TEXT("TLS Callbacks"));
			execute_protection(&TLSCallbackThread, TEXT("TLS thread attach callback "));
		}

		if (ENABLE_DEBUG_CHECKS) {
			print_category(TEXT("Debugger Detection"));
			execute_protection(&IsDebuggerPresentAPI, TEXT("Checking IsDebuggerPresent API "));
			execute_protection(&IsDebuggerPresentPEB, TEXT("Checking PEB.BeingDebugged "));
			execute_protection(&CheckRemoteDebuggerPresentAPI, TEXT("Checking CheckRemoteDebuggerPresent API "));
			execute_protection(&NtGlobalFlag, TEXT("Checking PEB.NtGlobalFlag "));
			execute_protection(&HeapFlags, TEXT("Checking ProcessHeap.Flags "));
			execute_protection(&HeapForceFlags, TEXT("Checking ProcessHeap.ForceFlags "));
			execute_protection(&NtQueryInformationProcess_ProcessDebugPort, TEXT("Checking NtQueryInformationProcess with ProcessDebugPort "));
			execute_protection(&NtQueryInformationProcess_ProcessDebugFlags, TEXT("Checking NtQueryInformationProcess with ProcessDebugFlags "));
			execute_protection(&NtQueryInformationProcess_ProcessDebugObject, TEXT("Checking NtQueryInformationProcess with ProcessDebugObject "));
			execute_protection(&WUDF_IsAnyDebuggerPresent, TEXT("Checking WudfIsAnyDebuggerPresent API "));
			execute_protection(&WUDF_IsKernelDebuggerPresent, TEXT("Checking WudfIsKernelDebuggerPresent API "));
			execute_protection(&WUDF_IsUserDebuggerPresent, TEXT("Checking WudfIsUserDebuggerPresent API "));
			execute_protection(&NtSetInformationThread_ThreadHideFromDebugger, TEXT("Checking NtSetInformationThread with ThreadHideFromDebugger "));
			execute_protection(&CloseHandle_InvalideHandle, TEXT("Checking CloseHandle with an invalide handle "));
			execute_protection(&NtSystemDebugControl_Command, TEXT("Checking NtSystemDebugControl"));
			execute_protection(&UnhandledExcepFilterTest, TEXT("Checking UnhandledExcepFilterTest "));
			execute_protection(&OutputDebugStringAPI, TEXT("Checking OutputDebugString "));
			execute_protection(&HardwareBreakpoints, TEXT("Checking Hardware Breakpoints "));
			execute_protection(&SoftwareBreakpoints, TEXT("Checking Software Breakpoints "));
			execute_protection(&Interrupt_3, TEXT("Checking Interupt 1 "));
			execute_protection(&TrapFlag, TEXT("Checking trap flag"));
			execute_protection(&MemoryBreakpoints_PageGuard, TEXT("Checking Memory Breakpoints PAGE GUARD "));
			execute_protection(&IsParentExplorerExe, TEXT("Checking If Parent Process is explorer.exe "));
			execute_protection(&CanOpenCsrss, TEXT("Checking SeDebugPrivilege "));
			execute_protection(&NtQueryObject_ObjectTypeInformation, TEXT("Checking NtQueryObject with ObjectTypeInformation "));
			execute_protection(&NtQueryObject_ObjectAllTypesInformation, TEXT("Checking NtQueryObject with ObjectAllTypesInformation "));
			execute_protection(&NtQuerySystemInformation_SystemKernelDebuggerInformation, TEXT("Checking NtQuerySystemInformation with SystemKernelDebuggerInformation  "));
			execute_protection(&SharedUserData_KernelDebugger, TEXT("Checking SharedUserData->KdDebuggerEnabled  "));
			execute_protection(&ProcessJob, TEXT("Checking if process is in a job  "));
			execute_protection(&VirtualAlloc_WriteWatch_BufferOnly, TEXT("Checking VirtualAlloc write watch (buffer only) "));
			execute_protection(&VirtualAlloc_WriteWatch_APICalls, TEXT("Checking VirtualAlloc write watch (API calls) "));
			execute_protection(&VirtualAlloc_WriteWatch_IsDebuggerPresent, TEXT("Checking VirtualAlloc write watch (IsDebuggerPresent) "));
			execute_protection(&VirtualAlloc_WriteWatch_CodeWrite, TEXT("Checking VirtualAlloc write watch (code write) "));
			execute_protection(&ModuleBoundsHookCheck, TEXT("Checking for API hooks outside module bounds "));
		}

		if (ENABLE_INJECTION_CHECKS) {
			print_category(TEXT("DLL Injection Detection"));
			execute_protection(&ScanForModules_EnumProcessModulesEx_32bit, TEXT("Enumerating modules with EnumProcessModulesEx [32-bit] "));
			execute_protection(&ScanForModules_EnumProcessModulesEx_64bit, TEXT("Enumerating modules with EnumProcessModulesEx [64-bit] "));
			execute_protection(&ScanForModules_EnumProcessModulesEx_All, TEXT("Enumerating modules with EnumProcessModulesEx [ALL] "));
			execute_protection(&ScanForModules_ToolHelp32, TEXT("Enumerating modules with ToolHelp32 "));
			execute_protection(&ScanForModules_LdrEnumerateLoadedModules, TEXT("Enumerating the process LDR via LdrEnumerateLoadedModules "));
			execute_protection(&ScanForModules_LDR_Direct, TEXT("Enumerating the process LDR directly "));
			//execute_protection(&ScanForModules_MemoryWalk_GMI, TEXT("Walking process memory with GetModuleInformation "));
			//execute_protection(&ScanForModules_MemoryWalk_Hidden, TEXT("Walking process memory for hidden modules "));
			//execute_protection(&ScanForModules_DotNetModuleStructures, TEXT("Walking process memory for .NET module structures "));
		}

		if (ENABLE_GEN_SANDBOX_CHECKS) {
			print_category(TEXT("Generic Sandboxe/VM Detection"));
			loaded_dlls();
			known_file_names();
			known_usernames();
			known_hostnames();
			other_known_sandbox_environment_checks();
			execute_protection(&NumberOfProcessors, TEXT("Checking Number of processors in machine "));
			execute_protection(&idt_trick, TEXT("Checking Interupt Descriptor Table location "));
			execute_protection(&gdt_trick, TEXT("Checking Global Descriptor Table location "));
			execute_protection(&str_trick, TEXT("Checking Store Task Register "));
			execute_protection(&number_cores_wmi, TEXT("Checking Number of cores in machine using WMI "));
			execute_protection(&disk_size_wmi, TEXT("Checking hard disk size using WMI "));
			execute_protection(&dizk_size_deviceiocontrol, TEXT("Checking hard disk size using DeviceIoControl "));
			execute_protection(&setupdi_diskdrive, TEXT("Checking SetupDi_diskdrive "));
			execute_protection(&memory_space, TEXT("Checking memory space using GlobalMemoryStatusEx "));
			execute_protection(&disk_size_getdiskfreespace, TEXT("Checking disk size using GetDiskFreeSpaceEx "));
			execute_protection(&cpuid_is_hypervisor, TEXT("Checking if CPU hypervisor field is set using cpuid(0x1)"));
			execute_protection(&cpuid_hypervisor_vendor, TEXT("Checking hypervisor vendor using cpuid(0x40000000)"));
			execute_protection(&VMDriverServices, TEXT("VM Driver Services  "));
			execute_protection(&serial_number_bios_wmi, TEXT("Checking SerialNumber from BIOS using WMI "));
			execute_protection(&model_computer_system_wmi, TEXT("Checking Model from ComputerSystem using WMI "));
			execute_protection(&manufacturer_computer_system_wmi, TEXT("Checking Manufacturer from ComputerSystem using WMI "));
			execute_protection(&current_temperature_acpi_wmi, TEXT("Checking Current Temperature using WMI "));
			execute_protection(&process_id_processor_wmi, TEXT("Checking ProcessId using WMI "));
			execute_protection(&power_capabilities, TEXT("Checking power capabilities "));
			execute_protection(&query_license_value, TEXT("Checking NtQueryLicenseValue with Kernel-VMDetection-Private "));
			execute_protection(&cachememory_wmi, TEXT("Checking Win32_CacheMemory with WMI "));
			execute_protection(&physicalmemory_wmi, TEXT("Checking Win32_PhysicalMemory with WMI "));
			execute_protection(&memorydevice_wmi, TEXT("Checking Win32_MemoryDevice with WMI "));
			execute_protection(&memoryarray_wmi, TEXT("Checking Win32_MemoryArray with WMI "));
			execute_protection(&portconnector_wmi, TEXT("Checking Win32_PortConnector with WMI "));
			execute_protection(&smbiosmemory_wmi, TEXT("Checking Win32_SMBIOSMemory with WMI "));
			execute_protection(&perfctrs_thermalzoneinfo_wmi, TEXT("Checking ThermalZoneInfo performance counters with WMI "));
			execute_protection(&cim_memory_wmi, TEXT("Checking CIM_Memory with WMI "));
			execute_protection(&cim_physicalconnector_wmi, TEXT("Checking CIM_PhysicalConnector with WMI "));
			execute_protection(&cim_slot_wmi, TEXT("Checking CIM_Slot with WMI "));
			execute_protection(&registry_services_disk_enum, TEXT("Checking Services\\Disk\\Enum entries for VM strings "));
			execute_protection(&registry_disk_enum, TEXT("Checking Enum\\IDE and Enum\\SCSI entries for VM strings "));
		}

		if (ENABLE_VBOX_CHECKS) {
			print_category(TEXT("VirtualBox Detection"));
			vbox_reg_key_value();
			execute_protection(&vbox_dir, TEXT("Checking VirtualBox Guest Additions directory "));
			vbox_files();
			vbox_reg_keys();
			execute_protection(&vbox_check_mac, TEXT("Checking Mac Address start with 08:00:27 "));
			execute_protection(&hybridanalysismacdetect, TEXT("Checking MAC address (Hybrid Analysis) "));
			vbox_devices();
			execute_protection(&vbox_window_class, TEXT("Checking VBoxTrayToolWndClass / VBoxTrayToolWnd "));
			execute_protection(&vbox_network_share, TEXT("Checking VirtualBox Shared Folders network provider "));
			vbox_processes();
			execute_protection(&vbox_pnpentity_pcideviceid_wmi, TEXT("Checking Win32_PnPDevice DeviceId from WMI for VBox PCI device "));
			execute_protection(&vbox_pnpentity_controllers_wmi, TEXT("Checking Win32_PnPDevice Name from WMI for VBox controller hardware "));
			execute_protection(&vbox_pnpentity_vboxname_wmi, TEXT("Checking Win32_PnPDevice Name from WMI for VBOX names "));
			execute_protection(&vbox_bus_wmi, TEXT("Checking Win32_Bus from WMI "));
			execute_protection(&vbox_baseboard_wmi, TEXT("Checking Win32_BaseBoard from WMI "));
			execute_protection(&vbox_mac_wmi, TEXT("Checking MAC address from WMI "));
			execute_protection(&vbox_eventlogfile_wmi, TEXT("Checking NTEventLog from WMI "));
			execute_protection(&vbox_firmware_ACPI, TEXT("Checking ACPI tables  "));
		}

		if (ENABLE_VMWARE_CHECKS) {
			print_category(TEXT("VMWare Detection"));
			vmware_reg_key_value();
			vmware_reg_keys();
			vmware_files();
			vmware_mac();
			execute_protection(&vmware_adapter_name, TEXT("Checking VMWare network adapter name "));
			vmware_devices();
			execute_protection(&vmware_dir, TEXT("Checking VMWare directory "));
			execute_protection(&vmware_firmware_ACPI, TEXT("Checking ACPI tables  "));
		}

		if (ENABLE_VPC_CHECKS) {
			print_category(TEXT("Virtual PC Detection"));
			virtual_pc_process();
			virtual_pc_reg_keys();
		}

		if (ENABLE_XEN_CHECKS) {
			print_category(TEXT("Xen Detection"));
			xen_process();
			execute_protection(&xen_check_mac, TEXT("Checking Mac Address start with 08:16:3E "));
		}

		if (ENABLE_KVM_CHECKS) {
			print_category(TEXT("KVM Detection"));
			kvm_files();
			kvm_reg_keys();
			execute_protection(&kvm_dir, TEXT("Checking KVM virio directory "));
		}

		if (ENABLE_WINE_CHECKS) {
			print_category(TEXT("Wine Detection"));
			execute_protection(&wine_exports, TEXT("Checking Wine via dll exports "));
			wine_reg_keys();
		}

		if (ENABLE_PARALLELS_CHECKS) {
			print_category(TEXT("Paralles Detection"));
			parallels_process();
			execute_protection(&parallels_check_mac, TEXT("Checking Mac Address start with 00:1C:42 "));
		}

		if (ENABLE_CODE_INJECTIONS) {
			CreateRemoteThread_Injection();
			SetWindowsHooksEx_Injection();
			NtCreateThreadEx_Injection();
			RtlCreateUserThread_Injection();
			QueueUserAPC_Injection();
			GetSetThreadContext_Injection();
		}

		if (ENABLE_ANALYSIS_TOOLS_CHECK) {
			print_category(TEXT("Analysis-tools"));
			analysis_tools_process();
		}

		if (ENABLE_DUMPING_CHECK) {
			print_category(TEXT("Anti Dumping"));
			ErasePEHeaderFromMemory();
			SizeOfImage();
		}

		_tprintf(_T("\n\nProtection Check Is Done"));
	}
}

int main()
{
	API::Init();
	API::PrintAvailabilityReport();
	std::thread(ProtectionThread).detach();

	getchar();
}