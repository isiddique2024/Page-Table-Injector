#include "pdb.hpp"
#include <dia2.h>
#include <diacreate.h>
#include <atlbase.h>

#pragma comment(lib, "diaguids.lib")

// helper class to initialize COM once
class ComInitializer {
public:
  ComInitializer() {
    HRESULT hr = CoInitialize(NULL);
    initialized = SUCCEEDED(hr);
  }
  ~ComInitializer() {
    if (initialized) {
      CoUninitialize();
    }
  }

private:
  bool initialized;
};

// global COM initializer
static ComInitializer g_com_init;

std::string pdb_download(const std::string& pe_path, const std::string& pdb_download_path,
                         const std::string& symbol_server) {
  if (pe_path.empty()) {
    mapper_log("ERROR", "PE path cannot be empty");
    SetLastError(ERROR_INVALID_PARAMETER);
    return "";
  }

  mapper_log("SUCCESS", "starting PDB download for: %ws",
             std::wstring(pe_path.begin(), pe_path.end()).c_str());

  // determine PDB download directory
  std::string download_path = pdb_download_path;
  if (download_path.empty()) {
    char sz_download_dir[MAX_PATH] = {0};
    if (!GetCurrentDirectoryA(sizeof(sz_download_dir), sz_download_dir)) {
      mapper_log("ERROR", "failed to get current directory: 0x%lx", GetLastError());
      return "";
    }
    download_path = sz_download_dir;
    mapper_log("SUCCESS", "using current directory for PDB download");
  }

  if (download_path[download_path.size() - 1] != '\\') {
    download_path += "\\";
  }

  // create directory if it doesn't exist
  if (!CreateDirectoryA(download_path.c_str(), NULL)) {
    if (GetLastError() != ERROR_ALREADY_EXISTS) {
      mapper_log("ERROR", "failed to create download directory: 0x%lx", GetLastError());
      return "";
    }
  }

  mapper_log("SUCCESS", "download directory: %ws",
             std::wstring(download_path.begin(), download_path.end()).c_str());

#ifndef _AMD64_
  PVOID old_value = NULL;
  if (!Wow64DisableWow64FsRedirection(&old_value)) {
    mapper_log("ERROR", "failed to disable WOW64 redirection: 0x%lx", GetLastError());
  }
#endif

  // read PE file
  std::ifstream file(pe_path, std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    mapper_log("ERROR", "failed to open PE file: %ws",
               std::wstring(pe_path.begin(), pe_path.end()).c_str());
#ifndef _AMD64_
    Wow64RevertWow64FsRedirection(old_value);
#endif
    SetLastError(ERROR_FILE_NOT_FOUND);
    return "";
  }

  auto size = file.tellg();
  if (size <= 0) {
    mapper_log("ERROR", "PE file is empty or invalid");
    file.close();
#ifndef _AMD64_
    Wow64RevertWow64FsRedirection(old_value);
#endif
    SetLastError(ERROR_INVALID_DATA);
    return "";
  }

  file.seekg(0, std::ios::beg);
  std::vector<char> buffer(size);

#ifndef _AMD64_
  Wow64RevertWow64FsRedirection(old_value);
#endif

  if (!file.read(buffer.data(), size)) {
    mapper_log("ERROR", "failed to read PE file data");
    SetLastError(ERROR_ACCESS_DENIED);
    return "";
  }

  mapper_log("SUCCESS", "PE file read successfully, size: 0x%llx bytes", size);

  std::string pdb_path = download_path + Md5(buffer.data(), static_cast<ULONG>(size)) + ".pdb";

  // parse PE headers
  if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) {
    mapper_log("ERROR", "file too small to contain DOS header");
    SetLastError(ERROR_INVALID_DATA);
    return "";
  }

  auto p_dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
  if (p_dos->e_magic != IMAGE_DOS_SIGNATURE) {
    mapper_log("ERROR", "invalid DOS signature");
    SetLastError(ERROR_INVALID_DATA);
    return "";
  }

  if (buffer.size() < p_dos->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
    mapper_log("ERROR", "file too small to contain NT headers");
    SetLastError(ERROR_INVALID_DATA);
    return "";
  }

  auto p_nt = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.data() + p_dos->e_lfanew);
  if (p_nt->Signature != IMAGE_NT_SIGNATURE) {
    mapper_log("ERROR", "invalid NT signature");
    SetLastError(ERROR_INVALID_DATA);
    return "";
  }

  auto p_file = &p_nt->FileHeader;
  IMAGE_OPTIONAL_HEADER64* p_opt64 = nullptr;
  IMAGE_OPTIONAL_HEADER32* p_opt32 = nullptr;
  bool is_x86 = false;

  if (p_file->Machine == IMAGE_FILE_MACHINE_AMD64) {
    p_opt64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(&p_nt->OptionalHeader);
    mapper_log("SUCCESS", "detected x64 PE file");
  } else if (p_file->Machine == IMAGE_FILE_MACHINE_I386) {
    p_opt32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&p_nt->OptionalHeader);
    is_x86 = true;
    mapper_log("SUCCESS", "detected x86 PE file");
  } else {
    mapper_log("ERROR", "unsupported machine type: 0x%x", p_file->Machine);
    SetLastError(ERROR_NOT_SUPPORTED);
    return "";
  }

  auto image_size = is_x86 ? p_opt32->SizeOfImage : p_opt64->SizeOfImage;
  mapper_log("SUCCESS", "image size: 0x%lx bytes", image_size);

  // map file to image
  auto image_buffer = std::make_unique<BYTE[]>(image_size);
  if (!image_buffer) {
    mapper_log("ERROR", "failed to allocate image buffer");
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return "";
  }

  auto headers_size = is_x86 ? p_opt32->SizeOfHeaders : p_opt64->SizeOfHeaders;
  std::memcpy(image_buffer.get(), buffer.data(), headers_size);

  auto p_current_section_header = IMAGE_FIRST_SECTION(p_nt);
  for (UINT i = 0; i != p_file->NumberOfSections; ++i, ++p_current_section_header) {
    if (p_current_section_header->SizeOfRawData) {
      if (p_current_section_header->VirtualAddress + p_current_section_header->SizeOfRawData >
              image_size ||
          p_current_section_header->PointerToRawData + p_current_section_header->SizeOfRawData >
              buffer.size()) {
        mapper_log("ERROR", "invalid section data detected");
        SetLastError(ERROR_INVALID_DATA);
        return "";
      }

      std::memcpy(image_buffer.get() + p_current_section_header->VirtualAddress,
                  buffer.data() + p_current_section_header->PointerToRawData,
                  p_current_section_header->SizeOfRawData);
    }
  }

  // get debug directory
  IMAGE_DATA_DIRECTORY* p_data_dir = nullptr;
  if (is_x86) {
    p_data_dir = &p_opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
  } else {
    p_data_dir = &p_opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
  }

  if (!p_data_dir->Size || p_data_dir->VirtualAddress >= image_size) {
    mapper_log("ERROR", "no debug directory found or invalid debug directory");
    SetLastError(ERROR_NOT_SUPPORTED);
    return "";
  }

  auto p_debug_dir =
      reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(image_buffer.get() + p_data_dir->VirtualAddress);
  if (IMAGE_DEBUG_TYPE_CODEVIEW != p_debug_dir->Type) {
    mapper_log("ERROR", "debug directory type is not CodeView");
    SetLastError(ERROR_NOT_SUPPORTED);
    return "";
  }

  if (p_debug_dir->AddressOfRawData >= image_size) {
    mapper_log("ERROR", "invalid debug raw data address");
    SetLastError(ERROR_INVALID_DATA);
    return "";
  }

  auto pdb_info_ptr =
      reinterpret_cast<pdb_info*>(image_buffer.get() + p_debug_dir->AddressOfRawData);
  if (pdb_info_ptr->signature != 0x53445352) {  // 'RSDS'
    mapper_log("ERROR", "invalid PDB signature");
    SetLastError(ERROR_NOT_SUPPORTED);
    return "";
  }

  mapper_log("SUCCESS", "found valid PDB info in debug directory");

  // convert GUID to string
  wchar_t w_guid[100] = {0};
  if (!StringFromGUID2(pdb_info_ptr->guid, w_guid, 100)) {
    mapper_log("ERROR", "failed to convert GUID to string");
    SetLastError(ERROR_NOT_SUPPORTED);
    return "";
  }

  char a_guid[100] = {0};
  size_t l_guid = 0;
  if (wcstombs_s(&l_guid, a_guid, w_guid, sizeof(a_guid)) || !l_guid) {
    mapper_log("ERROR", "failed to convert GUID to multibyte string");
    SetLastError(ERROR_NOT_SUPPORTED);
    return "";
  }

  // filter GUID (remove non-hex characters)
  char guid_filtered[256] = {0};
  for (size_t i = 0; i != l_guid; ++i) {
    if ((a_guid[i] >= '0' && a_guid[i] <= '9') || (a_guid[i] >= 'A' && a_guid[i] <= 'F') ||
        (a_guid[i] >= 'a' && a_guid[i] <= 'f')) {
      guid_filtered[strlen(guid_filtered)] = a_guid[i];
    }
  }

  char age[16] = {0};
  if (_itoa_s(pdb_info_ptr->age, age, 10) != 0) {
    mapper_log("ERROR", "failed to convert age to string");
    SetLastError(ERROR_NOT_SUPPORTED);
    return "";
  }

  // construct download URL
  std::string url = symbol_server;
  url += pdb_info_ptr->pdb_file_name;
  url += "/";
  url += guid_filtered;
  url += age;
  url += "/";
  url += pdb_info_ptr->pdb_file_name;

  mapper_log("SUCCESS", "download URL: %ws", std::wstring(url.begin(), url.end()).c_str());

  // download PDB
  DeleteFileA(pdb_path.c_str());
  auto hr = URLDownloadToFileA(NULL, url.c_str(), pdb_path.c_str(), NULL, NULL);
  if (FAILED(hr)) {
    mapper_log("ERROR", "failed to download PDB file, HRESULT: 0x%08x", hr);
    SetLastError(12029);
    return "";
  }

  mapper_log("SUCCESS", "PDB downloaded successfully to: %ws",
             std::wstring(pdb_path.begin(), pdb_path.end()).c_str());

  return pdb_path;
}

bool pdb_load(const std::string& pdb_path, p_pdb_context pdb) {
  if (pdb_path.empty() || !pdb) {
    mapper_log("ERROR", "invalid parameters for pdb_load");
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  mapper_log("SUCCESS", "loading PDB: %ws", std::wstring(pdb_path.begin(), pdb_path.end()).c_str());

  // Initialize context
  std::memset(pdb, 0, sizeof(pdb_context));

  // create DIA data source
  CComPtr<IDiaDataSource> pSource;
  HRESULT hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER, IID_IDiaDataSource,
                                (void**)&pSource);

  if (FAILED(hr)) {
    // try alternative method - NoRegCoCreate
    hr = NoRegCoCreate(L"msdia140.dll", CLSID_DiaSource, IID_IDiaDataSource, (void**)&pSource);
    if (FAILED(hr)) {
      mapper_log("ERROR", "failed to create DIA data source: 0x%08x", hr);
      SetLastError(ERROR_NOT_SUPPORTED);
      return false;
    }
  }

  // load PDB data
  std::wstring wide_path(pdb_path.begin(), pdb_path.end());
  hr = pSource->loadDataFromPdb(wide_path.c_str());
  if (FAILED(hr)) {
    mapper_log("ERROR", "failed to load PDB data: 0x%08x", hr);
    SetLastError(ERROR_INVALID_DATA);
    return false;
  }

  // open session
  CComPtr<IDiaSession> pSession;
  hr = pSource->openSession(&pSession);
  if (FAILED(hr)) {
    mapper_log("ERROR", "failed to open DIA session: 0x%08x", hr);
    SetLastError(ERROR_ACCESS_DENIED);
    return false;
  }

  // get global scope
  CComPtr<IDiaSymbol> pGlobal;
  hr = pSession->get_globalScope(&pGlobal);
  if (FAILED(hr)) {
    mapper_log("ERROR", "failed to get global scope: 0x%08x", hr);
    SetLastError(ERROR_ACCESS_DENIED);
    return false;
  }

  // store DIA objects in context (we'll need to cast them back when using)
  pdb->h_pdb_file = (HANDLE)pSource.Detach();     // store as opaque handle
  pdb->h_process = (HANDLE)pSession.Detach();     // store session as process handle
  pdb->base_address = (DWORD64)pGlobal.Detach();  // store global scope

  // verify symbols are loaded by enumerating a few
  mapper_log("SUCCESS", "enumerating symbols for verification...");

  IDiaSession* pSessionRaw = (IDiaSession*)pdb->h_process;
  IDiaSymbol* pGlobalRaw = (IDiaSymbol*)pdb->base_address;

  CComPtr<IDiaEnumSymbols> pEnumSymbols;
  hr = pGlobalRaw->findChildren(SymTagPublicSymbol, NULL, nsNone, &pEnumSymbols);

  if (SUCCEEDED(hr)) {
    LONG count = 0;
    hr = pEnumSymbols->get_Count(&count);
    if (SUCCEEDED(hr) && count > 0) {
      mapper_log("SUCCESS", "found %d public symbols", count);

      // show first few symbols
      CComPtr<IDiaSymbol> pSymbol;
      ULONG celt = 0;
      for (int i = 0;
           i < min(10, count) && SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && celt == 1;
           i++) {
        BSTR name;
        if (SUCCEEDED(pSymbol->get_name(&name))) {
          mapper_log("DEBUG", "Symbol[%d]: %ws", i, name);
          SysFreeString(name);
        }
        pSymbol.Release();
      }
    } else {
      mapper_log("WARNING", "no public symbols found in PDB");
    }
  }

  mapper_log("SUCCESS", "PDB loaded successfully using DIA SDK");
  return true;
}

ULONG pdb_get_rva(p_pdb_context pdb, const std::string& sym_name) {
  if (!pdb || !pdb->h_process || sym_name.empty()) {
    mapper_log("ERROR", "invalid parameters for pdb_get_rva");
    return static_cast<ULONG>(-1);
  }

  IDiaSession* pSession = (IDiaSession*)pdb->h_process;
  IDiaSymbol* pGlobal = (IDiaSymbol*)pdb->base_address;

  // convert symbol name to wide string
  std::wstring wide_name(sym_name.begin(), sym_name.end());

  // find symbol by name
  CComPtr<IDiaEnumSymbols> pEnumSymbols;
  HRESULT hr =
      pGlobal->findChildren(SymTagNull, wide_name.c_str(), nsfCaseInsensitive, &pEnumSymbols);

  if (FAILED(hr)) {
    mapper_log("ERROR", "failed to find symbol '%s': 0x%08x", sym_name.c_str(), hr);
    return static_cast<ULONG>(-1);
  }

  // get first matching symbol
  CComPtr<IDiaSymbol> pSymbol;
  ULONG celt = 0;
  hr = pEnumSymbols->Next(1, &pSymbol, &celt);

  if (FAILED(hr) || celt != 1) {
    // try with public symbols specifically
    pEnumSymbols.Release();
    hr = pGlobal->findChildren(SymTagPublicSymbol, wide_name.c_str(), nsfCaseInsensitive,
                               &pEnumSymbols);

    if (SUCCEEDED(hr)) {
      hr = pEnumSymbols->Next(1, &pSymbol, &celt);
    }

    if (FAILED(hr) || celt != 1) {
      mapper_log("ERROR", "symbol '%s' not found", sym_name.c_str());
      return static_cast<ULONG>(-1);
    }
  }

  // get RVA
  DWORD rva = 0;
  hr = pSymbol->get_relativeVirtualAddress(&rva);

  if (FAILED(hr)) {
    mapper_log("ERROR", "failed to get RVA for symbol '%s': 0x%08x", sym_name.c_str(), hr);
    return static_cast<ULONG>(-1);
  }

  mapper_log("SUCCESS", "Found symbol '%s' at RVA: 0x%x", sym_name.c_str(), rva);
  return static_cast<ULONG>(rva);
}

ULONG pdb_get_struct_property_offset(p_pdb_context pdb, const std::string& struct_name,
                                     const std::wstring& property_name) {
  if (!pdb || !pdb->h_process || struct_name.empty() || property_name.empty()) {
    mapper_log("ERROR", "invalid parameters for pdb_get_struct_property_offset");
    return static_cast<ULONG>(-1);
  }

  IDiaSession* pSession = (IDiaSession*)pdb->h_process;
  IDiaSymbol* pGlobal = (IDiaSymbol*)pdb->base_address;

  // convert struct name to wide string
  std::wstring wide_struct_name(struct_name.begin(), struct_name.end());

  // find UDT (User Defined Type) by name
  CComPtr<IDiaEnumSymbols> pEnumSymbols;
  HRESULT hr =
      pGlobal->findChildren(SymTagUDT, wide_struct_name.c_str(), nsfCaseInsensitive, &pEnumSymbols);

  if (FAILED(hr)) {
    mapper_log("ERROR", "failed to find struct '%s': 0x%08x", struct_name.c_str(), hr);
    return static_cast<ULONG>(-1);
  }

  // get first matching UDT
  CComPtr<IDiaSymbol> pUDT;
  ULONG celt = 0;
  hr = pEnumSymbols->Next(1, &pUDT, &celt);

  if (FAILED(hr) || celt != 1) {
    mapper_log("ERROR", "struct '%s' not found", struct_name.c_str());
    return static_cast<ULONG>(-1);
  }

  // find children (members) of the UDT
  CComPtr<IDiaEnumSymbols> pEnumMembers;
  hr = pUDT->findChildren(SymTagData, NULL, nsNone, &pEnumMembers);

  if (FAILED(hr)) {
    mapper_log("ERROR", "failed to enumerate struct members: 0x%08x", hr);
    return static_cast<ULONG>(-1);
  }

  // iterate through members to find the property
  CComPtr<IDiaSymbol> pMember;
  while (SUCCEEDED(pEnumMembers->Next(1, &pMember, &celt)) && celt == 1) {
    BSTR memberName;
    if (SUCCEEDED(pMember->get_name(&memberName))) {
      if (wcscmp(memberName, property_name.c_str()) == 0) {
        // found the property, get its offset
        LONG offset = 0;
        hr = pMember->get_offset(&offset);
        SysFreeString(memberName);

        if (SUCCEEDED(hr)) {
          mapper_log("SUCCESS", "Found property '%ws' at offset 0x%x in struct '%s'",
                     property_name.c_str(), offset, struct_name.c_str());
          return static_cast<ULONG>(offset);
        }

        mapper_log("ERROR", "failed to get offset for property '%ws': 0x%08x",
                   property_name.c_str(), hr);
        return static_cast<ULONG>(-1);
      }
      SysFreeString(memberName);
    }
    pMember.Release();
  }

  mapper_log("ERROR", "property '%ws' not found in struct '%s'", property_name.c_str(),
             struct_name.c_str());
  return static_cast<ULONG>(-1);
}

ULONG pdb_get_struct_size(p_pdb_context pdb, const std::string& struct_name) {
  if (!pdb || !pdb->h_process || struct_name.empty()) {
    mapper_log("ERROR", "invalid parameters for pdb_get_struct_size");
    return static_cast<ULONG>(-1);
  }

  IDiaSession* pSession = (IDiaSession*)pdb->h_process;
  IDiaSymbol* pGlobal = (IDiaSymbol*)pdb->base_address;

  // convert struct name to wide string
  std::wstring wide_struct_name(struct_name.begin(), struct_name.end());

  // find UDT by name
  CComPtr<IDiaEnumSymbols> pEnumSymbols;
  HRESULT hr =
      pGlobal->findChildren(SymTagUDT, wide_struct_name.c_str(), nsfCaseInsensitive, &pEnumSymbols);

  if (FAILED(hr)) {
    mapper_log("ERROR", "failed to find struct '%s': 0x%08x", struct_name.c_str(), hr);
    return static_cast<ULONG>(-1);
  }

  // get first matching UDT
  CComPtr<IDiaSymbol> pUDT;
  ULONG celt = 0;
  hr = pEnumSymbols->Next(1, &pUDT, &celt);

  if (FAILED(hr) || celt != 1) {
    mapper_log("ERROR", "struct '%s' not found", struct_name.c_str());
    return static_cast<ULONG>(-1);
  }

  // get size
  ULONGLONG size = 0;
  hr = pUDT->get_length(&size);

  if (FAILED(hr)) {
    mapper_log("ERROR", "failed to get size for struct '%s': 0x%08x", struct_name.c_str(), hr);
    return static_cast<ULONG>(-1);
  }

  mapper_log("SUCCESS", "Struct '%s' size: 0x%llx bytes", struct_name.c_str(), size);
  return static_cast<ULONG>(size);
}

void pdb_unload(const std::string& pdb_path, p_pdb_context pdb) {
  if (!pdb) {
    mapper_log("ERROR", "invalid PDB context for unload");
    return;
  }

  mapper_log("SUCCESS", "unloading PDB");

  // release DIA objects
  if (pdb->base_address) {
    IDiaSymbol* pGlobal = (IDiaSymbol*)pdb->base_address;
    pGlobal->Release();
    pdb->base_address = 0;
  }

  if (pdb->h_process) {
    IDiaSession* pSession = (IDiaSession*)pdb->h_process;
    pSession->Release();
    pdb->h_process = nullptr;
  }

  if (pdb->h_pdb_file) {
    IDiaDataSource* pSource = (IDiaDataSource*)pdb->h_pdb_file;
    pSource->Release();
    pdb->h_pdb_file = nullptr;
  }

  // delete PDB file if path provided
  if (!pdb_path.empty()) {
    if (DeleteFileA(pdb_path.c_str())) {
      mapper_log("SUCCESS", "PDB file deleted successfully");
    } else {
      mapper_log("ERROR", "failed to delete PDB file: 0x%lx", GetLastError());
    }
  }

  mapper_log("SUCCESS", "PDB unloaded successfully");
}