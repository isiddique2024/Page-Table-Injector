namespace utils {
#define DISABLE_DEBUG_PRINT 0
#if DISABLE_DEBUG_PRINT
  #define log(level, format, ...) ((void)0)
#else
  #define log(level, format, ...)                                         \
    do {                                                                  \
      const char* prefix;                                                 \
      if (strcmp(level, "SUCCESS") == 0)                                  \
        prefix = "[+]";                                                   \
      else if (strcmp(level, "ERROR") == 0)                               \
        prefix = "[!]";                                                   \
      else if (strcmp(level, "WARNING") == 0)                             \
        prefix = "[-]";                                                   \
      else                                                                \
        prefix = "[?]";                                                   \
      printf("%s %s: " format "\n", prefix, __FUNCTION__, ##__VA_ARGS__); \
    } while (0)
#endif

  // read a file into a byte array
  std::vector<uint8_t> read_file(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
      return {};
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
      return {};
    }

    return buffer;
  }

}  // namespace utils