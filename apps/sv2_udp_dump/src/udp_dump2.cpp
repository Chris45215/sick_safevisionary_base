#include <iostream>
#include <memory>

// Use the direct headers from the vendor tree.
// If your headers live under include/sick_safevisionary_base/, you can also:
//   #include "sick_safevisionary_base/SafeVisionaryData.h"
//   #include "sick_safevisionary_base/SafeVisionaryDataStream.h"
#include "SafeVisionaryData.h"
#include "SafeVisionaryDataStream.h"

int main(int argc, char** argv) {
    uint16_t port = (argc > 1) ? static_cast<uint16_t>(std::stoi(argv[1])) : 2115;

    auto data = std::make_shared<visionary::SafeVisionaryData>();
    visionary::SafeVisionaryDataStream stream(data);

    // This overload binds to the local UDP port.
    if (!stream.openUdpConnection(port)) {
        std::cerr << "Failed to bind UDP port " << port << "\n";
        return 1;
    }

    std::cout << "Listening on UDP port " << port << "...\n";
    for (;;) {
        if (stream.getNextBlobUdp()) {
            const auto& dist = data->getDistanceMap();
            std::cout << "blob ok  pixels=" << dist.size()
                      << "  status=" << static_cast<int>(data->getDeviceStatus())
                      << "  flags=0x" << std::hex << data->getFlags() << std::dec << "\n";
        } else {
            std::cout << "timeout/parse error\n";
        }
    }
}
