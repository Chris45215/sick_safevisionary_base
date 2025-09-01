#include <iostream>
#include <memory>
#include "sick_safevisionary_base/SafeVisionaryData.h"
#include "sick_safevisionary_base/SafeVisionaryDataStream.h"

int main(int argc, char** argv) {
    uint16_t port = (argc > 1) ? static_cast<uint16_t>(std::stoi(argv[1])) : 2011;

    auto data = std::make_shared<visionary::SafeVisionaryData>();
    visionary::SafeVisionaryDataStream stream(data);

    if (!stream.openUdpConnection(port)) {
        std::cerr << "Failed to bind UDP port " << port << "\n";
        return 1;
    }

    std::cout << "Listening on UDP port " << port << "...\n";
    for (;;) {
        if (stream.getNextBlobUdp()) {
            const auto& dist = data->getDistanceMap();
            std::cout << "pixels=" << dist.size()
                      << " status=" << static_cast<int>(data->getDeviceStatus())
                      << " flags=0x" << std::hex << data->getFlags() << std::dec << "\n";
        } else {
            std::cout << "No blob (timeout or parse error)\n";
        }
    }
}
