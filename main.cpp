// main.cpp
#include <memory>
#include <thread>
#include <atomic>
#include "include/sick_safevisionary_base/SafeVisionaryDataStream.h"
#include "include/sick_safevisionary_base/SafeVisionaryData.h"

using namespace visionary;

int main()
{
    constexpr uint16_t SENSOR_UDP_PORT = 30722;   // change per device
    auto data = std::make_shared<SafeVisionaryData>();
    SafeVisionaryDataStream stream(data);

    if (!stream.openUdpConnection(SENSOR_UDP_PORT))
    {
        std::fprintf(stderr,"Could not bind UDP port\n");
        return -1;
    }

    while (true)
    {
        if (!stream.getNextBlobUdp())          // blocks until a full frame OR a drop
            continue;                          // bad telegram discarded – simply wait for next

        // --- we now own a complete, validated telegram --------------------------
        const auto &depth = data->getDistanceMap();      // 1/4 mm units
        uint32_t f       = data->getFrameNum();
        uint64_t ts_ms   = data->getTimestampMS();

        // TODO: push <depth,f,ts_ms> to your processing queue or directly process here.
    }
}
