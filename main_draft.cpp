#include "include/sick_safevisionary_base/SafeVisionaryDataStream.h" // SafeVisionaryDataStream.hpp"   // comes with the SDK
#include "include/sick_safevisionary_base/SafeVisionaryData.h"//"SafeVisionaryData.hpp"

int main(int argc, char** argv)
{
    using namespace visionary;           // same as in the .cpp files
    uint16_t port = 12000;               // or pass via argv

    SafeVisionaryData     dataHandler;
    SafeVisionaryDataStream stream(&dataHandler);

    if (!stream.openUdpConnection(port)) {
        std::cerr << "Cannot bind UDP port\n";
        return 1;
    }

    while (true) {
        if (!stream.getNextBlobUdp()) {              // blocks until a full Blob or error
            if (stream.getLastError() == DataStreamError::DATA_RECEIVE_TIMEOUT)
                continue;                            // benign: just try again
            std::cerr << "Stream error\n";
            continue;                                // or break / reconnect
        }

        /* --- You now have a complete frame --- */
        auto& depth  = dataHandler.getDepthMap();    // std::vector<uint16_t>
        uint64_t ts  = dataHandler.getBlobTimestamp();
        uint32_t fno = dataHandler.getFrameNumber();

        process(depth, ts, fno);                     // your code
    }
}