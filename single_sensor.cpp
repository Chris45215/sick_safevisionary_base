#include <memory>
#include "include/sick_safevisionary_base/SafeVisionaryDataStream.h"
#include "include/sick_safevisionary_base/SafeVisionaryData.h"

int main(int argc, char** argv)
{
    using namespace visionary;
    uint16_t port = 12000;

    auto dataHandler = std::make_shared<SafeVisionaryData>();

    //SafeVisionaryData dataHandler;
    //SafeVisionaryDataStream stream(&dataHandler);
    SafeVisionaryDataStream stream(dataHandler);


    if (!stream.openUdpConnection(port)) {
        std::cerr << "Cannot bind UDP port\n";
        return 1;
    }

    /*
    while (true) {
        if (!stream.getNextBlobUdp()) { //blocks until a full blob or error
            if (stream.getLastError() == DataStreamError::DATA_RECEIVE_TIMEOUT) 
            continue;   //try again
            }
            std::cerr << "Stream error\n";
            continue;       //or break / reconnect
    }
    */
    while (stream.getNextBlobUdp())
    {
        const auto& depth = dataHandler->getDistanceMap();   //of type std::vector<uint16_t>
        std::uint64_t ts = dataHandler->getBlobTimestamp(); //Get this from the array SafeVisionaryData.m_segmentTimestamp, which is inherited from VisionaryData.cpp
        std::uint32_t fno = dataHandler->getFrameNum();

        use(depth, ts, fno);
    }

    //Now have a complete frame

    

    //process(depth, ts, fno);
}