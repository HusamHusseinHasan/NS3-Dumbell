
#include <string>
#include <fstream>
#include <cstdlib>
#include <map>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/gnuplot.h"

typedef uint32_t uint;

using namespace ns3;

#define ERROR 0.000001

NS_LOG_COMPONENT_DEFINE ("Dumbell-H01");

class APP: public Application {
	private:
		virtual void StartApplication(void);
		virtual void StopApplication(void);

		void ScheduleTx(void);
		void SendPacket(void);

		Ptr<Socket>     mSocket;
		Address         mPeer;
		uint32_t        mPacketSize;
		uint32_t        mNPackets;
		DataRate        mDataRate;
		EventId         mSendEvent;
		bool            mRunning;
		uint32_t        mPacketsSent;

	public:
		APP();
		virtual ~APP();

		void Setup(Ptr<Socket> socket, Address address, uint packetSize, uint nPackets, DataRate dataRate);
		void ChangeRate(DataRate newRate);
		void recv(int numBytesRcvd);

};

APP::APP(): mSocket(0),
		    mPeer(),
		    mPacketSize(0),
		    mNPackets(0),
		    mDataRate(0),
		    mSendEvent(),
		    mRunning(false),
		    mPacketsSent(0) {
}

APP::~APP() {
	mSocket = 0;
}

void APP::Setup(Ptr<Socket> socket, Address address, uint packetSize, uint nPackets, DataRate dataRate) {
	mSocket = socket;
	mPeer = address;
	mPacketSize = packetSize;
	mNPackets = nPackets;
	mDataRate = dataRate;
}

void APP::StartApplication() {
	mRunning = true;
	mPacketsSent = 0;
	mSocket->Bind();
	mSocket->Connect(mPeer);
	SendPacket();
}

void APP::StopApplication() {
	mRunning = false;
	if(mSendEvent.IsRunning()) {
		Simulator::Cancel(mSendEvent);
	}
	if(mSocket) {
		mSocket->Close();
	}
}

void APP::SendPacket() {
	Ptr<Packet> packet = Create<Packet>(mPacketSize);
	mSocket->Send(packet);

	if(++mPacketsSent < mNPackets) {
		ScheduleTx();
	}
}

void APP::ScheduleTx() {
	if (mRunning) {
		Time tNext(Seconds(mPacketSize*8/static_cast<double>(mDataRate.GetBitRate())));
		mSendEvent = Simulator::Schedule(tNext, &APP::SendPacket, this);
	}
}

void APP::ChangeRate(DataRate newrate) {
	mDataRate = newrate;
	return;
}

static void CwndChange(Ptr<OutputStreamWrapper> stream, double startTime, uint oldCwnd, uint newCwnd) {
	*stream->GetStream() << Simulator::Now ().GetSeconds () - startTime << "\t" << newCwnd << std::endl;
}

static void CwndChange2(Ptr<OutputStreamWrapper> stream, double startTime, uint oldCwnd, uint newCwnd) {
	*stream->GetStream() << Simulator::Now ().GetSeconds () - startTime << "\t" << newCwnd << std::endl;
}
std::map<uint, uint> mapDrop;
static void packetDrop(Ptr<OutputStreamWrapper> stream, double startTime, uint myId) {
	*stream->GetStream() << Simulator::Now ().GetSeconds () - startTime << "\t" << std::endl;
	if(mapDrop.find(myId) == mapDrop.end()) {
		mapDrop[myId] = 0;
	}
	mapDrop[myId]++;
}

void IncRate(Ptr<APP> app, DataRate rate) {
	app->ChangeRate(rate);
	return;
}

std::map<Address, double> mapBytesReceived;
std::map<std::string, double> mapBytesReceivedIPV4, mapMaxThroughput;
static double lastTimePrint = 0, lastTimePrintIPV4 = 0;
double printGap = 0;

void ReceivedPacket(Ptr<OutputStreamWrapper> stream, double startTime, std::string context, Ptr<const Packet> p, const Address& addr){
	double timeNow = Simulator::Now().GetSeconds();
	if(mapBytesReceived.find(addr) == mapBytesReceived.end())
		mapBytesReceived[addr] = 0;
	mapBytesReceived[addr] += p->GetSize();
	double kbps_ = (((mapBytesReceived[addr] * 8.0) / 1024)/(timeNow-startTime));
	if(timeNow - lastTimePrint >= printGap) {
		lastTimePrint = timeNow;
		*stream->GetStream() << timeNow-startTime << "\t" <<  kbps_ << std::endl;
	}
}

void ReceivedPacketIPV4(Ptr<OutputStreamWrapper> stream, double startTime, std::string context, Ptr<const Packet> p, Ptr<Ipv4> ipv4, uint interface) {
	double timeNow = Simulator::Now().GetSeconds();

	if(mapBytesReceivedIPV4.find(context) == mapBytesReceivedIPV4.end())
		mapBytesReceivedIPV4[context] = 0;
	if(mapMaxThroughput.find(context) == mapMaxThroughput.end())
		mapMaxThroughput[context] = 0;
	mapBytesReceivedIPV4[context] += p->GetSize();
	double kbps_ = (((mapBytesReceivedIPV4[context] * 8.0) / 1024)/(timeNow-startTime));
	if(timeNow - lastTimePrintIPV4 >= printGap) {
		lastTimePrintIPV4 = timeNow;
		*stream->GetStream() << timeNow-startTime << "\t" <<  kbps_ << std::endl;
		if(mapMaxThroughput[context] < kbps_)
			mapMaxThroughput[context] = kbps_;
	}
}

Ptr<Socket> uniFlow(Address sinkAddress, 
					uint sinkPort, 
					std::string tcpVariant, 
					Ptr<Node> hostNode, 
					Ptr<Node> sinkNode, 
					double startTime, 
					double stopTime,
					uint packetSize,
					uint numPackets,
					std::string dataRate,
					double appStartTime,
					double appStopTime) {
					
	if(tcpVariant.compare("TcpNewReno") == 0) {
		Config::SetDefault("ns3::TcpL4Protocol::SocketType",StringValue ("ns3::TcpNewReno"));  //TypeIdValue(TcpNewReno::GetTypeId())
	} else if(tcpVariant.compare("TcpWestwood") == 0) {
		Config::SetDefault("ns3::TcpL4Protocol::SocketType", StringValue ("ns3::TcpIllinois"));//TypeIdValue(TcpWestwood::GetTypeId())
	} else if(tcpVariant.compare("TcpHtcp") == 0) {
		Config::SetDefault("ns3::TcpL4Protocol::SocketType", TypeIdValue(TcpHtcp::GetTypeId()));
	} else if(tcpVariant.compare("TcpBic") == 0) {
		Config::SetDefault("ns3::TcpL4Protocol::SocketType", TypeIdValue(TcpBic::GetTypeId()));
	}else {
		fprintf(stderr, "Invalid TCP version\n");
		exit(EXIT_FAILURE);
	}
	PacketSinkHelper packetSinkHelper("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), sinkPort));
	ApplicationContainer sinkApps = packetSinkHelper.Install(sinkNode);
	sinkApps.Start(Seconds(startTime));
	sinkApps.Stop(Seconds(stopTime));

	Ptr<Socket> ns3TcpSocket = Socket::CreateSocket(hostNode, TcpSocketFactory::GetTypeId());
	
	Ptr<APP> app = CreateObject<APP>();
	app->Setup(ns3TcpSocket, sinkAddress, packetSize, numPackets, DataRate(dataRate));
	hostNode->AddApplication(app);
	app->SetStartTime(Seconds(appStartTime));
	app->SetStopTime(Seconds(appStopTime));
	return ns3TcpSocket;
}

int main(int argc, char **argv) {

	std::cout << "Part A started..." << std::endl;
	std::string rateHR = "100Mbps";
	std::string latencyHR = "20ms";
	std::string rateRR = "10Mbps";
	std::string latencyRR = "50ms";
	uint packetSize = 1.2*1024;		//1.2KB
	uint numSender = 4;
	double errorP = ERROR;

	//Creating channel without IP address
	PointToPointHelper p2pHR, p2pRR;
	p2pHR.SetDeviceAttribute("DataRate", StringValue(rateHR));
	p2pHR.SetChannelAttribute("Delay", StringValue(latencyHR));
	p2pRR.SetDeviceAttribute("DataRate", StringValue(rateRR));
	p2pRR.SetChannelAttribute("Delay", StringValue(latencyRR));

	//Adding some errorrate
	Ptr<RateErrorModel> em = CreateObjectWithAttributes<RateErrorModel> ("ErrorRate", DoubleValue (errorP));

	//Empty node containers
	NodeContainer routers, senders, receivers;
	//Create n nodes and append pointers to them to the end of this NodeContainer. 
	routers.Create(2);
	senders.Create(numSender);
	receivers.Create(numSender);

	NetDeviceContainer routerDevices = p2pRR.Install(routers);
	NetDeviceContainer leftRouterDevices, rightRouterDevices, senderDevices, receiverDevices;

	//Adding links
	std::cout << "Adding links" << std::endl;
	for(uint i = 0; i < numSender; ++i) {
		NetDeviceContainer cleft = p2pHR.Install(routers.Get(0), senders.Get(i));
		leftRouterDevices.Add(cleft.Get(0));
		senderDevices.Add(cleft.Get(1));
		cleft.Get(0)->SetAttribute("ReceiveErrorModel", PointerValue(em));

		NetDeviceContainer cright = p2pHR.Install(routers.Get(1), receivers.Get(i));
		rightRouterDevices.Add(cright.Get(0));
		receiverDevices.Add(cright.Get(1));
		cright.Get(0)->SetAttribute("ReceiveErrorModel", PointerValue(em));
	}

	//Install Internet Stack
	std::cout << "Install internet stack" << std::endl;
	InternetStackHelper stack;
	stack.Install(routers);
	stack.Install(senders);
	stack.Install(receivers);

	//Adding IP addresses
	std::cout << "Adding IP addresses" << std::endl;
	Ipv4AddressHelper senderIP = Ipv4AddressHelper("10.1.0.0", "255.255.255.0");
	Ipv4AddressHelper receiverIP = Ipv4AddressHelper("10.2.0.0", "255.255.255.0");
	Ipv4AddressHelper routerIP = Ipv4AddressHelper("10.3.0.0", "255.255.255.0");
	
	Ipv4InterfaceContainer routerIFC, senderIFCs, receiverIFCs, leftRouterIFCs, rightRouterIFCs;

	routerIFC = routerIP.Assign(routerDevices);

	for(uint i = 0; i < numSender; ++i) {
		NetDeviceContainer senderDevice;
		senderDevice.Add(senderDevices.Get(i));
		senderDevice.Add(leftRouterDevices.Get(i));
		Ipv4InterfaceContainer senderIFC = senderIP.Assign(senderDevice);
		senderIFCs.Add(senderIFC.Get(0));
		leftRouterIFCs.Add(senderIFC.Get(1));
		senderIP.NewNetwork();

		NetDeviceContainer receiverDevice;
		receiverDevice.Add(receiverDevices.Get(i));
		receiverDevice.Add(rightRouterDevices.Get(i));
		Ipv4InterfaceContainer receiverIFC = receiverIP.Assign(receiverDevice);
		receiverIFCs.Add(receiverIFC.Get(0));
		rightRouterIFCs.Add(receiverIFC.Get(1));
		receiverIP.NewNetwork();
	}

	std::cout << "Measuring Performance of each TCP variant..." << std::endl;
	double durationGap = 100;
	double netDuration = 0;
	uint port = 9000;
	uint numPackets = 10000000;
	std::string transferSpeed = "100Mbps";	

	//TCP TcpNewReno from H1 to H5
	AsciiTraceHelper asciiTraceHelper;
	Ptr<OutputStreamWrapper> stream1CWND = asciiTraceHelper.CreateFileStream("h1.cwnd");
	Ptr<OutputStreamWrapper> stream1PD = asciiTraceHelper.CreateFileStream("h1.congestion_loss");
	Ptr<OutputStreamWrapper> stream1TP = asciiTraceHelper.CreateFileStream("h1.tp");
	Ptr<OutputStreamWrapper> stream1GP = asciiTraceHelper.CreateFileStream("h1.gp");
	Ptr<Socket> ns3TcpSocket1 = uniFlow(InetSocketAddress(receiverIFCs.GetAddress(0), port), port, "TcpNewReno", senders.Get(0), receivers.Get(0), netDuration, netDuration+durationGap, packetSize, numPackets, transferSpeed, netDuration, netDuration+durationGap);
	ns3TcpSocket1->TraceConnectWithoutContext("CongestionWindow", MakeBoundCallback (&CwndChange, stream1CWND, netDuration));
	ns3TcpSocket1->TraceConnectWithoutContext("Drop", MakeBoundCallback (&packetDrop, stream1PD, netDuration, 1));

	// Measure PacketSinks
	std::string sink = "/NodeList/6/ApplicationList/0/$ns3::PacketSink/Rx";
	Config::Connect(sink, MakeBoundCallback(&ReceivedPacket, stream1GP, netDuration));

	std::string sink_ = "/NodeList/6/$ns3::Ipv4L3Protocol/Rx";
	Config::Connect(sink_, MakeBoundCallback(&ReceivedPacketIPV4, stream1TP, netDuration));

	netDuration += durationGap;
    transferSpeed = "10Mbps";	
	//TCP Westwood from H2 to H6
	Ptr<OutputStreamWrapper> stream2CWND = asciiTraceHelper.CreateFileStream("h2.cwnd");
	Ptr<OutputStreamWrapper> stream2PD = asciiTraceHelper.CreateFileStream("h2.congestion_loss");
	Ptr<OutputStreamWrapper> stream2TP = asciiTraceHelper.CreateFileStream("h2.tp");
	Ptr<OutputStreamWrapper> stream2GP = asciiTraceHelper.CreateFileStream("h2.gp");
	Ptr<Socket> ns3TcpSocket2 = uniFlow(InetSocketAddress(receiverIFCs.GetAddress(1), port), port, "TcpWestwood", senders.Get(1), receivers.Get(1), netDuration, netDuration+durationGap, packetSize, numPackets, transferSpeed, netDuration, netDuration+durationGap); 
	ns3TcpSocket2->TraceConnectWithoutContext("CongestionWindow", MakeBoundCallback (&CwndChange2, stream2CWND, netDuration));
	ns3TcpSocket2->TraceConnectWithoutContext("Drop", MakeBoundCallback (&packetDrop, stream2PD, netDuration, 2));

	sink = "/NodeList/7/ApplicationList/0/$ns3::PacketSink/Rx";
	Config::Connect(sink, MakeBoundCallback(&ReceivedPacket, stream2GP, netDuration));
	sink_ = "/NodeList/7/$ns3::Ipv4L3Protocol/Rx";
	Config::Connect(sink_, MakeBoundCallback(&ReceivedPacketIPV4, stream2TP, netDuration));
	netDuration += durationGap;
    
    transferSpeed = "50Mbps";	
	//TCP TcpHtcp from H3 to H7
	Ptr<OutputStreamWrapper> stream3CWND = asciiTraceHelper.CreateFileStream("h3.cwnd");
	Ptr<OutputStreamWrapper> stream3PD = asciiTraceHelper.CreateFileStream("h3.congestion_loss");
	Ptr<OutputStreamWrapper> stream3TP = asciiTraceHelper.CreateFileStream("h3.tp");
	Ptr<OutputStreamWrapper> stream3GP = asciiTraceHelper.CreateFileStream("h3.gp");
	Ptr<Socket> ns3TcpSocket3 = uniFlow(InetSocketAddress(receiverIFCs.GetAddress(2), port), port, "TcpHtcp", senders.Get(2), receivers.Get(2), netDuration, netDuration+durationGap, packetSize, numPackets, transferSpeed, netDuration, netDuration+durationGap);
	ns3TcpSocket3->TraceConnectWithoutContext("CongestionWindow", MakeBoundCallback (&CwndChange, stream3CWND, netDuration));
	ns3TcpSocket3->TraceConnectWithoutContext("Drop", MakeBoundCallback (&packetDrop, stream3PD, netDuration, 3));

	sink = "/NodeList/8/ApplicationList/0/$ns3::PacketSink/Rx";
	Config::Connect(sink, MakeBoundCallback(&ReceivedPacket, stream3GP, netDuration));
	sink_ = "/NodeList/8/$ns3::Ipv4L3Protocol/Rx";
	Config::Connect(sink_, MakeBoundCallback(&ReceivedPacketIPV4, stream3TP, netDuration));
	netDuration += durationGap;

    transferSpeed = "75Mbps";	
	//TCP TcpBic from H4 to H8
	Ptr<OutputStreamWrapper> stream4CWND = asciiTraceHelper.CreateFileStream("h4.cwnd");
	Ptr<OutputStreamWrapper> stream4PD = asciiTraceHelper.CreateFileStream("h4.congestion_loss");
	Ptr<OutputStreamWrapper> stream4TP = asciiTraceHelper.CreateFileStream("h4.tp");
	Ptr<OutputStreamWrapper> stream4GP = asciiTraceHelper.CreateFileStream("h4.gp");
	Ptr<Socket> ns3TcpSocket4 = uniFlow(InetSocketAddress(receiverIFCs.GetAddress(3), port), port, "TcpBic", senders.Get(3), receivers.Get(3), netDuration, netDuration+durationGap, packetSize, numPackets, transferSpeed, netDuration, netDuration+durationGap);
	ns3TcpSocket4->TraceConnectWithoutContext("CongestionWindow", MakeBoundCallback (&CwndChange, stream4CWND, netDuration));
	ns3TcpSocket4->TraceConnectWithoutContext("Drop", MakeBoundCallback (&packetDrop, stream4PD, netDuration, 4));

	sink = "/NodeList/9/ApplicationList/0/$ns3::PacketSink/Rx";
	Config::Connect(sink, MakeBoundCallback(&ReceivedPacket, stream4GP, netDuration));
	sink_ = "/NodeList/9/$ns3::Ipv4L3Protocol/Rx";
	Config::Connect(sink_, MakeBoundCallback(&ReceivedPacketIPV4, stream4TP, netDuration));
	netDuration += durationGap;

	//Turning on Static Global Routing
	Ipv4GlobalRoutingHelper::PopulateRoutingTables();

	Ptr<FlowMonitor> flowmon;
	FlowMonitorHelper flowmonHelper;
	flowmon = flowmonHelper.InstallAll();
	Simulator::Stop(Seconds(netDuration));
	Simulator::Run();
	
	flowmon->CheckForLostPackets();
	Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());
	std::map<FlowId, FlowMonitor::FlowStats> stats = flowmon->GetFlowStats();
	for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin(); i != stats.end(); ++i) {
	
		Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
		if(t.sourceAddress == "10.1.0.1") {
			if(mapDrop.find(1)==mapDrop.end())
				mapDrop[1] = 0;
			*stream1PD->GetStream() << "TcpNewReno Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
			*stream1PD->GetStream()  << "Net Packet Lost: " << i->second.lostPackets << "\n";
			*stream1PD->GetStream()  << "Packet Lost due to buffer overflow: " << mapDrop[1] << "\n";
			*stream1PD->GetStream()  << "Packet Lost due to Congestion: " << i->second.lostPackets - mapDrop[1] << "\n";
			*stream1PD->GetStream() << "Max throughput: " << mapMaxThroughput["/NodeList/6/$ns3::Ipv4L3Protocol/Rx"] << std::endl;
		} 
		
		else if(t.sourceAddress == "10.1.1.1") {
			if(mapDrop.find(2)==mapDrop.end())
				mapDrop[2] = 0;
			*stream2PD->GetStream() << "Tcp Westwood Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
			*stream2PD->GetStream()  << "Net Packet Lost: " << i->second.lostPackets << "\n";
			*stream2PD->GetStream()  << "Packet Lost due to buffer overflow: " << mapDrop[2] << "\n";
			*stream2PD->GetStream()  << "Packet Lost due to Congestion: " << i->second.lostPackets - mapDrop[2] << "\n";
			*stream2PD->GetStream() << "Max throughput: " << mapMaxThroughput["/NodeList/7/$ns3::Ipv4L3Protocol/Rx"] << std::endl;
		} 
		
		else if(t.sourceAddress == "10.1.2.1") {
			if(mapDrop.find(3)==mapDrop.end())
				mapDrop[3] = 0;
			*stream3PD->GetStream() << "TcpHtcp Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
			*stream3PD->GetStream()  << "Net Packet Lost: " << i->second.lostPackets << "\n";
			*stream3PD->GetStream()  << "Packet Lost due to buffer overflow: " << mapDrop[3] << "\n";
			*stream3PD->GetStream()  << "Packet Lost due to Congestion: " << i->second.lostPackets - mapDrop[3] << "\n";
			*stream3PD->GetStream() << "Max throughput: " << mapMaxThroughput["/NodeList/8/$ns3::Ipv4L3Protocol/Rx"] << std::endl;
		}
		
		else if(t.sourceAddress == "10.1.3.1") {
			if(mapDrop.find(4)==mapDrop.end())
				mapDrop[4] = 0;
			*stream4PD->GetStream() << "TcpBic Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
			*stream4PD->GetStream()  << "Net Packet Lost: " << i->second.lostPackets << "\n";
			*stream4PD->GetStream()  << "Packet Lost due to buffer overflow: " << mapDrop[4] << "\n";
			*stream4PD->GetStream()  << "Packet Lost due to Congestion: " << i->second.lostPackets - mapDrop[4] << "\n";
			*stream4PD->GetStream() << "Max throughput: " << mapMaxThroughput["/NodeList/9/$ns3::Ipv4L3Protocol/Rx"] << std::endl;
		}
	}

	//flowmon->SerializeToXmlFile("application_6_a.flowmon", true, true);
	std::cout << "Simulation finished" << std::endl;
	Simulator::Destroy();

}
