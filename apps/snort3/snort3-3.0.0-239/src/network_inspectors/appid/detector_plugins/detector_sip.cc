//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// detector_sip.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detector_sip.h"

#include "appid_module.h"
#include "appid_inspector.h"
#include "app_info_table.h"
#include "protocols/packet.h"

static const char SIP_REGISTER_BANNER[] = "REGISTER ";
static const char SIP_INVITE_BANNER[] = "INVITE ";
static const char SIP_CANCEL_BANNER[] = "CANCEL ";
static const char SIP_ACK_BANNER[] = "ACK ";
static const char SIP_BYE_BANNER[] = "BYE ";
static const char SIP_OPTIONS_BANNER[] = "OPTIONS ";
static const char SIP_BANNER[] = "SIP/2.0 ";
static const char SIP_BANNER_END[] = "SIP/2.0\x00d\x00a";
#define SIP_REGISTER_BANNER_LEN (sizeof(SIP_REGISTER_BANNER)-1)
#define SIP_INVITE_BANNER_LEN (sizeof(SIP_INVITE_BANNER)-1)
#define SIP_CANCEL_BANNER_LEN (sizeof(SIP_CANCEL_BANNER)-1)
#define SIP_ACK_BANNER_LEN (sizeof(SIP_ACK_BANNER)-1)
#define SIP_BYE_BANNER_LEN (sizeof(SIP_BYE_BANNER)-1)
#define SIP_OPTIONS_BANNER_LEN (sizeof(SIP_OPTIONS_BANNER)-1)
#define SIP_BANNER_LEN (sizeof(SIP_BANNER)-1)
#define SIP_BANNER_END_LEN (sizeof(SIP_BANNER_END)-1)
#define SIP_BANNER_LEN    (sizeof(SIP_BANNER)-1)

#define USER_STRING "from: "
#define MAX_USER_POS ((int)sizeof(USER_STRING) - 2)

static const unsigned SIP_PORT = 5060;
static const unsigned MAX_VENDOR_SIZE = 64;

enum SIPState
{
    SIP_STATE_INIT = 0,
    SIP_STATE_REGISTER,
    SIP_STATE_CALL
};

enum tSIP_FLAGS
{
    SIP_FLAG_SERVER_CHECKED = (1<< 0)
};

struct ClientSIPData
{
    void* owner = nullptr;
    SIPState state = SIP_STATE_INIT;
    uint32_t flags = 0;
    std::string user_name;
    std::string user_agent;
    std::string from;
};

struct DetectorSipConfig
{
    void* sip_ua_matcher;
    DetectorAppSipPattern* sip_ua_list;
    void* sip_server_matcher;
    DetectorAppSipPattern* sip_server_list;
};

static THREAD_LOCAL DetectorSipConfig detector_sip_config;

static void clean_sip_ua()
{
    DetectorAppSipPattern* node;

    if ( detector_sip_config.sip_ua_matcher )
    {
        mlmpDestroy((tMlmpTree*)detector_sip_config.sip_ua_matcher);
        detector_sip_config.sip_ua_matcher = nullptr;
    }

    for ( node = detector_sip_config.sip_ua_list; node; node = detector_sip_config.sip_ua_list )
    {
        detector_sip_config.sip_ua_list = node->next;
        snort_free((void*)node->pattern.pattern);
        snort_free(node->userData.clientVersion);
        snort_free(node);
    }
}

static void clean_sip_server()
{
    DetectorAppSipPattern* node;

    if ( detector_sip_config.sip_server_matcher )
    {
        mlmpDestroy((tMlmpTree*)detector_sip_config.sip_server_matcher);
        detector_sip_config.sip_server_matcher = nullptr;
    }

    for ( node = detector_sip_config.sip_server_list; node; node =
        detector_sip_config.sip_server_list )
    {
        detector_sip_config.sip_server_list = node->next;
        snort_free((void*)node->pattern.pattern);
        snort_free(node->userData.clientVersion);
        snort_free(node);
    }
}

static void clientDataFree(void* data)
{
    delete (ClientSIPData*)data;
}

SipUdpClientDetector::SipUdpClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "SIP";
    proto = IpProtocol::UDP;
    minimum_matches = 2;
    provides_user = true;

    udp_patterns =
    {
        { (const uint8_t*)SIP_REGISTER_BANNER, sizeof(SIP_REGISTER_BANNER) - 1, 0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_INVITE_BANNER, sizeof(SIP_INVITE_BANNER) - 1,     0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_CANCEL_BANNER, sizeof(SIP_CANCEL_BANNER) - 1,     0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_ACK_BANNER, sizeof(SIP_ACK_BANNER) - 1,           0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_BYE_BANNER, sizeof(SIP_BYE_BANNER) - 1,           0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_OPTIONS_BANNER, sizeof(SIP_OPTIONS_BANNER) - 1,  -1, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_BANNER, sizeof(SIP_BANNER) - 1,                   0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_BANNER_END, sizeof(SIP_BANNER_END) - 1,          -1, 0, APP_ID_SIP },
    };

    appid_registry =
    {
        { APP_ID_SIP, APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
    };

    AppIdInspector::get_inspector()->get_sip_event_handler().set_client(this);
    handler->register_detector(name, this, proto);
}

SipUdpClientDetector::~SipUdpClientDetector()
{
    if (detector_sip_config.sip_ua_matcher)
        clean_sip_ua();

    if (detector_sip_config.sip_server_matcher)
        clean_sip_server();
}

int SipUdpClientDetector::validate(AppIdDiscoveryArgs& args)
{
    ClientSIPData* fd = (ClientSIPData*)data_get(args.asd);
    if ( !fd )
    {
        fd = new ClientSIPData();
        data_add(args.asd, fd, &clientDataFree);
        fd->owner = this;
        args.asd->set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    return APPID_INPROCESS;
}

SipTcpClientDetector::SipTcpClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "SIP";
    proto = IpProtocol::TCP;
    minimum_matches = 2;
    provides_user = true;

    tcp_patterns =
    {
        { (const uint8_t*)SIP_REGISTER_BANNER, sizeof(SIP_REGISTER_BANNER) - 1, 0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_INVITE_BANNER, sizeof(SIP_INVITE_BANNER) - 1,     0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_CANCEL_BANNER, sizeof(SIP_CANCEL_BANNER) - 1,     0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_ACK_BANNER, sizeof(SIP_ACK_BANNER) - 1,           0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_BYE_BANNER, sizeof(SIP_BYE_BANNER) - 1,           0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_OPTIONS_BANNER, sizeof(SIP_OPTIONS_BANNER) - 1,  -1, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_BANNER, sizeof(SIP_BANNER) - 1,                   0, 0, APP_ID_SIP },
        { (const uint8_t*)SIP_BANNER_END, sizeof(SIP_BANNER_END) - 1,          -1, 0, APP_ID_SIP },
    };

    appid_registry =
    {
        { APP_ID_SIP, APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
    };

    handler->register_detector(name, this, proto);
}

SipTcpClientDetector::~SipTcpClientDetector()
{
}

int SipTcpClientDetector::validate(AppIdDiscoveryArgs& args)
{
    ClientSIPData* fd = (ClientSIPData*)data_get(args.asd);
    if ( !fd )
    {
        fd = new ClientSIPData();
        data_add(args.asd, fd, &clientDataFree);
        fd->owner = this;
        args.asd->set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    return APPID_INPROCESS;
}

struct ServiceSIPData
{
    uint8_t serverPkt;
    char vendor[MAX_VENDOR_SIZE];
};

static int sipAppAddPattern(DetectorAppSipPattern** patternList, AppId ClientAppId,
    const char* clientVersion, const char* serverPattern)
{
    /* Allocate memory for data structures */
    DetectorAppSipPattern* pattern = (DetectorAppSipPattern*)snort_calloc(
        sizeof(DetectorAppSipPattern));
    pattern->userData.ClientAppId = ClientAppId;
    pattern->userData.clientVersion = snort_strdup(clientVersion);
    pattern->pattern.pattern = (uint8_t*)snort_strdup(serverPattern);
    pattern->pattern.patternSize = (int)strlen(serverPattern);
    pattern->next = *patternList;
    *patternList = pattern;

    return 0;
}

int SipUdpClientDetector::sipUaPatternAdd(AppId ClientAppId, const char* clientVersion, const
    char* pattern)
{
    return sipAppAddPattern(&detector_sip_config.sip_ua_list, ClientAppId, clientVersion, pattern);
}

int SipUdpClientDetector::sipServerPatternAdd(AppId ClientAppId, const char* clientVersion, const
    char* pattern)
{
    return sipAppAddPattern(&detector_sip_config.sip_server_list, ClientAppId, clientVersion,
        pattern);
}

int SipUdpClientDetector::finalize_sip_ua()
{
    const int PATTERN_PART_MAX = 10;
    static THREAD_LOCAL tMlmpPattern patterns[PATTERN_PART_MAX];
    int num_patterns;
    DetectorAppSipPattern* patternNode;

    detector_sip_config.sip_ua_matcher = mlmpCreate();
    if ( !detector_sip_config.sip_ua_matcher )
        return -1;

    detector_sip_config.sip_server_matcher = mlmpCreate();
    if ( !detector_sip_config.sip_server_matcher )
    {
        mlmpDestroy((tMlmpTree*)detector_sip_config.sip_ua_matcher);
        detector_sip_config.sip_ua_matcher = nullptr;
        return -1;
    }

    for ( patternNode = detector_sip_config.sip_ua_list; patternNode; patternNode =
        patternNode->next )
    {
        num_patterns = HttpPatternMatchers::get_instance()->parse_multiple_http_patterns(
            (const char*)patternNode->pattern.pattern,  patterns,  PATTERN_PART_MAX, 0);
        patterns[num_patterns].pattern = nullptr;

        mlmpAddPattern((tMlmpTree*)detector_sip_config.sip_ua_matcher, patterns, patternNode);
    }

    for ( patternNode = detector_sip_config.sip_server_list; patternNode; patternNode =
        patternNode->next )
    {
        num_patterns = HttpPatternMatchers::get_instance()->parse_multiple_http_patterns(
            (const char*)patternNode->pattern.pattern, patterns,  PATTERN_PART_MAX, 0);
        patterns[num_patterns].pattern = nullptr;

        mlmpAddPattern((tMlmpTree*)detector_sip_config.sip_server_matcher, patterns, patternNode);
    }

    mlmpProcessPatterns((tMlmpTree*)detector_sip_config.sip_ua_matcher);
    mlmpProcessPatterns((tMlmpTree*)detector_sip_config.sip_server_matcher);
    return 0;
}

static int get_sip_client_app(void* patternMatcher, const char* pattern, uint32_t patternLen,
    AppId* ClientAppId, char** clientVersion)
{
    tMlmpPattern patterns[3];
    DetectorAppSipPattern* data;

    if ( !pattern )
        return 0;

    patterns[0].pattern = (uint8_t*)pattern;
    patterns[0].patternSize = patternLen;
    patterns[1].pattern = nullptr;

    data = (DetectorAppSipPattern*)mlmpMatchPatternGeneric((tMlmpTree*)patternMatcher, patterns);

    if ( !data )
        return 0;

    *ClientAppId = data->userData.ClientAppId;
    *clientVersion = data->userData.clientVersion;

    return 1;
}

void SipServiceDetector::createRtpFlow(AppIdSession* asd, const Packet* pkt, const SfIp* cliIp,
    uint16_t cliPort, const SfIp* srvIp, uint16_t srvPort, IpProtocol proto, int16_t app_id)
{
    AppIdSession* fp, * fp2;

    fp = AppIdSession::create_future_session(pkt, cliIp, cliPort, srvIp, srvPort, proto, app_id,
        APPID_EARLY_SESSION_FLAG_FW_RULE);
    if ( fp )
    {
        fp->client_app_id = asd->client_app_id;
        fp->payload_app_id = asd->payload_app_id;
        fp->service_app_id = APP_ID_RTP;
        initialize_expected_session(asd, fp, APPID_SESSION_IGNORE_ID_FLAGS);
    }

    // create an RTCP flow as well
    fp2 = AppIdSession::create_future_session(pkt, cliIp, cliPort + 1, srvIp, srvPort + 1, proto,
        app_id, APPID_EARLY_SESSION_FLAG_FW_RULE);
    if ( fp2 )
    {
        fp2->client_app_id = asd->client_app_id;
        fp2->payload_app_id = asd->payload_app_id;
        fp2->service_app_id = APP_ID_RTCP;
        initialize_expected_session(asd, fp2, APPID_SESSION_IGNORE_ID_FLAGS);
    }
}

void SipServiceDetector::addFutureRtpFlows(SipEvent& event, AppIdSession* asd)
{
    event.begin_media_sessions();

    auto session_a = event.next_media_session();
    auto session_b = event.next_media_session();

    if ( !session_a || !session_b )
        return;

    DebugFormat(DEBUG_SIP, "Adding future media sessions ID: %u and %u\n",
        session_b->get_id(), session_b->get_id());

    session_a->begin_media_data();
    session_b->begin_media_data();

    auto media_a = session_a->next_media_data();
    auto media_b = session_b->next_media_data();

    while ( media_a && media_b )
    {
        DebugFormat(DEBUG_SIP, "Adding future channels Source IP: %s Port: %hu\n",
            media_a->get_address()->ntoa(), media_a->get_port());
        DebugFormat(DEBUG_SIP, "Adding future channels Destine IP: %s Port: %hu\n",
            media_b->get_address()->ntoa(), media_b->get_port());

        createRtpFlow(asd, event.get_packet(), media_a->get_address(), media_a->get_port(),
            media_b->get_address(), media_b->get_port(), IpProtocol::UDP, APP_ID_RTP);
        createRtpFlow(asd, event.get_packet(), media_b->get_address(), media_b->get_port(),
            media_a->get_address(), media_b->get_port(), IpProtocol::UDP, APP_ID_RTP);

        media_a = session_a->next_media_data();
        media_b = session_b->next_media_data();
    }
}

SipServiceDetector::SipServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "sip";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;
    provides_user = true;

    tcp_patterns =
    {
        { (const uint8_t*)SIP_BANNER, SIP_BANNER_LEN, 0, 0, 0 },
        { (const uint8_t*)SIP_INVITE_BANNER, SIP_INVITE_BANNER_LEN, 0, 0, 0 },
        { (const uint8_t*)SIP_ACK_BANNER, SIP_ACK_BANNER_LEN, 0, 0, 0 },
        { (const uint8_t*)SIP_REGISTER_BANNER, SIP_REGISTER_BANNER_LEN, 0, 0, 0 },
        { (const uint8_t*)SIP_CANCEL_BANNER, SIP_CANCEL_BANNER_LEN, 0, 0, 0 },
        { (const uint8_t*)SIP_BYE_BANNER, SIP_BYE_BANNER_LEN, 0, 0, 0 },
        { (const uint8_t*)SIP_OPTIONS_BANNER, SIP_OPTIONS_BANNER_LEN, 0, 0, 0 },
    };

    udp_patterns = tcp_patterns;

    appid_registry =
    {
        { APP_ID_SIP, APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_CLIENT_USER },
        { APP_ID_RTP, APPINFO_FLAG_SERVICE_ADDITIONAL }
    };

    service_ports =
    {
        { SIP_PORT, IpProtocol::UDP, false },
        { SIP_PORT, IpProtocol::TCP, false }
    };

    AppIdInspector::get_inspector()->get_sip_event_handler().set_service(this);
    handler->register_detector(name, this, proto);
}

SipServiceDetector::~SipServiceDetector()
{
}

int SipServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    ServiceSIPData* ss;
    AppIdSession* asd = args.asd;

    ss = (ServiceSIPData*)data_get(asd);
    if (!ss)
    {
        ss = (ServiceSIPData*)snort_calloc(sizeof(ServiceSIPData));
        data_add(asd, ss, &snort_free);
    }

    if (args.size && args.dir == APP_ID_FROM_RESPONDER)
        ss->serverPkt++;

    if (ss->serverPkt > 10)
    {
        if (!asd->is_service_detected())
        {
            fail_service(asd, args.pkt, args.dir);
        }
        asd->clear_session_flags(APPID_SESSION_CONTINUE);
        return APPID_NOMATCH;
    }

    if (!asd->is_service_detected())
        service_inprocess(asd, args.pkt, args.dir);

    return APPID_INPROCESS;
}

THREAD_LOCAL SipUdpClientDetector* SipEventHandler::client = nullptr;
THREAD_LOCAL SipServiceDetector* SipEventHandler::service = nullptr;

void SipEventHandler::handle(DataEvent& event, Flow* flow)
{
    AppIdSession* asd = nullptr;
    SipEvent& sip_event = (SipEvent&)event;

#ifdef DEBUG_APP_ID_SESSIONS
    {
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        const SfIp* ip;

        src_ip[0] = 0;
        ip = p->ptrs.ip_api.get_src();
        sfip_ntop(ip, src_ip, sizeof(src_ip));
        dst_ip[0] = 0;
        ip = p->ptrs.ip_api.get_dst();
        sfip_ntop(ip, dst_ip, sizeof(dst_ip));
        fprintf(SF_DEBUG_FILE, "AppId Sip Snort Callback Session %s-%u -> %s-%u %d\n", src_ip,
            (unsigned)p->src_port, dst_ip, (unsigned)p->dst_port, IsTCP(p) ? IpProtocol::TCP :
            IpProtocol::UDP);
    }
#endif
    if ( flow )
        asd = appid_api.get_appid_session(flow);

    if ( !asd )
        return;

    client_handler(sip_event, asd);
    service_handler(sip_event, asd);
}

void SipEventHandler::client_handler(SipEvent& sip_event, AppIdSession* asd)
{
    AppId ClientAppId = APP_ID_SIP;
    char* clientVersion = nullptr;

    ClientSIPData* fd = (ClientSIPData*)client->data_get(asd);
    if ( !fd )
    {
        fd = new ClientSIPData();
        client->data_add(asd, fd, &clientDataFree);
        fd->owner = client;
        asd->set_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS);
    }

    int direction = (sip_event.get_packet()->is_from_client()) ?
        APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;

    if ( sip_event.is_invite() && direction == APP_ID_FROM_INITIATOR )
    {
        if (sip_event.get_from_len())
            fd->from = sip_event.get_from();
        if (sip_event.get_user_name_len())
            fd->user_name = sip_event.get_user_name();
        if (sip_event.get_user_agent_len())
            fd->user_agent = sip_event.get_user_agent();
    }

    if ( fd->user_agent.size() )
    {
        if ( get_sip_client_app(detector_sip_config.sip_ua_matcher,
            fd->user_agent.c_str(), fd->user_agent.size(), &ClientAppId, &clientVersion) )
            goto success;
    }

    if ( fd->from.size() && !(fd->flags & SIP_FLAG_SERVER_CHECKED) )
    {
        fd->flags |= SIP_FLAG_SERVER_CHECKED;

        if ( get_sip_client_app(detector_sip_config.sip_server_matcher,
            fd->from.c_str(), fd->from.size(), &ClientAppId, &clientVersion) )
            goto success;
    }

    if ( !sip_event.is_dialog_established() )
        return;

success:
    //client detection successful
    client->add_app(asd, APP_ID_SIP, ClientAppId, clientVersion);
    appid_stats.sip_clients++;

    if ( fd->user_name.size() )
        client->add_user(asd, fd->user_name.c_str(), APP_ID_SIP, true);

    asd->set_client_detected();
}

void SipEventHandler::service_handler(SipEvent& sip_event, AppIdSession* asd)
{
    ServiceSIPData* ss = (ServiceSIPData*)service->data_get(asd);
    if ( !ss )
    {
        ss = (ServiceSIPData*)snort_calloc(sizeof(ServiceSIPData));
        service->data_add(asd, ss, &snort_free);
    }

    ss->serverPkt = 0;
    int direction = sip_event.get_packet()->is_from_client() ? APP_ID_FROM_INITIATOR :
        APP_ID_FROM_RESPONDER;

    if ( direction == APP_ID_FROM_RESPONDER )
    {
        if ( sip_event.get_user_agent() )
        {
            memcpy(ss->vendor, sip_event.get_user_agent(),
                sip_event.get_user_agent_len() > (MAX_VENDOR_SIZE - 1) ?  (MAX_VENDOR_SIZE - 1) :
                sip_event.get_user_agent_len());
        }
        else if ( sip_event.get_server() )
        {
            memcpy(ss->vendor, sip_event.get_server(),
                sip_event.get_server_len() > (MAX_VENDOR_SIZE - 1) ?  (MAX_VENDOR_SIZE - 1) :
                sip_event.get_server_len());
        }
    }

    if ( !sip_event.has_dialog() )
        return;

    if ( sip_event.is_media_updated() )
        service->addFutureRtpFlows(sip_event, asd);

    if ( sip_event.is_dialog_established() )
    {
        if ( !asd->is_service_detected() )
        {
            asd->set_session_flags(APPID_SESSION_CONTINUE);
            service->add_service(asd, sip_event.get_packet(), direction, APP_ID_SIP,
                ss->vendor[0] ? ss->vendor : nullptr, nullptr, nullptr);
            appid_stats.sip_flows++;
        }
    }
}

